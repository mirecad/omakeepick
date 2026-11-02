//! Opening a KDBX file and turning its entries into a searchable, secret-free index.

use std::collections::HashMap;
use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use keepass::db::{EntryId, EntryRef, GroupId, GroupRef, Times};
use keepass::error::{DatabaseKeyError, DatabaseOpenError};
use keepass::{Database, DatabaseKey};
use zeroize::Zeroizing;

use crate::quickunlock::QuickBlob;
use crate::totp;

/// The credentials that open one database. Lives only in memory; an empty password means
/// "no password component" (key-file-only databases), matching KeePassXC.
#[derive(Clone)]
pub struct KeyMaterial {
    password: Option<Zeroizing<String>>,
    keyfile: Option<Zeroizing<Vec<u8>>>,
}

impl KeyMaterial {
    pub fn new(password: Zeroizing<String>, keyfile: Option<Zeroizing<Vec<u8>>>) -> Result<Self, VaultError> {
        let password = (!password.is_empty()).then_some(password);
        if password.is_none() && keyfile.is_none() {
            return Err(VaultError::BadRequest("Enter the master password or choose a key file".into()));
        }
        Ok(KeyMaterial { password, keyfile })
    }

    fn database_key(&self) -> Result<DatabaseKey, VaultError> {
        let mut key = DatabaseKey::new();
        if let Some(password) = &self.password {
            key = key.with_password(password);
        }
        if let Some(keyfile) = &self.keyfile {
            key =
                key.with_keyfile(&mut keyfile.as_slice()).map_err(|e| VaultError::Keyfile(e.to_string()))?;
        }
        Ok(key)
    }

    /// `[flags][len32][password][len32][keyfile]`, used as the quick-unlock plaintext.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let password = self.password.as_ref().map(|p| p.as_bytes());
        let keyfile = self.keyfile.as_ref().map(|k| k.as_slice());
        let mut out = Zeroizing::new(Vec::with_capacity(
            9 + password.map_or(0, <[u8]>::len) + keyfile.map_or(0, <[u8]>::len),
        ));
        out.push(u8::from(password.is_some()) | (u8::from(keyfile.is_some()) << 1));
        for part in [password.unwrap_or_default(), keyfile.unwrap_or_default()] {
            out.extend_from_slice(&(part.len() as u32).to_le_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&flags, mut rest) = bytes.split_first()?;
        let mut take = || -> Option<&[u8]> {
            let len = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            let part = rest.get(4..4 + len)?;
            rest = &rest[4 + len..];
            Some(part)
        };
        let password = take()?;
        let keyfile = take()?;
        Some(KeyMaterial {
            password: (flags & 1 != 0)
                .then(|| String::from_utf8(password.to_vec()).ok().map(Zeroizing::new))
                .flatten(),
            keyfile: (flags & 2 != 0).then(|| Zeroizing::new(keyfile.to_vec())),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum VaultError {
    BadRequest(String),
    NotFound(PathBuf),
    BadCredentials,
    Keyfile(String),
    Format(String),
    Io(String),
}

impl VaultError {
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::BadRequest(_) => "bad_request",
            VaultError::NotFound(_) => "not_found",
            VaultError::BadCredentials => "bad_credentials",
            VaultError::Keyfile(_) => "keyfile_error",
            VaultError::Format(_) => "format_error",
            VaultError::Io(_) => "failed",
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::BadRequest(msg) => f.write_str(msg),
            // No paths in messages: they can end up on a notification's command line.
            VaultError::NotFound(_) => f.write_str("The file does not exist"),
            VaultError::BadCredentials => f.write_str("Wrong password or key file (or the file is damaged)"),
            VaultError::Keyfile(msg) => write!(f, "Cannot use the key file: {msg}"),
            VaultError::Format(msg) => write!(f, "Not a readable KeePass database: {msg}"),
            VaultError::Io(msg) => f.write_str(msg),
        }
    }
}

fn map_open_error(err: DatabaseOpenError) -> VaultError {
    match err {
        // KDBX 3.1 has no key check: a wrong key surfaces as a decryption (padding) error.
        DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey) | DatabaseOpenError::Cryptography(_) => {
            VaultError::BadCredentials
        }
        DatabaseOpenError::Key(DatabaseKeyError::EmptyKey) => {
            VaultError::BadRequest("Enter the master password or choose a key file".into())
        }
        DatabaseOpenError::Key(e) => VaultError::Keyfile(e.to_string()),
        DatabaseOpenError::Io(e) => VaultError::Io(e.to_string()),
        other => VaultError::Format(other.to_string()),
    }
}

/// Largest files we read. Real databases and key files are far smaller; without a cap a
/// device node or a sparse file would be read into memory whole.
const MAX_DATABASE_BYTES: u64 = 256 << 20;
const MAX_KEYFILE_BYTES: u64 = 16 << 20;

/// Reads a regular file of at most `limit` bytes. Anything else (a FIFO, which would block the
/// open forever; a device; a huge file) is refused.
fn read_file(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let too_large = || std::io::Error::other("the file is too large");
    // O_NONBLOCK makes opening a FIFO return at once; regular files ignore it.
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    if meta.len() > limit {
        return Err(too_large());
    }
    let mut data = Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    // The file may grow after fstat: cap the read itself as well.
    (&file).take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(too_large());
    }
    Ok(data)
}

pub fn read_keyfile(path: &Path) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    read_file(path, MAX_KEYFILE_BYTES).map_err(|e| match e.kind() {
        ErrorKind::NotFound => VaultError::NotFound(path.to_path_buf()),
        _ => VaultError::Keyfile(e.to_string()),
    })
}

/// Decrypts the database at `path`. Runs the KDF, so call it from a blocking thread.
pub fn open_database(path: &Path, key: &KeyMaterial) -> Result<Database, VaultError> {
    parse_database(&read_database(path)?, key)
}

/// The raw database file; `parse_database` decrypts it. Messages never include the path: they
/// can end up in a notification.
pub fn read_database(path: &Path) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    read_file(path, MAX_DATABASE_BYTES).map_err(|e| match e.kind() {
        ErrorKind::NotFound => VaultError::NotFound(path.to_path_buf()),
        _ => VaultError::Io(format!("Cannot read the database file: {e}")),
    })
}

/// Runs the KDF, so call it from a blocking thread.
pub fn parse_database(data: &[u8], key: &KeyMaterial) -> Result<Database, VaultError> {
    header::check(data)?;
    Database::parse(data, key.database_key()?).map_err(map_open_error)
}

/// A sanity check of the KDBX outer header before the `keepass` crate sees it.
///
/// The header is not authenticated until after the key derivation, so the KDF parameters in it
/// are attacker-controlled when the file comes from a sync peer or a shared vault. The crate
/// runs them as given (2^63 AES rounds spin for centuries, terabytes of Argon2 memory abort the
/// process) and panics on fixed-size fields that are too short. With `panic = "abort"` either
/// one takes the daemon down, or wedges it `busy` forever. This mirrors the crate's parsing and
/// refuses such files with an error instead.
mod header {
    use super::VaultError;

    /// Far above anything KeePassXC offers, well below "forever".
    const MAX_AES_ROUNDS: u64 = 1 << 34;
    const MAX_ARGON2_MEMORY: u64 = 4 << 30;
    const MAX_ARGON2_ITERATIONS: u64 = 1_000;
    const MAX_ARGON2_PARALLELISM: u32 = 256;
    /// memory × iterations, in bytes·passes: 64 MiB × 1000 passes, about a minute of work.
    const MAX_ARGON2_WORK: u128 = (64 << 20) * 1_000;

    const KDBX_SIGNATURE: [u8; 8] = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
    const AES_KDF: [u8; 16] = *b"\xc9\xd9\xf3\x9a\x62\x8a\x44\x60\xbf\x74\x0d\x08\xc1\x8a\x4f\xea";
    const ARGON2D: [u8; 16] = *b"\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c";
    const ARGON2ID: [u8; 16] = *b"\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6";

    fn damaged() -> VaultError {
        VaultError::Format("the header is damaged".into())
    }

    fn too_expensive() -> VaultError {
        VaultError::Format("its key derivation settings are beyond what this app accepts".into())
    }

    fn u32_at(data: &[u8], at: usize) -> Result<u32, VaultError> {
        Ok(u32::from_le_bytes(data.get(at..at + 4).ok_or_else(damaged)?.try_into().expect("4 bytes")))
    }

    fn u64_at(data: &[u8], at: usize) -> Result<u64, VaultError> {
        Ok(u64::from_le_bytes(data.get(at..at + 8).ok_or_else(damaged)?.try_into().expect("8 bytes")))
    }

    pub fn check(data: &[u8]) -> Result<(), VaultError> {
        // Not KDBX 3/4 at all: let the crate name the problem (KDB 1, not a database, …).
        if data.get(..8) != Some(&KDBX_SIGNATURE[..]) {
            return Ok(());
        }
        let major = u16::from_le_bytes(data.get(10..12).ok_or_else(damaged)?.try_into().expect("2 bytes"));
        let length_bytes = match major {
            3 => 2,
            4 => 4,
            _ => return Ok(()),
        };
        let mut pos = 12;
        loop {
            let kind = *data.get(pos).ok_or_else(damaged)?;
            let len = if length_bytes == 2 {
                u16::from_le_bytes(
                    data.get(pos + 1..pos + 3).ok_or_else(damaged)?.try_into().expect("2 bytes"),
                ) as usize
            } else {
                u32_at(data, pos + 1)? as usize
            };
            let start = pos + 1 + length_bytes;
            let end = start.checked_add(len).ok_or_else(damaged)?;
            let field = data.get(start..end).ok_or_else(damaged)?;
            pos = end;
            match (major, kind) {
                (_, 0) => return Ok(()),
                // Compression flags and (KDBX 3) the inner stream id are read as u32.
                (_, 3) | (3, 10) if field.len() < 4 => return Err(damaged()),
                // KDBX 3: transform rounds.
                (3, 6) => {
                    if u64_at(field, 0)? > MAX_AES_ROUNDS {
                        return Err(too_expensive());
                    }
                }
                // KDBX 4: KDF parameters and public custom data are variant dictionaries.
                (4, 11) => check_kdf(&variant_dictionary(field)?)?,
                (4, 12) => {
                    variant_dictionary(field)?;
                }
                _ => {}
            }
        }
    }

    enum Value {
        U32(u32),
        U64(u64),
        Bytes(Vec<u8>),
        Other,
    }

    /// Parses a KDBX 4 variant dictionary, checking that fixed-size values have their size.
    fn variant_dictionary(buf: &[u8]) -> Result<Vec<(String, Value)>, VaultError> {
        if u16::from_le_bytes(buf.get(..2).ok_or_else(damaged)?.try_into().expect("2 bytes")) != 0x0100 {
            return Ok(Vec::new()); // the crate rejects the version itself
        }
        let mut pos = 2;
        let mut out = Vec::new();
        while pos + 9 < buf.len() {
            let kind = buf[pos];
            let key_len = u32_at(buf, pos + 1)? as usize;
            let key = buf.get(pos + 5..pos + 5 + key_len).ok_or_else(damaged)?;
            pos += 5 + key_len;
            let value_len = u32_at(buf, pos)? as usize;
            let value = buf.get(pos + 4..pos + 4 + value_len).ok_or_else(damaged)?;
            pos += 4 + value_len;
            let value = match kind {
                0x04 | 0x0c if value.len() < 4 => return Err(damaged()),
                0x05 | 0x0d if value.len() < 8 => return Err(damaged()),
                0x04 => Value::U32(u32_at(value, 0)?),
                0x05 => Value::U64(u64_at(value, 0)?),
                0x42 => Value::Bytes(value.to_vec()),
                _ => Value::Other,
            };
            out.push((String::from_utf8_lossy(key).into_owned(), value));
        }
        Ok(out)
    }

    fn check_kdf(params: &[(String, Value)]) -> Result<(), VaultError> {
        let get = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        let Some(Value::Bytes(uuid)) = get("$UUID") else { return Ok(()) };
        if uuid[..] == AES_KDF {
            if let Some(Value::U64(rounds)) = get("R")
                && *rounds > MAX_AES_ROUNDS
            {
                return Err(too_expensive());
            }
        } else if uuid[..] == ARGON2D || uuid[..] == ARGON2ID {
            let memory = match get("M") {
                Some(Value::U64(m)) => *m,
                _ => return Ok(()),
            };
            let iterations = match get("I") {
                Some(Value::U64(i)) => *i,
                _ => return Ok(()),
            };
            let parallelism = match get("P") {
                Some(Value::U32(p)) => *p,
                _ => return Ok(()),
            };
            if memory > MAX_ARGON2_MEMORY
                || iterations > MAX_ARGON2_ITERATIONS
                || parallelism > MAX_ARGON2_PARALLELISM
                || u128::from(memory) * u128::from(iterations) > MAX_ARGON2_WORK
            {
                return Err(too_expensive());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const KDBX3: &[u8] = include_bytes!("../tests/fixtures/password.kdbx");

        /// Offset of the first KDBX 3 header field of `kind`.
        fn field3(data: &[u8], kind: u8) -> usize {
            let mut pos = 12;
            loop {
                let len = u16::from_le_bytes([data[pos + 1], data[pos + 2]]) as usize;
                if data[pos] == kind {
                    return pos;
                }
                pos += 3 + len;
            }
        }

        #[test]
        fn accepts_the_fixture() {
            check(KDBX3).unwrap();
        }

        #[test]
        fn refuses_absurd_aes_rounds_in_kdbx3() {
            let mut data = KDBX3.to_vec();
            let at = field3(&data, 6) + 3;
            data[at..at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(check(&data), Err(too_expensive()));
        }

        #[test]
        fn refuses_short_fields_instead_of_panicking() {
            // Compression flags cut to one byte, which the crate reads as a u32.
            let mut data = KDBX3.to_vec();
            let at = field3(&data, 3);
            let len = u16::from_le_bytes([data[at + 1], data[at + 2]]) as usize;
            data[at + 1..at + 3].copy_from_slice(&1u16.to_le_bytes());
            data.drain(at + 4..at + 3 + len);
            assert_eq!(check(&data), Err(damaged()));
            // A header that just ends.
            assert_eq!(check(&KDBX3[..40]), Err(damaged()));
        }

        /// A KDBX 4 header with the given KDF parameters (a variant dictionary built by hand).
        fn kdbx4(kdf: &[(&str, Value)]) -> Vec<u8> {
            let mut vd = vec![0x00, 0x01];
            for (key, value) in kdf {
                let (kind, bytes): (u8, Vec<u8>) = match value {
                    Value::U32(v) => (0x04, v.to_le_bytes().to_vec()),
                    Value::U64(v) => (0x05, v.to_le_bytes().to_vec()),
                    Value::Bytes(b) => (0x42, b.clone()),
                    Value::Other => (0x08, vec![1]),
                };
                vd.push(kind);
                vd.extend((key.len() as u32).to_le_bytes());
                vd.extend(key.as_bytes());
                vd.extend((bytes.len() as u32).to_le_bytes());
                vd.extend(bytes);
            }
            vd.push(0);
            let mut data = KDBX_SIGNATURE.to_vec();
            data.extend([0, 0, 4, 0]);
            let mut field = |kind: u8, bytes: &[u8]| {
                data.push(kind);
                data.extend((bytes.len() as u32).to_le_bytes());
                data.extend(bytes);
            };
            field(2, &[0; 16]);
            field(3, &1u32.to_le_bytes());
            field(4, &[0; 32]);
            field(7, &[0; 12]);
            field(11, &vd);
            field(0, b"\r\n\r\n");
            data
        }

        #[test]
        fn bounds_argon2_in_kdbx4() {
            let argon = |memory: u64, iterations: u64, parallelism: u32| {
                kdbx4(&[
                    ("$UUID", Value::Bytes(ARGON2ID.to_vec())),
                    ("S", Value::Bytes(vec![0; 32])),
                    ("M", Value::U64(memory)),
                    ("I", Value::U64(iterations)),
                    ("P", Value::U32(parallelism)),
                    ("V", Value::U32(0x13)),
                ])
            };
            check(&argon(64 << 20, 10, 2)).unwrap();
            check(&argon(1 << 30, 32, 8)).unwrap();
            assert_eq!(check(&argon(1 << 40, 1, 1)), Err(too_expensive()));
            assert_eq!(check(&argon(64 << 20, 100_000, 1)), Err(too_expensive()));
            assert_eq!(check(&argon(64 << 20, 1, 1 << 20)), Err(too_expensive()));
            assert_eq!(check(&argon(4 << 30, 1_000, 1)), Err(too_expensive()));
            let aes = |rounds: u64| {
                kdbx4(&[
                    ("$UUID", Value::Bytes(AES_KDF.to_vec())),
                    ("S", Value::Bytes(vec![0; 32])),
                    ("R", Value::U64(rounds)),
                ])
            };
            check(&aes(60_000_000)).unwrap();
            assert_eq!(check(&aes(u64::MAX)), Err(too_expensive()));
            // A u64 parameter that is only 2 bytes long would panic the crate's reader.
            let short = kdbx4(&[("$UUID", Value::Bytes(AES_KDF.to_vec())), ("R", Value::Other)]);
            let mut short = short;
            let at = short.windows(1).rposition(|w| w == b"R").unwrap() + 1;
            short[at - 6] = 0x05; // retag the bool as u64 while leaving its 1-byte value
            assert_eq!(check(&short), Err(damaged()));
        }
    }
}

/// Searchable, secret-free view of one entry. Notes are wiped when the index is dropped: people
/// keep recovery codes in them.
#[derive(Clone)]
pub struct IndexedEntry {
    pub id: EntryId,
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    /// URL without scheme and `www.`, which is what people type.
    pub url_match: String,
    pub group: String,
    pub tags: String,
    pub notes: Zeroizing<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub autotype: bool,
}

/// The entry's group followed by all its ancestors up to the root.
fn ancestors<'a>(db: &'a Database, entry: &EntryRef<'_>) -> impl Iterator<Item = GroupRef<'a>> + use<'a> {
    std::iter::successors(db.group(entry.parent().id()), move |g| {
        g.parent().map(|p| p.id()).and_then(|id| db.group(id))
    })
}

/// KeePass group flags are tri-state: the nearest group with an explicit value decides.
fn inherited_flag(db: &Database, entry: &EntryRef<'_>, flag: impl Fn(&GroupRef<'_>) -> Option<bool>) -> bool {
    ancestors(db, entry).find_map(|g| flag(&g)).unwrap_or(true)
}

/// Path below the root group, e.g. `Personal/Dev`.
fn group_path(db: &Database, entry: &EntryRef<'_>) -> String {
    let mut names: Vec<String> =
        ancestors(db, entry).filter(|g| g.parent().is_some()).map(|g| g.name.clone()).collect();
    names.reverse();
    names.join("/")
}

fn in_group(db: &Database, entry: &EntryRef<'_>, group_id: GroupId) -> bool {
    ancestors(db, entry).any(|g| g.id() == group_id)
}

fn strip_url(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.strip_prefix("www.").unwrap_or(rest).to_string()
}

/// Indexes every searchable entry: skips the Recycle Bin, expired entries and groups with
/// searching disabled.
pub fn build_index(db: &Database) -> Vec<IndexedEntry> {
    let recycle_bin = db.recycle_bin().map(|g| g.id());
    let now = Times::now();
    let mut out = Vec::new();
    for entry in db.iter_all_entries() {
        if recycle_bin.is_some_and(|bin| in_group(db, &entry, bin)) {
            continue;
        }
        if entry.times.expires == Some(true) && entry.times.expiry < now {
            continue;
        }
        if !inherited_flag(db, &entry, |g| g.enable_searching) {
            continue;
        }
        let field = |name: &str| entry.get(name).unwrap_or_default().trim().to_string();
        let url = field(keepass::db::fields::URL);
        out.push(IndexedEntry {
            id: entry.id(),
            uuid: entry.id().uuid().to_string(),
            title: field(keepass::db::fields::TITLE),
            username: field(keepass::db::fields::USERNAME),
            url_match: strip_url(&url),
            url,
            group: group_path(db, &entry),
            tags: entry.tags.join(" "),
            notes: Zeroizing::new(entry.get(keepass::db::fields::NOTES).unwrap_or_default().to_string()),
            has_password: !entry.get_password().unwrap_or_default().is_empty(),
            has_totp: totp::has_totp(&entry),
            autotype: entry.autotype.as_ref().is_none_or(|a| a.enabled)
                && inherited_flag(db, &entry, |g| g.enable_autotype),
        });
    }
    out.sort_by_cached_key(|e| (e.title.to_lowercase(), e.group.to_lowercase()));
    out
}

/// The auto-type sequence for an entry: its own, else the nearest group default, else
/// the configured default.
pub fn autotype_sequence(db: &Database, entry: &EntryRef<'_>, default: &str) -> String {
    let own =
        entry.autotype.as_ref().and_then(|a| a.default_sequence.as_deref()).filter(|s| !s.trim().is_empty());
    if let Some(seq) = own {
        return seq.to_string();
    }
    ancestors(db, entry)
        .find_map(|g| g.default_autotype_sequence.clone().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| default.to_string())
}

/// An unlocked database plus everything needed to reload it.
pub struct OpenDb {
    pub path: PathBuf,
    pub keyfile: Option<PathBuf>,
    pub key: KeyMaterial,
    pub quick: Option<QuickBlob>,
    pub db: Database,
    pub index: Vec<IndexedEntry>,
    by_uuid: HashMap<String, usize>,
}

impl OpenDb {
    pub fn new(
        path: PathBuf,
        keyfile: Option<PathBuf>,
        key: KeyMaterial,
        quick: Option<QuickBlob>,
        db: Database,
    ) -> Self {
        let mut open = OpenDb { path, keyfile, key, quick, db, index: Vec::new(), by_uuid: HashMap::new() };
        open.reindex();
        open
    }

    pub fn replace_database(&mut self, db: Database) {
        self.db = db;
        self.reindex();
    }

    fn reindex(&mut self) {
        self.index = build_index(&self.db);
        self.by_uuid = self.index.iter().enumerate().map(|(i, e)| (e.uuid.clone(), i)).collect();
    }

    pub fn indexed(&self, uuid: &str) -> Option<&IndexedEntry> {
        self.by_uuid.get(uuid).map(|&i| &self.index[i])
    }

    pub fn entry(&self, uuid: &str) -> Option<EntryRef<'_>> {
        self.indexed(uuid).and_then(|e| self.db.entry(e.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_material_roundtrip() {
        let key =
            KeyMaterial::new(Zeroizing::new("pässword".into()), Some(Zeroizing::new(vec![1, 2, 3]))).unwrap();
        let back = KeyMaterial::from_bytes(&key.to_bytes()).unwrap();
        assert_eq!(back.password.as_deref().map(String::as_str), Some("pässword"));
        assert_eq!(back.keyfile.as_deref().map(Vec::as_slice), Some(&[1u8, 2, 3][..]));

        let only_file =
            KeyMaterial::new(Zeroizing::new(String::new()), Some(Zeroizing::new(vec![9]))).unwrap();
        let back = KeyMaterial::from_bytes(&only_file.to_bytes()).unwrap();
        assert!(back.password.is_none());
        assert!(KeyMaterial::from_bytes(&[3, 1, 0]).is_none());
    }

    #[test]
    fn empty_key_is_rejected() {
        assert!(matches!(
            KeyMaterial::new(Zeroizing::new(String::new()), None),
            Err(VaultError::BadRequest(_))
        ));
    }

    #[test]
    fn strips_url_scheme() {
        assert_eq!(strip_url("https://www.github.com/login"), "github.com/login");
        assert_eq!(strip_url("gitea.lan:3000"), "gitea.lan:3000");
    }
}
