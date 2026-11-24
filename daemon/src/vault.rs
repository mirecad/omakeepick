//! Opening a KDBX file and turning its entries into a searchable, secret-free index.

use std::collections::HashMap;
use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
        let key = KeyMaterial { keyfile, ..KeyMaterial::from_password(password) };
        if key.is_empty() {
            return Err(VaultError::no_credentials());
        }
        Ok(key)
    }

    /// The password alone, as the daemon holds it while the helper is still reading the key
    /// file. Empty-handed if the password is empty and the key file is all there is.
    pub fn from_password(password: Zeroizing<String>) -> Self {
        KeyMaterial { password: (!password.is_empty()).then_some(password), keyfile: None }
    }

    /// Adds the contents of the key file.
    pub fn with_keyfile(self, keyfile: Zeroizing<Vec<u8>>) -> Self {
        KeyMaterial { keyfile: Some(keyfile), ..self }
    }

    /// Neither a password nor a key file.
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.keyfile.is_none()
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
    pub fn no_credentials() -> Self {
        VaultError::BadRequest("Enter the master password or choose a key file".into())
    }

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
        DatabaseOpenError::Key(DatabaseKeyError::EmptyKey) => VaultError::no_credentials(),
        DatabaseOpenError::Key(e) => VaultError::Keyfile(e.to_string()),
        DatabaseOpenError::Io(e) => VaultError::Io(e.to_string()),
        other => VaultError::Format(other.to_string()),
    }
}

/// Largest files we read. Real databases and key files are far smaller; without a cap a
/// device node or a sparse file would be read into memory whole.
///
/// Opening a database takes five to seven times its size in memory when its contents do not
/// compress. At this size that is up to 0.9 GiB, which the helper's limit
/// (`opener::HELPER_MEMORY_BYTES`) has room for.
pub const MAX_DATABASE_BYTES: u64 = 128 << 20;
const MAX_KEYFILE_BYTES: u64 = 16 << 20;

/// When the database file was last written and how big it is, as of the moment it was read.
/// Tells a real change from a spurious file event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    modified: (i64, i64),
    len: u64,
}

impl Stamp {
    pub const BYTES: usize = 24;

    fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Stamp { modified: (meta.mtime(), meta.mtime_nsec()), len: meta.len() }
    }

    pub fn to_bytes(self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[..8].copy_from_slice(&self.modified.0.to_le_bytes());
        out[8..16].copy_from_slice(&self.modified.1.to_le_bytes());
        out[16..].copy_from_slice(&self.len.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> Self {
        let field = |at: usize| -> [u8; 8] { bytes[at..at + 8].try_into().expect("8 bytes") };
        Stamp {
            modified: (i64::from_le_bytes(field(0)), i64::from_le_bytes(field(8))),
            len: u64::from_le_bytes(field(16)),
        }
    }
}

/// Reads a regular file of at most `limit` bytes. Anything else (a FIFO, which would block the
/// open forever; a device; a huge file) is refused.
///
/// This can still hang for as long as the file system likes (a network mount that stopped
/// answering), so it must only run where no secret is held: in the `opener` helper, before it
/// is given the credentials.
fn read_file(path: &Path, limit: u64) -> Result<(Zeroizing<Vec<u8>>, Stamp), std::io::Error> {
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
    Ok((data, Stamp::of(&meta)))
}

pub fn read_keyfile(path: &Path) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    read_file(path, MAX_KEYFILE_BYTES).map(|(data, _)| data).map_err(|e| match e.kind() {
        ErrorKind::NotFound => VaultError::NotFound(path.to_path_buf()),
        _ => VaultError::Keyfile(e.to_string()),
    })
}

/// Decrypts the database at `path` in this process. The daemon does not: it goes through
/// `opener`. Runs the KDF, so call it from a blocking thread.
pub fn open_database(path: &Path, key: &KeyMaterial) -> Result<Database, VaultError> {
    parse_database(&read_database(path)?.0, key)
}

/// The raw database file and its stamp; `parse_database` decrypts it. Messages never include
/// the path: they can end up in a notification.
pub fn read_database(path: &Path) -> Result<(Zeroizing<Vec<u8>>, Stamp), VaultError> {
    read_file(path, MAX_DATABASE_BYTES).map_err(|e| match e.kind() {
        ErrorKind::NotFound => VaultError::NotFound(path.to_path_buf()),
        _ => VaultError::Io(format!("Cannot read the database file: {e}")),
    })
}

/// The header check alone (see `header`). Needs no key, so a file with absurd derivation
/// settings can be refused before anyone is given the credentials.
pub fn check_header(data: &[u8]) -> Result<(), VaultError> {
    header::check(data)
}

/// Takes out of `db` what the daemon has no use for: attachments (the files and their names),
/// the earlier versions of entries (old passwords among them), custom icons and the list of
/// deleted objects. The helper does this before it hands a database over, so none of it ever
/// reaches the daemon.
pub fn strip(db: &mut Database) {
    // The order matters. The database keeps track of which version of which entry uses an
    // icon, and taking an icon out follows those tracks into the histories: so the icons go
    // while the histories are still there.
    db.foreach_custom_icon_mut(|icon| icon.remove());
    let named: Vec<(EntryId, Vec<String>)> = db
        .iter_all_entries()
        .map(|entry| (entry.id(), entry.attachments_named().map(|(name, _)| name.to_string()).collect()))
        .collect();
    for (id, names) in named {
        let Some(mut entry) = db.entry_mut(id) else { continue };
        for name in names {
            entry.remove_attachment_by_name(&name);
        }
    }
    db.foreach_entry_mut(|mut entry| entry.history = None);
    // Whatever only an earlier version had attached. This goes by what the entries say now,
    // not by the tracks, which the line above has left pointing at versions that are gone.
    db.remove_unused_attachments();
    db.deleted_objects.clear();
    // Tags: a list of strings in memory, each of which costs twenty-four bytes and more
    // however short it is, and a tag in the file can be one separator. Entries keep the tags
    // that the index takes; groups keep none, since nothing reads them.
    db.foreach_entry_mut(|mut entry| {
        let mut room = MAX_INDEXED_TEXT_BYTES;
        entry.tags.retain(|tag| {
            let fits = !tag.is_empty() && tag.len() <= room;
            if fits {
                room -= tag.len();
            }
            fits
        });
        entry.tags.shrink_to_fit();
    });
    db.foreach_group_mut(|mut group| group.tags = Vec::new());
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

    /// Half a minute of one core at the 67 million rounds a second measured on a laptop of
    /// 2023: far above what KeePassXC sets for a derivation of even five seconds, and well
    /// inside the two minutes after which the daemon gives up on a derivation.
    const MAX_AES_ROUNDS: u64 = 1 << 31;
    /// KeePassXC writes 64 MiB unless told otherwise. This much is allocated on the word of a
    /// header nobody has authenticated yet, so it is a size a desktop can spare, and one that
    /// fits in what the helper may have (`opener::HELPER_MEMORY_BYTES`).
    const MAX_ARGON2_MEMORY: u64 = 1 << 30;
    const MAX_ARGON2_ITERATIONS: u64 = 1_000;
    const MAX_ARGON2_PARALLELISM: u32 = 256;
    /// memory × iterations, in bytes·passes: 64 MiB × 1000 passes, about a minute of work.
    const MAX_ARGON2_WORK: u128 = (64 << 20) * 1_000;

    const KDBX_SIGNATURE: [u8; 8] = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
    /// The AES derivation has two names. KDBX 4 files carry the second; the crate takes
    /// either one in them.
    const AES_KDF: [u8; 16] = *b"\xc9\xd9\xf3\x9a\x62\x8a\x44\x60\xbf\x74\x0d\x08\xc1\x8a\x4f\xea";
    const AES_KDF_KDBX4: [u8; 16] = *b"\x7c\x02\xbb\x82\x79\xa7\x4a\xc0\x92\x7d\x11\x4a\x00\x64\x82\x38";
    const ARGON2D: [u8; 16] = *b"\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c";
    const ARGON2ID: [u8; 16] = *b"\x9e\x29\x8b\x19\x56\xdb\x47\x73\xb2\x3d\xfc\x3e\xc6\xf0\xa1\xe6";

    fn damaged() -> VaultError {
        VaultError::Format("the header is damaged".into())
    }

    fn not_kdbx() -> VaultError {
        VaultError::Format("it is not a KDBX 3.1 or KDBX 4 file".into())
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
        // Not KDBX 3 or 4. The crate also reads the format of KeePass 1, whose header says
        // how long to derive as well and is not checked here; nothing but KDBX is let through.
        if data.get(..8) != Some(&KDBX_SIGNATURE[..]) {
            return Err(not_kdbx());
        }
        let major = u16::from_le_bytes(data.get(10..12).ok_or_else(damaged)?.try_into().expect("2 bytes"));
        let length_bytes = match major {
            3 => 2,
            4 => 4,
            _ => return Err(not_kdbx()),
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
                // Should the field come twice, each has to pass, whichever the crate goes by.
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

    fn repeated_key() -> VaultError {
        VaultError::Format("the header repeats a key derivation parameter".into())
    }

    /// Parses a KDBX 4 variant dictionary, checking that fixed-size values have their size.
    ///
    /// A repeated key is refused outright. KeePassXC never writes one, and parsers disagree on
    /// which copy counts (the `keepass` crate keeps the last), so a file could otherwise pass
    /// this check with one value and be derived with another.
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
            let key = String::from_utf8_lossy(key).into_owned();
            if out.iter().any(|(k, _)| *k == key) {
                return Err(repeated_key());
            }
            out.push((key, value));
        }
        Ok(out)
    }

    /// Settings the crate will refuse (a parameter missing, or of another type than it reads)
    /// pass here.
    fn check_kdf(params: &[(String, Value)]) -> Result<(), VaultError> {
        let get = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v);
        let Some(Value::Bytes(uuid)) = get("$UUID") else { return Ok(()) };
        if uuid[..] == AES_KDF || uuid[..] == AES_KDF_KDBX4 {
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
            assert_eq!(check(&argon((1 << 30) + 1024, 1, 1)), Err(too_expensive()));
            assert_eq!(check(&argon(1 << 40, 1, 1)), Err(too_expensive()));
            assert_eq!(check(&argon(64 << 20, 100_000, 1)), Err(too_expensive()));
            assert_eq!(check(&argon(64 << 20, 1, 1 << 20)), Err(too_expensive()));
            assert_eq!(check(&argon(4 << 30, 1_000, 1)), Err(too_expensive()));
            // Under either of its two names.
            for name in [AES_KDF, AES_KDF_KDBX4] {
                let aes = |rounds: u64| {
                    kdbx4(&[
                        ("$UUID", Value::Bytes(name.to_vec())),
                        ("S", Value::Bytes(vec![0; 32])),
                        ("R", Value::U64(rounds)),
                    ])
                };
                check(&aes(60_000_000)).unwrap();
                check(&aes(1 << 31)).unwrap();
                assert_eq!(check(&aes((1 << 31) + 1)), Err(too_expensive()));
                assert_eq!(check(&aes(u64::MAX)), Err(too_expensive()));
            }
            // A u64 parameter that is only 2 bytes long would panic the crate's reader.
            let short = kdbx4(&[("$UUID", Value::Bytes(AES_KDF.to_vec())), ("R", Value::Other)]);
            let mut short = short;
            let at = short.windows(1).rposition(|w| w == b"R").unwrap() + 1;
            short[at - 6] = 0x05; // retag the bool as u64 while leaving its 1-byte value
            assert_eq!(check(&short), Err(damaged()));
        }

        /// The `keepass` crate reads a variant dictionary into a `HashMap`, so of two copies of
        /// a key the last one wins there. A check that looked at the first copy could be
        /// passed with a cheap "R" followed by the real, absurd one.
        #[test]
        fn refuses_repeated_kdf_parameters() {
            let uuid = || ("$UUID", Value::Bytes(AES_KDF.to_vec()));
            let salt = || ("S", Value::Bytes(vec![0; 32]));
            let twice = kdbx4(&[uuid(), salt(), ("R", Value::U64(1)), ("R", Value::U64(u64::MAX))]);
            assert_eq!(check(&twice), Err(repeated_key()));
            // The same for the algorithm itself: AES first, Argon2 with huge memory last.
            let two_kdfs = kdbx4(&[
                uuid(),
                salt(),
                ("R", Value::U64(1)),
                ("$UUID", Value::Bytes(ARGON2ID.to_vec())),
                ("M", Value::U64(1 << 40)),
                ("I", Value::U64(1)),
                ("P", Value::U32(1)),
                ("V", Value::U32(0x13)),
            ]);
            assert_eq!(check(&two_kdfs), Err(repeated_key()));
            // Even a harmless repetition is refused: no real writer produces one.
            let same = kdbx4(&[uuid(), salt(), ("R", Value::U64(1)), ("R", Value::U64(1))]);
            assert_eq!(check(&same), Err(repeated_key()));
            // Public custom data is a variant dictionary too.
            let mut data = kdbx4(&[uuid(), salt(), ("R", Value::U64(1))]);
            let end = data.len() - 9; // before the end field (kind 0, len 4, "\r\n\r\n")
            let mut vd = vec![0x00, 0x01];
            for _ in 0..2 {
                vd.extend([0x04, 1, 0, 0, 0, b'k', 4, 0, 0, 0, 1, 0, 0, 0]);
            }
            vd.push(0);
            let mut field = vec![12];
            field.extend((vd.len() as u32).to_le_bytes());
            field.extend(vd);
            data.splice(end..end, field);
            assert_eq!(check(&data), Err(repeated_key()));
        }

        /// A header can carry the whole KDF field twice, and the crate goes by the last one.
        /// Each of them has to pass.
        #[test]
        fn checks_every_kdf_field() {
            let argon = |memory: u64| {
                kdbx4(&[
                    ("$UUID", Value::Bytes(ARGON2ID.to_vec())),
                    ("S", Value::Bytes(vec![0; 32])),
                    ("M", Value::U64(memory)),
                    ("I", Value::U64(1)),
                    ("P", Value::U32(1)),
                    ("V", Value::U32(0x13)),
                ])
            };
            // Where `kdbx4` puts the KDF field: after the signature, the version and four
            // fields of 16, 4, 32 and 12 bytes; the end field of 9 bytes follows it.
            let kdf_at = 12 + (5 + 16) + (5 + 4) + (5 + 32) + (5 + 12);
            for (first, second, passes) in
                [(64 << 20, 256 << 20, true), (64 << 20, 1 << 40, false), (1 << 40, 64 << 20, false)]
            {
                let mut data = argon(first);
                let other = argon(second);
                assert_eq!(other[kdf_at], 11);
                let end = data.len() - 9;
                data.splice(end..end, other[kdf_at..other.len() - 9].iter().copied());
                assert_eq!(check(&data), if passes { Ok(()) } else { Err(too_expensive()) });
            }
        }

        /// The crate reads more than KDBX: the format of KeePass 1 as well, whose header is
        /// not checked here. Nothing but KDBX 3 and 4 gets as far as the crate.
        #[test]
        fn lets_nothing_but_kdbx_through() {
            let keepass1 = [0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5, 0, 0, 3, 0];
            assert_eq!(check(&keepass1), Err(not_kdbx()));
            assert_eq!(check(b"<?xml version=\"1.0\"?>"), Err(not_kdbx()));
            assert_eq!(check(b""), Err(not_kdbx()));
            let mut kdbx2 = KDBX3.to_vec();
            kdbx2[10] = 2;
            assert_eq!(check(&kdbx2), Err(not_kdbx()));
        }
    }
}

/// The most of a title, a user name, a URL or an entry's tags that the index takes, in bytes.
/// More than anything has to show or to search; what is longer is cut and ends in "…".
pub const MAX_INDEXED_TEXT_BYTES: usize = 1024;
/// The most of an entry's notes that the index takes, and so the most that is searched.
pub const MAX_INDEXED_NOTES_BYTES: usize = 16 << 10;
/// The most of a group's path that the index takes. A longer path loses its beginning: the
/// groups nearest to an entry say most about it.
pub const MAX_GROUP_PATH_BYTES: usize = 256;
/// The most of one group's name in such a path.
const MAX_GROUP_NAME_BYTES: usize = 96;

/// Searchable, secret-free view of one entry. Notes are wiped when the index is dropped: people
/// keep recovery codes in them.
///
/// How long its texts are is not left to the database (see the limits above), and the path
/// of a group exists once however many entries the group has. Without that a database of a
/// few megabytes could ask for an index of any size: the name of a group is in the file
/// once and would be in the index once for every entry under it.
#[derive(Clone)]
pub struct IndexedEntry {
    pub id: EntryId,
    pub uuid: String,
    pub title: String,
    pub username: String,
    pub url: String,
    /// URL without scheme and `www.`, which is what people type.
    pub url_match: String,
    /// The path of the group below the root, e.g. `Personal/Dev`. Shared by its entries.
    pub group: Arc<str>,
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

/// The longest beginning of `text` that is at most `max` bytes.
fn beginning(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The longest end of `text` that is at most `max` bytes.
fn ending(text: &str, max: usize) -> &str {
    let mut start = text.len().saturating_sub(max);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// `text` if it is at most `max` bytes, else its beginning with "…" for the rest.
fn cut(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    format!("{}…", beginning(text, max - "…".len()))
}

/// The path of a group called `name` in the group at `path`, cut to what the index takes.
fn path_below(path: &str, name: &str) -> String {
    let name = cut(name, MAX_GROUP_NAME_BYTES);
    if path.is_empty() {
        return name;
    }
    let whole = format!("{path}/{name}");
    if whole.len() <= MAX_GROUP_PATH_BYTES {
        return whole;
    }
    // From a group's name on where there is one, so that it reads `…/Work/Mail`.
    let kept = ending(&whole, MAX_GROUP_PATH_BYTES - "…".len());
    format!("…{}", kept.find('/').map_or(kept, |slash| &kept[slash..]))
}

/// What an entry has from the groups it is in.
#[derive(Clone)]
struct Inherited {
    path: Arc<str>,
    in_recycle_bin: bool,
    /// KeePass group flags are tri-state: the nearest group with an explicit value decides.
    searching: bool,
    autotype: bool,
}

/// Works out [`Inherited`] once for each group instead of once for each entry. A database
/// can put any number of entries at the bottom of any number of nested groups, and asking
/// every group above every entry is the product of the two.
struct Groups<'a> {
    db: &'a Database,
    recycle_bin: Option<GroupId>,
    known: HashMap<GroupId, Inherited>,
}

impl<'a> Groups<'a> {
    fn new(db: &'a Database) -> Self {
        Groups { db, recycle_bin: db.recycle_bin().map(|g| g.id()), known: HashMap::new() }
    }

    fn of(&mut self, group: GroupId) -> Option<Inherited> {
        // From this group up to the first one that is known already, or to the root.
        let mut unknown = Vec::new();
        let mut above = None;
        let mut next = Some(group);
        while let Some(id) = next {
            if let Some(known) = self.known.get(&id) {
                above = Some(known.clone());
                break;
            }
            unknown.push(id);
            next = self.db.group(id).and_then(|g| g.parent().map(|p| p.id()));
        }
        // And back down, each group from the one above it.
        for id in unknown.into_iter().rev() {
            let group = self.db.group(id)?;
            let in_bin = self.recycle_bin == Some(id);
            let inherited = match (&above, group.parent().is_some()) {
                (Some(above), _) => Inherited {
                    path: path_below(&above.path, &group.name).into(),
                    in_recycle_bin: above.in_recycle_bin || in_bin,
                    searching: group.enable_searching.unwrap_or(above.searching),
                    autotype: group.enable_autotype.unwrap_or(above.autotype),
                },
                // The root: its name is not part of a path.
                (None, is_below_something) => Inherited {
                    path: if is_below_something { path_below("", &group.name).into() } else { "".into() },
                    in_recycle_bin: in_bin,
                    searching: group.enable_searching.unwrap_or(true),
                    autotype: group.enable_autotype.unwrap_or(true),
                },
            };
            self.known.insert(id, inherited.clone());
            above = Some(inherited);
        }
        above
    }
}

fn strip_url(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.strip_prefix("www.").unwrap_or(rest).to_string()
}

/// Indexes every searchable entry: skips the Recycle Bin, expired entries and groups with
/// searching disabled. The work is in proportion to the entries and groups there are, and the
/// result to the text they hold; `opener` limits both before a database gets here.
pub fn build_index(db: &Database) -> Vec<IndexedEntry> {
    let mut groups = Groups::new(db);
    let now = Times::now();
    let mut out = Vec::new();
    for entry in db.iter_all_entries() {
        let Some(group) = groups.of(entry.parent().id()) else { continue };
        if group.in_recycle_bin || !group.searching {
            continue;
        }
        if entry.times.expires == Some(true) && entry.times.expiry < now {
            continue;
        }
        let field = |name: &str| cut(entry.get(name).unwrap_or_default().trim(), MAX_INDEXED_TEXT_BYTES);
        let url = field(keepass::db::fields::URL);
        let mut tags = String::new();
        for tag in &entry.tags {
            if tags.len() > MAX_INDEXED_TEXT_BYTES {
                break;
            }
            if !tags.is_empty() {
                tags.push(' ');
            }
            tags.push_str(beginning(tag, MAX_INDEXED_TEXT_BYTES));
        }
        let notes = entry.get(keepass::db::fields::NOTES).unwrap_or_default();
        out.push(IndexedEntry {
            id: entry.id(),
            uuid: entry.id().uuid().to_string(),
            title: field(keepass::db::fields::TITLE),
            username: field(keepass::db::fields::USERNAME),
            url_match: strip_url(&url),
            url,
            group: group.path,
            tags: cut(&tags, MAX_INDEXED_TEXT_BYTES),
            notes: Zeroizing::new(beginning(notes, MAX_INDEXED_NOTES_BYTES).to_string()),
            has_password: !entry.get_password().unwrap_or_default().is_empty(),
            has_totp: totp::has_totp(&entry),
            autotype: entry.autotype.as_ref().is_none_or(|a| a.enabled) && group.autotype,
        });
    }
    out.sort_by_cached_key(|e| (e.title.to_lowercase(), e.group.to_lowercase()));
    out
}

/// The index of a database: its searchable entries by title, and each one by its UUID.
///
/// The entries can be shared ([`Index::entries`]). A search that is under way keeps the ones
/// it started with, for the moment it takes to notice a lock or a reload.
pub struct Index {
    entries: Arc<[IndexedEntry]>,
    by_uuid: HashMap<String, usize>,
}

impl Index {
    /// See [`build_index`] for what this costs: run it where the daemon is not kept waiting.
    pub fn build(db: &Database) -> Index {
        let entries: Arc<[IndexedEntry]> = build_index(db).into();
        let by_uuid = entries.iter().enumerate().map(|(i, e)| (e.uuid.clone(), i)).collect();
        Index { entries, by_uuid }
    }

    pub fn entries(&self) -> Arc<[IndexedEntry]> {
        self.entries.clone()
    }

    pub fn get(&self, uuid: &str) -> Option<&IndexedEntry> {
        self.by_uuid.get(uuid).map(|&i| &self.entries[i])
    }
}

impl std::ops::Deref for Index {
    type Target = [IndexedEntry];

    fn deref(&self) -> &[IndexedEntry] {
        &self.entries
    }
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
    pub index: Index,
}

impl OpenDb {
    /// Builds the index as well. The daemon has it built along with taking the database over
    /// and uses [`OpenDb::with_index`].
    pub fn new(
        path: PathBuf,
        keyfile: Option<PathBuf>,
        key: KeyMaterial,
        quick: Option<QuickBlob>,
        db: Database,
    ) -> Self {
        let index = Index::build(&db);
        OpenDb::with_index(path, keyfile, key, quick, db, index)
    }

    pub fn with_index(
        path: PathBuf,
        keyfile: Option<PathBuf>,
        key: KeyMaterial,
        quick: Option<QuickBlob>,
        db: Database,
        index: Index,
    ) -> Self {
        OpenDb { path, keyfile, key, quick, db, index }
    }

    /// `index` is the index of `db`.
    pub fn replace_database(&mut self, db: Database, index: Index) {
        self.db = db;
        self.index = index;
    }

    pub fn indexed(&self, uuid: &str) -> Option<&IndexedEntry> {
        self.index.get(uuid)
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
    fn key_material_in_two_steps() {
        let password = KeyMaterial::from_password(Zeroizing::new("pw".into()));
        assert!(!password.is_empty());
        let whole =
            KeyMaterial::from_bytes(&password.to_bytes()).unwrap().with_keyfile(Zeroizing::new(vec![5]));
        let at_once = KeyMaterial::new(Zeroizing::new("pw".into()), Some(Zeroizing::new(vec![5]))).unwrap();
        assert_eq!(whole.to_bytes(), at_once.to_bytes());

        // A key-file-only database: nothing to send until the key file is read.
        let nothing = KeyMaterial::from_password(Zeroizing::new(String::new()));
        assert!(nothing.is_empty());
        let back = KeyMaterial::from_bytes(&nothing.to_bytes()).unwrap();
        assert!(back.is_empty());
        assert!(!back.with_keyfile(Zeroizing::new(vec![1])).is_empty());
    }

    fn group(db: &mut Database, parent: GroupId, name: &str) -> GroupId {
        let mut parent = db.group_mut(parent).unwrap();
        let mut group = parent.add_group();
        group.name = name.into();
        group.id()
    }

    fn entry(db: &mut Database, group: GroupId, title: &str) -> EntryId {
        let mut group = db.group_mut(group).unwrap();
        let mut entry = group.add_entry();
        entry.set_unprotected(keepass::db::fields::TITLE, title);
        entry.id()
    }

    /// What an entry has from the groups above it: the nearest one that says whether to
    /// search or to auto-type decides, the recycle bin counts wherever above it is, and the
    /// path is the names from below the root down.
    #[test]
    fn groups_hand_down_what_they_say() {
        let mut db = Database::new();
        let root = db.root().id();
        let off = group(&mut db, root, "Off");
        db.group_mut(off).unwrap().enable_searching = Some(false);
        db.group_mut(off).unwrap().enable_autotype = Some(false);
        let under = group(&mut db, off, "Under");
        let on_again = group(&mut db, under, "On again");
        db.group_mut(on_again).unwrap().enable_searching = Some(true);
        let below = group(&mut db, on_again, "Below");
        let bin = group(&mut db, root, "Bin");
        db.meta.recyclebin_uuid = Some(bin.uuid());
        let old = group(&mut db, bin, "Old");
        for (group, title) in [
            (root, "at the root"),
            (off, "not searched"),
            (under, "not searched either"),
            (on_again, "searched again"),
            (below, "and below that"),
            (bin, "thrown away"),
            (old, "thrown away with its group"),
        ] {
            entry(&mut db, group, title);
        }
        let found: Vec<(String, String, bool)> =
            build_index(&db).into_iter().map(|e| (e.title, e.group.to_string(), e.autotype)).collect();
        assert_eq!(
            found,
            [
                ("and below that".to_string(), "Off/Under/On again/Below".to_string(), false),
                ("at the root".to_string(), String::new(), true),
                ("searched again".to_string(), "Off/Under/On again".to_string(), false),
            ]
        );
    }

    /// The index takes a fixed length of every text at most, cut where a character ends, and
    /// the path of a group once for all its entries. The database decides neither.
    #[test]
    fn the_database_does_not_decide_how_long_a_text_in_the_index_is() {
        let mut db = Database::new();
        let mut at = db.root().id();
        for level in 0..30 {
            at = group(&mut db, at, &format!("Úroveň číslo {level}"));
        }
        // A megabyte of name, in characters of two bytes.
        at = group(&mut db, at, &"ž".repeat(1 << 19));
        for title in ["first", "second"] {
            let id = entry(&mut db, at, title);
            let mut entry = db.entry_mut(id).unwrap();
            entry.set_unprotected(keepass::db::fields::USERNAME, "ž".repeat(5000));
            entry.set_unprotected(
                keepass::db::fields::URL,
                format!("https://www.example.com/{}", "a".repeat(5000)),
            );
            entry.set_unprotected(keepass::db::fields::NOTES, format!("x{}", "ž".repeat(20_000)));
            entry.tags = (0..500).map(|n| format!("tag-{n}")).collect();
        }
        let index = build_index(&db);
        assert_eq!(index.len(), 2);

        let path = &index[0].group;
        assert!(Arc::ptr_eq(path, &index[1].group), "one path for both entries");
        assert!(path.len() <= MAX_GROUP_PATH_BYTES, "{} bytes", path.len());
        // It lost its beginning and kept the groups nearest to the entry; the long name is cut.
        assert!(path.starts_with("…/Úroveň číslo "), "{path}");
        assert!(path.contains("/Úroveň číslo 29/žžž"), "{path}");
        assert!(path.ends_with("žžž…"), "{path}");

        for e in &index {
            assert!(
                e.username.len() <= MAX_INDEXED_TEXT_BYTES && e.username.ends_with("žž…"),
                "{}",
                e.username.len()
            );
            assert!(e.url.len() <= MAX_INDEXED_TEXT_BYTES && e.url_match.starts_with("example.com/aaa"));
            assert!(
                e.tags.len() <= MAX_INDEXED_TEXT_BYTES && e.tags.starts_with("tag-0 tag-1 "),
                "{}",
                e.tags.len()
            );
            assert!(e.notes.len() <= MAX_INDEXED_NOTES_BYTES && e.notes.len() > MAX_INDEXED_NOTES_BYTES - 2);
            assert!(e.notes.starts_with("xžž") && e.notes.ends_with("žž"));
        }
        // What is short enough is left as it is.
        assert_eq!((index[0].title.as_str(), index[1].title.as_str()), ("first", "second"));
    }

    /// Indexing is work in proportion to the entries and groups there are, however deep the
    /// entries are. Forty thousand entries two thousand groups down are eighty million
    /// questions if every entry asks every group above it; this has to be done in a moment.
    #[test]
    fn indexing_goes_by_how_many_entries_there_are_not_by_how_deep() {
        let mut db = Database::new();
        let mut at = db.root().id();
        for _ in 0..2000 {
            at = db.group_mut(at).unwrap().add_group().id();
        }
        let mut deepest = db.group_mut(at).unwrap();
        for _ in 0..40_000 {
            deepest.add_entry();
        }
        let started = std::time::Instant::now();
        let index = build_index(&db);
        let took = started.elapsed();
        assert_eq!(index.len(), 40_000);
        assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    }

    #[test]
    fn stamp_roundtrip() {
        let stamp = Stamp { modified: (1_762_000_000, 999_999_999), len: 1 << 40 };
        assert_eq!(Stamp::from_bytes(&stamp.to_bytes()), stamp);
        let before = Stamp { modified: (-1, 0), len: 0 };
        assert_eq!(Stamp::from_bytes(&before.to_bytes()), before);
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
