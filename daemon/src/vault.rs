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
            VaultError::NotFound(path) => write!(f, "{} does not exist", path.display()),
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

fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, std::io::Error> {
    std::fs::read(path).map(Zeroizing::new)
}

pub fn read_keyfile(path: &Path) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    read_file(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => VaultError::NotFound(path.to_path_buf()),
        _ => VaultError::Keyfile(e.to_string()),
    })
}

/// Decrypts the database at `path`. Runs the KDF, so call it from a blocking thread.
pub fn open_database(path: &Path, key: &KeyMaterial) -> Result<Database, VaultError> {
    let data = read_file(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => VaultError::NotFound(path.to_path_buf()),
        _ => VaultError::Io(format!("Cannot read {}: {e}", path.display())),
    })?;
    Database::parse(&data, key.database_key()?).map_err(map_open_error)
}

/// Searchable, secret-free view of one entry.
#[derive(Debug, Clone)]
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
    pub notes: String,
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
            notes: entry.get(keepass::db::fields::NOTES).unwrap_or_default().to_string(),
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
