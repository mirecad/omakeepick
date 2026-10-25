//! Persistent, non-secret state: last used database and key file, the key file used with each
//! database, and per-entry usage counts for ranking. Stored as JSON in the state directory.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::search::Usage;

/// Usage entries kept per database; the least recently used are dropped beyond this.
const MAX_USAGE: usize = 1000;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Persisted {
    pub last_db: Option<PathBuf>,
    /// Database path → key file path last used with it.
    pub keyfiles: HashMap<PathBuf, PathBuf>,
    /// Database path → entry UUID → (use count, last use in Unix seconds).
    pub usage: HashMap<PathBuf, Usage>,
}

pub struct Store {
    path: PathBuf,
    pub data: Persisted,
}

impl Store {
    pub fn load(dir: &Path) -> Store {
        let path = dir.join("state.json");
        let data =
            fs::read(&path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        Store { path, data }
    }

    pub fn save(&self) {
        if let Err(e) = self.try_save() {
            eprintln!("omakeepickd: cannot save {}: {e}", self.path.display());
        }
    }

    fn try_save(&self) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            crate::paths::ensure_private_dir(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let mut file =
            fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(&self.data)?)?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)
    }

    pub fn keyfile_for(&self, db: &Path) -> Option<PathBuf> {
        self.data.keyfiles.get(db).cloned()
    }

    /// Remembers a successful unlock.
    pub fn remember(&mut self, db: &Path, keyfile: Option<&Path>) {
        self.data.last_db = Some(db.to_path_buf());
        match keyfile {
            Some(k) => self.data.keyfiles.insert(db.to_path_buf(), k.to_path_buf()),
            None => self.data.keyfiles.remove(db),
        };
        self.save();
    }

    pub fn usage(&self, db: &Path) -> Option<&Usage> {
        self.data.usage.get(db)
    }

    pub fn record_use(&mut self, db: &Path, uuid: &str, now: i64) {
        let usage = self.data.usage.entry(db.to_path_buf()).or_default();
        let slot = usage.entry(uuid.to_string()).or_insert((0, now));
        slot.0 = slot.0.saturating_add(1);
        slot.1 = now;
        if usage.len() > MAX_USAGE {
            let mut by_age: Vec<(String, i64)> = usage.iter().map(|(k, v)| (k.clone(), v.1)).collect();
            by_age.sort_by_key(|(_, last)| *last);
            for (uuid, _) in by_age.into_iter().take(usage.len() - MAX_USAGE) {
                usage.remove(&uuid);
            }
        }
        self.save();
    }

    /// Drops usage of entries that no longer exist.
    pub fn prune_usage(&mut self, db: &Path, live: impl Fn(&str) -> bool) {
        if let Some(usage) = self.data.usage.get_mut(db) {
            let before = usage.len();
            usage.retain(|uuid, _| live(uuid));
            if usage.len() != before {
                self.save();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_usage() {
        let dir = tempfile::tempdir().unwrap();
        let db = Path::new("/x/Secrets.kdbx");
        let mut store = Store::load(dir.path());
        store.remember(db, Some(Path::new("/x/key.keyx")));
        store.record_use(db, "a", 10);
        store.record_use(db, "a", 20);
        store.record_use(db, "b", 15);

        let mut store = Store::load(dir.path());
        assert_eq!(store.data.last_db.as_deref(), Some(db));
        assert_eq!(store.keyfile_for(db).as_deref(), Some(Path::new("/x/key.keyx")));
        assert_eq!(store.usage(db).unwrap()["a"], (2, 20));
        store.prune_usage(db, |uuid| uuid == "a");
        assert!(!store.usage(db).unwrap().contains_key("b"));
        store.remember(db, None);
        assert!(store.keyfile_for(db).is_none());
    }

    #[test]
    fn corrupt_file_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("state.json"), b"{nope").unwrap();
        assert!(Store::load(dir.path()).data.last_db.is_none());
    }
}
