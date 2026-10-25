//! Watches the open database file so external changes (Syncthing, KeePassXC saves) are picked
//! up. The parent directory is watched because most writers replace the file by renaming.

use std::path::Path;

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use tokio::sync::mpsc;

pub struct Watcher {
    _inner: RecommendedWatcher,
}

impl Watcher {
    pub fn new(path: &Path, changed: mpsc::UnboundedSender<()>) -> notify::Result<Watcher> {
        let name = path.file_name().map(|n| n.to_os_string());
        let dir = path.parent().unwrap_or(Path::new("/"));
        let mut inner = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            if matches!(event.kind, EventKind::Access(_)) {
                return;
            }
            if event.paths.iter().any(|p| p.file_name().map(|n| n.to_os_string()) == name) {
                let _ = changed.send(());
            }
        })?;
        inner.watch(dir, RecursiveMode::NonRecursive)?;
        Ok(Watcher { _inner: inner })
    }
}
