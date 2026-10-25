//! Filesystem locations used by the daemon.
//!
//! `OMAKEEPICK_RUNTIME_DIR` and `OMAKEEPICK_STATE_DIR` override the defaults; the integration
//! tests use them to run an isolated daemon.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn home() -> PathBuf {
    env_dir("HOME").unwrap_or_else(|| PathBuf::from("/"))
}

/// `$XDG_RUNTIME_DIR/omakeepick` (tmpfs, wiped on logout/reboot).
pub fn runtime_dir() -> PathBuf {
    if let Some(dir) = env_dir("OMAKEEPICK_RUNTIME_DIR") {
        return dir;
    }
    let base = env_dir("XDG_RUNTIME_DIR")
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })));
    base.join("omakeepick")
}

/// `$XDG_STATE_HOME/omakeepick` (persistent, never holds secrets).
pub fn state_dir() -> PathBuf {
    if let Some(dir) = env_dir("OMAKEEPICK_STATE_DIR") {
        return dir;
    }
    env_dir("XDG_STATE_HOME").unwrap_or_else(|| home().join(".local/state")).join("omakeepick")
}

pub fn socket_path() -> PathBuf {
    runtime_dir().join("sock")
}

pub fn log_path() -> PathBuf {
    state_dir().join("daemon.log")
}

/// Creates `dir` (and parents) and forces it to mode 0700.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Expands a leading `~/` so paths typed by hand behave like in a shell.
pub fn expand_home(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None if path == "~" => home(),
        None => PathBuf::from(path),
    }
}
