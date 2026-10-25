//! Clipboard access through wl-clipboard.
//!
//! Values are offered with `--sensitive` so clipboard managers skip them, and a copied secret
//! is cleared after a timeout, but only if the clipboard still holds it.

use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const TEXT_TYPE: &str = "text/plain;charset=utf-8";

async fn wl_copy(args: &[&str], data: Option<&[u8]>) -> Result<(), String> {
    let mut child = Command::new("wl-copy")
        .args(args)
        .stdin(if data.is_some() { Stdio::piped() } else { Stdio::null() })
        // wl-copy forks a server that inherits these; never tie it to our pipes.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                "tool_missing:wl-copy (wl-clipboard) is not installed".to_string()
            }
            _ => format!("Cannot run wl-copy: {e}"),
        })?;
    if let Some(data) = data {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(data).await.map_err(|e| format!("wl-copy: {e}"))?;
    }
    let status = child.wait().await.map_err(|e| format!("wl-copy: {e}"))?;
    if !status.success() {
        return Err("wl-copy failed".into());
    }
    Ok(())
}

/// Puts `data` on the clipboard (or the primary selection) as sensitive text.
pub async fn set(data: &[u8], primary: bool) -> Result<(), String> {
    let mut args = vec!["--type", TEXT_TYPE, "--sensitive"];
    if primary {
        args.push("--primary");
    }
    if wl_copy(&args, Some(data)).await.is_ok() {
        return Ok(());
    }
    // wl-clipboard < 2.3 has no --sensitive.
    args.retain(|a| *a != "--sensitive");
    wl_copy(&args, Some(data)).await
}

async fn clear(primary: bool) {
    let args: &[&str] = if primary { &["--primary", "--clear"] } else { &["--clear"] };
    let _ = wl_copy(args, None).await;
}

pub async fn clear_all() {
    clear(false).await;
    clear(true).await;
}

async fn read() -> Option<Vec<u8>> {
    let out = Command::new("wl-paste")
        .args(["--no-newline", "--type", "text"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    out.status.success().then_some(out.stdout)
}

fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Tracks the secret we last copied (as a hash) so it can be cleared later without clobbering
/// anything the user copied in the meantime.
#[derive(Default)]
pub struct Clipboard {
    current: Mutex<Option<(u64, [u8; 32])>>,
}

impl Clipboard {
    /// Copies `value` and returns a ticket for [`clear_if_unchanged`](Self::clear_if_unchanged).
    pub async fn copy(&self, value: &[u8]) -> Result<u64, String> {
        set(value, false).await?;
        let mut current = self.current.lock().expect("clipboard lock");
        let ticket = current.map_or(1, |(t, _)| t + 1);
        *current = Some((ticket, digest(value)));
        Ok(ticket)
    }

    /// Clears the clipboard after `delay` if it still holds the value copied under `ticket`.
    pub async fn clear_if_unchanged(&self, ticket: u64, delay: Duration) {
        tokio::time::sleep(delay).await;
        let expected = match *self.current.lock().expect("clipboard lock") {
            Some((t, hash)) if t == ticket => hash,
            _ => return,
        };
        self.clear_matching(expected).await;
    }

    /// Clears the clipboard right away if it still holds our last secret (used on lock).
    pub async fn clear_now(&self) {
        let expected = match *self.current.lock().expect("clipboard lock") {
            Some((_, hash)) => hash,
            None => return,
        };
        self.clear_matching(expected).await;
    }

    async fn clear_matching(&self, expected: [u8; 32]) {
        let held = read().await.map(|mut data| {
            let hash = digest(&data);
            zeroize::Zeroize::zeroize(&mut data);
            hash
        });
        if held == Some(expected) {
            clear(false).await;
        }
        let mut current = self.current.lock().expect("clipboard lock");
        if current.is_some_and(|(_, hash)| hash == expected) {
            *current = None;
        }
    }
}
