//! The clipboard, through wl-clipboard.
//!
//! A value is put on the clipboard by a `wl-copy --foreground` that the daemon starts and keeps
//! as its child. That process is the selection: it serves the value for as long as it lives and
//! ends by itself when something else is copied. Taking a value back is killing it, which needs
//! nothing to answer, neither the compositor nor another tool, so a lock empties the clipboard
//! at once. And whether the clipboard still has our value is whether that process still runs:
//! the clipboard is not read to find out.
//!
//! Values are offered with `--sensitive`, so clipboard managers skip them. One that keeps a copy
//! all the same takes the selection over, which ends our `wl-copy`. For that case alone the
//! clipboard is read: if it still has our value (compared by hash), it is cleared.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::OnceCell;
use zeroize::Zeroizing;

use crate::inflight::Tracker;
use crate::paths;
use crate::tool::{Feed, Stop, Tool};

const TEXT_TYPE: &str = "text/plain;charset=utf-8";

/// How long `wl-copy` gets to take a value. It reads its stdin once it has reached the
/// compositor, so one that has not by then is not going to.
const TAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// `wl-copy` sets the selection right after it has read the value. If that fails, it ends
/// within this.
const SET_GRACE: Duration = Duration::from_millis(20);

/// For each tool run while looking for a copy that a clipboard manager kept.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

fn cannot_run(e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "tool_missing:wl-copy (wl-clipboard) is not installed".to_string(),
        _ => format!("Cannot run wl-copy: {e}"),
    }
}

fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// A `wl-copy` that owns a selection. Dropping it kills it, and the selection is empty again.
pub struct Owner(Tool);

/// The value copied last, as far as it is still ours to take back.
struct Held {
    ticket: u64,
    owner: Owner,
    /// For recognising a copy that a clipboard manager kept.
    hash: [u8; 32],
    len: usize,
}

pub struct Clipboard {
    inflight: Tracker,
    /// Each `wl-copy` gets a directory of its own in here for its buffer file.
    scratch: PathBuf,
    /// Numbers the directories and the tickets.
    next: AtomicU64,
    /// Whether `wl-copy` knows `--sensitive` (wl-clipboard 2.3 and later).
    sensitive: OnceCell<bool>,
    current: Mutex<Option<Held>>,
}

impl Clipboard {
    pub fn new(inflight: Tracker) -> Clipboard {
        let scratch = paths::runtime_dir().join("clip");
        // Whatever a daemon that was killed left behind.
        let _ = std::fs::remove_dir_all(&scratch);
        Clipboard {
            inflight,
            scratch,
            next: AtomicU64::new(1),
            sensitive: OnceCell::new(),
            current: Mutex::new(None),
        }
    }

    async fn knows_sensitive(&self) -> Result<bool, String> {
        let probe = || async {
            // An option wl-copy does not know makes it fail before it looks at `--version`.
            let status = Command::new("wl-copy")
                .args(["--sensitive", "--version"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status()
                .await
                .map_err(cannot_run)?;
            Ok(status.success())
        };
        self.sensitive.get_or_try_init(probe).await.copied()
    }

    /// Puts `data` on the clipboard (or the primary selection) as sensitive text, for as long as
    /// the returned owner exists. `data` is dropped as soon as it is written to `wl-copy`.
    pub async fn offer(&self, data: impl AsRef<[u8]>, primary: bool) -> Result<Owner, String> {
        let sensitive = self.knows_sensitive().await?;
        let (mut feed, stdin) = Feed::new().map_err(cannot_run)?;
        // wl-copy keeps what it is given in a file under TMPDIR: unlinked at once since
        // wl-clipboard 2.3, for as long as it runs before that. In a directory of ours either
        // way, so that nothing of it is left once this wl-copy is killed.
        let scratch = self.scratch.join(self.next.fetch_add(1, Ordering::Relaxed).to_string());
        paths::ensure_private_dir(&scratch).map_err(|e| format!("Cannot prepare the clipboard: {e}"))?;
        let mut command = Command::new("wl-copy");
        command.args(["--foreground", "--type", TEXT_TYPE]);
        if sensitive {
            command.arg("--sensitive");
        }
        if primary {
            command.arg("--primary");
        }
        command.env("TMPDIR", &scratch).stdin(stdin).stdout(Stdio::null()).stderr(Stdio::null());
        let mut tool = Tool::spawn(command, Stop::Kill, Some(scratch), &self.inflight).map_err(cannot_run)?;
        let hand_over = async {
            let written = feed.write(data.as_ref()).await;
            // In the pipe or in wl-copy's hands from here on, and no longer in ours.
            drop(data);
            feed.end();
            written.map_err(|e| format!("wl-copy: {e}"))?;
            feed.taken(&mut tool).await.map_err(|_| "wl-copy failed".to_string())
        };
        match tokio::time::timeout(TAKE_TIMEOUT, hand_over).await {
            Ok(handed) => handed?,
            Err(_) => return Err("The clipboard did not take the value".into()),
        }
        if let Ok(Ok(status)) = tokio::time::timeout(SET_GRACE, tool.wait()).await
            && !status.success()
        {
            return Err("wl-copy failed".into());
        }
        Ok(Owner(tool))
    }

    /// Copies `value` and returns a ticket for [`clear_if_unchanged`](Self::clear_if_unchanged).
    pub async fn copy(&self, value: Zeroizing<String>) -> Result<u64, String> {
        let (hash, len) = (digest(value.as_bytes()), value.len());
        let owner = self.offer(value, false).await?;
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        let previous =
            self.current.lock().expect("clipboard lock").replace(Held { ticket, owner, hash, len });
        // Its wl-copy lost the selection to the new one and is ending by itself.
        drop(previous);
        Ok(ticket)
    }

    /// Takes the value copied under `ticket` back after `delay`, unless something else was
    /// copied since.
    pub async fn clear_if_unchanged(&self, ticket: u64, delay: Duration) {
        tokio::time::sleep(delay).await;
        let held = {
            let mut current = self.current.lock().expect("clipboard lock");
            if current.as_ref().is_some_and(|held| held.ticket == ticket) { current.take() } else { None }
        };
        if let Some(held) = held {
            self.take_back(held);
        }
    }

    /// Takes the value copied last back, right now: this is what a lock calls, and it does not
    /// wait for anything.
    pub fn forget(&self) {
        let held = self.current.lock().expect("clipboard lock").take();
        if let Some(held) = held {
            self.take_back(held);
        }
    }

    fn take_back(&self, mut held: Held) {
        if held.owner.0.is_running() {
            // Ours still: dropping the owner kills it.
            return;
        }
        // Something else has the selection, which ended our wl-copy. Most of the time that is
        // the next thing the user copied. It can also be a clipboard manager that keeps a copy
        // of what it sees, hint or not. Whether it is can only be read off the clipboard, and
        // clearing it takes the compositor: both in the background, as far as they answer.
        let guard = self.inflight.hold();
        tokio::spawn(async move {
            let Held { hash, len, .. } = held;
            if read(len).await.is_some_and(|seen| digest(&seen) == hash) {
                clear().await;
            }
            drop(guard);
        });
    }
}

/// The clipboard's text, if it is no longer than `limit` bytes.
async fn read(limit: usize) -> Option<Zeroizing<Vec<u8>>> {
    let look = async {
        let mut child = Command::new("wl-paste")
            .args(["--no-newline", "--type", "text"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;
        let mut out = child.stdout.take()?;
        // Room for one byte more than our value: anything longer is not it, and is not read.
        // Sized up front, so that it never grows and leaves a copy behind.
        let mut seen = Zeroizing::new(vec![0u8; limit + 1]);
        let mut filled = 0;
        while filled < seen.len() {
            match out.read(&mut seen[filled..]).await {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => return None,
            }
        }
        if filled > limit || !child.wait().await.ok()?.success() {
            return None;
        }
        seen.truncate(filled);
        Some(seen)
    };
    tokio::time::timeout(LOOKUP_TIMEOUT, look).await.ok().flatten()
}

async fn clear() {
    let run = Command::new("wl-copy")
        .arg("--clear")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status();
    let _ = tokio::time::timeout(LOOKUP_TIMEOUT, run).await;
}
