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
//! clipboard is read: if it still has our value (compared by a salted hash), it is cleared.
//!
//! This needs wl-clipboard 2.3 or newer, and not only for `--sensitive`. Its `wl-copy` keeps
//! what it is given in a file. Since 2.3 that file is under `$TMPDIR`, which the daemon points
//! at a directory of its own, and is unlinked as soon as it is written. Before 2.2 it stayed in
//! `/tmp` until `wl-copy` ended in its own time, so a `wl-copy` that is killed left it there.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::runtime::Handle;
use tokio::sync::OnceCell;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

/// For a tool that is only asked something: `wl-copy` its version, and `wl-paste` and
/// `wl-copy --clear` while looking for a copy that a clipboard manager kept.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

const TOO_OLD: &str = "tool_missing:wl-clipboard 2.3 or newer is needed";

fn cannot_run(e: std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "tool_missing:wl-copy (wl-clipboard) is not installed".to_string(),
        _ => format!("Cannot run wl-copy: {e}"),
    }
}

/// What it takes to know a value again without keeping it: a salted hash and the length. On
/// the heap, so that moving its owner about leaves no copy of it behind, and wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
struct Mark {
    salt: [u8; 16],
    hash: [u8; 32],
    len: usize,
}

impl Mark {
    fn hash(salt: &[u8; 16], data: &[u8]) -> [u8; 32] {
        Sha256::new().chain_update(salt).chain_update(data).finalize().into()
    }

    fn of(data: &[u8]) -> Box<Mark> {
        let mut mark = Box::new(Mark { salt: [0; 16], hash: [0; 32], len: data.len() });
        // Without randomness the hash is unsalted, which is what it was before it had a salt.
        let _ = getrandom::fill(&mut mark.salt);
        mark.hash = Mark::hash(&mark.salt, data);
        mark
    }

    fn is(&self, data: &[u8]) -> bool {
        let mut hash = Mark::hash(&self.salt, data);
        let same = data.len() == self.len && hash == self.hash;
        hash.zeroize();
        same
    }
}

/// A `wl-copy` that owns a selection. Dropping it takes the value back: it is killed, and the
/// selection is empty again.
pub struct Owner {
    tool: Tool,
    primary: bool,
    /// Taken by `drop`.
    mark: Option<Box<Mark>>,
    inflight: Tracker,
}

impl Owner {
    /// For an owner whose selection another one of ours has just taken. There is nothing of
    /// its value to look for: what is on the clipboard now is the new owner's, and if the two
    /// values are the same, looking would find the new one and clear it.
    fn superseded(mut self) {
        self.mark = None;
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        if self.tool.is_running() {
            // Ours still: dropping the tool kills it.
            return;
        }
        // Something else has the selection, which ended our wl-copy. Most of the time that is
        // the next thing the user copied. It can also be a clipboard manager that keeps a copy
        // of what it sees, hint or not. Whether it is can only be read off the clipboard, and
        // clearing it takes the compositor: both in the background, as far as they answer,
        // and no longer than a suspend can wait. Giving up drops what was read so far.
        let (Some(mark), Ok(runtime)) = (self.mark.take(), Handle::try_current()) else { return };
        let primary = self.primary;
        let guard = self.inflight.hold();
        let hurried = guard.hurried();
        runtime.spawn(async move {
            let look = async {
                if read(primary, mark.len).await.is_some_and(|seen| mark.is(&seen)) {
                    clear(primary).await;
                }
            };
            tokio::select! {
                () = look => {}
                () = hurried => {}
            }
            drop(guard);
        });
    }
}

/// The value copied last, for as long as it is ours to take back.
struct Held {
    ticket: u64,
    /// One that has ended by itself (something else was copied) stays here, unreaped, until
    /// the clear timer, a lock or the next copy drops it.
    owner: Owner,
}

pub struct Clipboard {
    inflight: Tracker,
    /// Each `wl-copy` gets a directory of its own in here for its buffer file.
    scratch: PathBuf,
    /// Numbers the directories and the tickets.
    next: AtomicU64,
    /// Set once `wl-copy` has shown that it is new enough.
    supported: OnceCell<()>,
    /// One copy at a time: two that overlap would each end the other's `wl-copy`.
    turn: tokio::sync::Mutex<()>,
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
            supported: OnceCell::new(),
            turn: tokio::sync::Mutex::new(()),
            current: Mutex::new(None),
        }
    }

    /// Whether `wl-copy` is from wl-clipboard 2.3 or newer, which is when `--sensitive` came.
    async fn check_version(&self) -> Result<(), String> {
        let probe = || async {
            // An option wl-copy does not know makes it fail before it looks at `--version`.
            let asked = Command::new("wl-copy")
                .args(["--sensitive", "--version"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status();
            // Whoever asks has a value in hand, and others wait their turn behind it.
            let Ok(status) = tokio::time::timeout(LOOKUP_TIMEOUT, asked).await else {
                return Err("wl-copy does not answer".to_string());
            };
            if status.map_err(cannot_run)?.success() { Ok(()) } else { Err(TOO_OLD.to_string()) }
        };
        self.supported.get_or_try_init(probe).await.map(|_| ())
    }

    /// Puts `data` on the clipboard (or the primary selection) as sensitive text, for as long as
    /// the returned owner exists. `data` is dropped as soon as it is written to `wl-copy`.
    pub async fn offer(&self, data: impl AsRef<[u8]>, primary: bool) -> Result<Owner, String> {
        self.check_version().await?;
        let mark = Mark::of(data.as_ref());
        let (mut feed, stdin) = Feed::new().map_err(cannot_run)?;
        // wl-copy keeps what it is given in a file under TMPDIR, which it unlinks as soon as
        // it is written. A directory of ours, removed with whatever is in it once this wl-copy
        // is gone: killed at the wrong moment, it would leave the file.
        let scratch = self.scratch.join(self.next.fetch_add(1, Ordering::Relaxed).to_string());
        paths::ensure_private_dir(&scratch).map_err(|e| format!("Cannot prepare the clipboard: {e}"))?;
        let mut command = Command::new("wl-copy");
        command.args(["--foreground", "--sensitive", "--type", TEXT_TYPE]);
        if primary {
            command.arg("--primary");
        }
        command.env("TMPDIR", &scratch).stdin(stdin).stdout(Stdio::null()).stderr(Stdio::null());
        let mut tool = Tool::spawn(command, Stop::Kill, Some(scratch), &self.inflight).map_err(cannot_run)?;
        let hand_over = async {
            let written = tokio::select! {
                written = feed.write(data.as_ref()) => written.map_err(|e| format!("wl-copy: {e}")),
                // More than fits in the pipe, and nobody is going to read the rest.
                _ = tool.wait() => Err("wl-copy failed".to_string()),
            };
            // In the pipe or in wl-copy's hands from here on, and no longer in ours.
            drop(data);
            feed.end();
            written?;
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
        Ok(Owner { tool, primary, mark: Some(mark), inflight: self.inflight.clone() })
    }

    /// Copies `value` and returns a ticket for [`clear_if_unchanged`](Self::clear_if_unchanged).
    pub async fn copy(&self, value: Zeroizing<String>) -> Result<u64, String> {
        let _turn = self.turn.lock().await;
        let owner = self.offer(value, false).await?;
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        let previous = self.current.lock().expect("clipboard lock").replace(Held { ticket, owner });
        // Its wl-copy lost the selection to the new one and has ended, or is about to.
        if let Some(previous) = previous {
            previous.owner.superseded();
        }
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
        drop(held);
    }

    /// Takes the value copied last back, right now: this is what a lock calls, and it does not
    /// wait for anything.
    pub fn forget(&self) {
        let held = self.current.lock().expect("clipboard lock").take();
        drop(held);
    }
}

fn selection(primary: bool) -> &'static [&'static str] {
    if primary { &["--primary"] } else { &[] }
}

/// The text on a selection, if it is no longer than `limit` bytes.
async fn read(primary: bool, limit: usize) -> Option<Zeroizing<Vec<u8>>> {
    let look = async {
        let mut child = Command::new("wl-paste")
            .args(selection(primary))
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

async fn clear(primary: bool) {
    let run = Command::new("wl-copy")
        .args(selection(primary))
        .arg("--clear")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status();
    let _ = tokio::time::timeout(LOOKUP_TIMEOUT, run).await;
}
