//! The daemon's state machine and command handlers.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keepass::Database;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Notify, broadcast, mpsc};
use zeroize::Zeroizing;

use crate::autotype::{self, Fields, PasteTypist, Wtype};
use crate::clipboard::Clipboard;
use crate::config::Settings;
use crate::opener::Opener;
use crate::protocol::{ApiError, Reply, args, ok, ok_with};
use crate::quickunlock::{self, QuickBlob};
use crate::search::Searcher;
use crate::state::Store;
use crate::vault::{self, KeyMaterial, OpenDb, Stamp, VaultError};
use crate::{paths, portal, totp, watch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Manual,
    Idle,
    Screen,
    Sleep,
    Pin,
    Closed,
}

impl LockReason {
    fn as_str(self) -> &'static str {
        match self {
            LockReason::Manual => "manual",
            LockReason::Idle => "idle",
            LockReason::Screen => "screen",
            LockReason::Sleep => "sleep",
            LockReason::Pin => "pin",
            LockReason::Closed => "closed",
        }
    }

    /// Suspend, too many wrong PINs and closing forget the quick-unlock key as well.
    fn wipes_quick_unlock(self) -> bool {
        matches!(self, LockReason::Sleep | LockReason::Pin | LockReason::Closed)
    }
}

/// A database that was unlocked and is now locked.
struct LockedDb {
    path: PathBuf,
    keyfile: Option<PathBuf>,
    quick: Option<QuickBlob>,
}

pub struct Core {
    settings: Settings,
    open: Option<OpenDb>,
    /// The stamp of the file the open database was read from, as the helper that read it saw
    /// it. The daemon itself never touches the file: any file access can hang.
    open_stamp: Option<Stamp>,
    locked: Option<LockedDb>,
    busy: bool,
    /// Set from logind's announcement of a sleep until it reports the wake-up. Nothing is
    /// unlocked meanwhile: an unlock that starts after the sleep's lock is not cancelled by it
    /// and would leave an open database in RAM, and so in a hibernation image.
    sleeping: bool,
    /// Bumped by every lock. An unlock captures it when it starts and its result is installed
    /// only if it is unchanged, so a lock, close or suspend during an unlock always wins.
    epoch: u64,
    /// Publishes `epoch`, so a running unlock or reload can stop, drop what it holds and kill
    /// its helper the moment a lock happens instead of finishing first.
    epoch_tx: tokio::sync::watch::Sender<u64>,
    /// The epoch of the last lock that wiped quick unlock. A quick unlock that started before
    /// it must not put its PIN key back.
    wiped_at: u64,
    lock_reason: Option<LockReason>,
    last_activity: Instant,
    store: Store,
    searcher: Searcher,
    watcher: Option<watch::Watcher>,
}

/// A key derivation that runs longer than this is killed. Legitimate derivations take a second
/// or two; the header check in `vault` already refuses absurd parameters, so this is the
/// backstop.
const KDF_TIMEOUT: Duration = Duration::from_secs(120);
const TOOK_TOO_LONG: &str = "Opening the database took too long and was abandoned";

/// A helper that has not read the database and the key file by then is killed: the file system
/// they are on is not answering.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TOO_LONG: &str = "Reading the database or the key file took too long and was abandoned";

/// How long a suspend is held back for a killed helper that was never given credentials. A
/// helper that `SIGKILL` has not ended by then is stuck in a file read the kernel will not
/// interrupt, for as long as the file system stays silent.
const STUCK_HELPER_GRACE: Duration = Duration::from_secs(1);

const MAX_QUERY_BYTES: usize = 256;
const MAX_QUERY_ATOMS: usize = 16;

/// Test hook: with the environment variable `name` set to a FIFO, an unlock blocks there until
/// the test writes to it, so a lock can be sent while the unlock is in flight.
/// `OMAKEEPICK_TEST_HOLD` is before the PIN check and before the helper starts,
/// `OMAKEEPICK_TEST_HOLD_HANDOVER` after the helper has handed the database over. Debug builds
/// only. `opener` has the matching hooks for the helper's file reads and for the derivation.
fn test_hold(name: &str) {
    #[cfg(debug_assertions)]
    if let Some(fifo) = std::env::var_os(name) {
        let _ = std::fs::read(fifo);
    }
    #[cfg(not(debug_assertions))]
    let _ = name;
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn unix_now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

fn db_name(path: &Path) -> String {
    path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

impl Core {
    fn phase(&self) -> &'static str {
        if self.open.is_some() {
            "unlocked"
        } else if self.locked.is_some() {
            "locked"
        } else {
            "closed"
        }
    }

    fn idle_deadline(&self) -> Option<Instant> {
        let minutes = self.settings.idle_lock_minutes;
        (self.open.is_some() && minutes > 0)
            .then(|| self.last_activity + Duration::from_secs(u64::from(minutes) * 60))
    }

    fn state(&self) -> Value {
        let (db, keyfile) = match (&self.open, &self.locked) {
            (Some(open), _) => (Some(open.path.clone()), open.keyfile.clone()),
            (None, Some(locked)) => (Some(locked.path.clone()), locked.keyfile.clone()),
            (None, None) => {
                let last = self.store.data.last_db.clone();
                let keyfile = last.as_deref().and_then(|db| self.store.keyfile_for(db));
                (last, keyfile)
            }
        };
        let quick = self.locked.as_ref().and_then(|l| l.quick.as_ref());
        let lock_at = self.idle_deadline().map(|deadline| {
            unix_now_ms() + deadline.saturating_duration_since(Instant::now()).as_millis() as i64
        });
        json!({
            "event": "state",
            "version": env!("CARGO_PKG_VERSION"),
            "phase": self.phase(),
            "busy": self.busy,
            "quickUnlock": quick.is_some(),
            "pinAttemptsLeft": quick.map_or(0, QuickBlob::attempts_left),
            "dbName": db.as_deref().map(db_name),
            "db": db,
            "keyfile": keyfile,
            "entryCount": self.open.as_ref().map_or(0, |o| o.index.len()),
            "lockAt": lock_at,
            "idleLockMinutes": self.settings.idle_lock_minutes,
            "lockReason": self.lock_reason.map(LockReason::as_str),
        })
    }

    /// Returns whether anything changed. Cancelling an unlock that is still running counts: its
    /// result would otherwise reopen the database after this lock.
    fn lock(&mut self, reason: LockReason) -> bool {
        self.watcher = None;
        self.epoch += 1;
        self.epoch_tx.send_replace(self.epoch);
        if reason.wipes_quick_unlock() {
            self.wiped_at = self.epoch;
        }
        let interrupted = self.busy;
        let changed = if let Some(open) = self.open.take() {
            let OpenDb { path, keyfile, quick, .. } = open;
            let quick = if reason.wipes_quick_unlock() { None } else { quick };
            self.locked = Some(LockedDb { path, keyfile, quick });
            true
        } else if let Some(locked) = &mut self.locked {
            let wiped = reason.wipes_quick_unlock() && locked.quick.is_some();
            if wiped {
                locked.quick = None;
            }
            wiped
        } else {
            false
        };
        if !changed && !interrupted {
            return false;
        }
        self.lock_reason = Some(reason);
        true
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Puts the PIN key a quick unlock took back, unless a lock since `epoch` wiped quick
    /// unlock (suspend, close) or there is no locked database left to hold it.
    fn restore_quick(&mut self, blob: QuickBlob, epoch: u64) -> bool {
        if self.wiped_at > epoch {
            return false;
        }
        match self.locked.as_mut() {
            Some(locked) => {
                locked.quick = Some(blob);
                true
            }
            None => false,
        }
    }
}

#[derive(Deserialize)]
struct UnlockArgs {
    db: String,
    keyfile: Option<String>,
    #[serde(default)]
    password: Zeroizing<String>,
    pin: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
struct PinArgs {
    pin: Zeroizing<String>,
}

#[derive(Deserialize)]
struct LockArgs {
    reason: Option<String>,
}

#[derive(Deserialize)]
struct SearchArgs {
    #[serde(default)]
    query: String,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct ActArgs {
    entry: String,
    action: String,
}

#[derive(Deserialize)]
struct PickArgs {
    kind: String,
}

#[derive(Deserialize)]
struct ConfigureArgs {
    settings: Value,
}

fn absolute(path: &str, what: &str) -> Result<PathBuf, ApiError> {
    let path = paths::expand_home(path.trim());
    if !path.is_absolute() {
        return Err(ApiError::bad_request(format!("The {what} path must be absolute")));
    }
    Ok(path)
}

/// Resolves auto-type placeholders against one entry.
struct EntryFields<'a>(&'a keepass::db::Entry);

impl Fields for EntryFields<'_> {
    fn field(&self, name: &str) -> Result<Option<Zeroizing<String>>, String> {
        use keepass::db::fields;
        let key = match name {
            "USERNAME" => fields::USERNAME,
            "PASSWORD" => fields::PASSWORD,
            "TITLE" => fields::TITLE,
            "URL" => fields::URL,
            "NOTES" => fields::NOTES,
            "TOTP" => return totp::current_code(self.0).map(|(code, _)| Some(code)),
            custom => custom.strip_prefix("S:").unwrap_or(custom),
        };
        Ok(self.0.get(key).map(|v| Zeroizing::new(v.to_string())))
    }
}

enum Prepared {
    Copy { value: Zeroizing<String>, what: &'static str },
    Type { tokens: Vec<autotype::Token> },
}

/// What a helper produced: the decrypted database, the credentials that open the file (the
/// password together with the key file as the helper read it) and the file's stamp.
struct Opened {
    db: Database,
    key: KeyMaterial,
    stamp: Stamp,
}

/// Why an open did not produce a database.
enum OpenError {
    /// A lock happened while it ran; the helper was killed.
    Cancelled,
    Vault(VaultError),
}

impl From<VaultError> for OpenError {
    fn from(err: VaultError) -> Self {
        OpenError::Vault(err)
    }
}

pub struct Daemon {
    core: Mutex<Core>,
    events: broadcast::Sender<String>,
    idle_wakeup: Notify,
    quit: Notify,
    clipboard: Clipboard,
    reload_tx: mpsc::UnboundedSender<()>,
    /// Whatever holds secrets outside `core`: unlocks, reloads, copies and auto-type, and
    /// helpers that were killed but are not reaped yet. `lock_and_settle` waits for them, so
    /// suspend is not allowed while they exist.
    inflight: AtomicUsize,
    settled: Notify,
}

/// Counts one holder in `Daemon::inflight` while it exists.
struct Inflight(Arc<Daemon>);

impl Inflight {
    fn new(daemon: &Arc<Daemon>) -> Self {
        daemon.inflight.fetch_add(1, Ordering::SeqCst);
        Inflight(daemon.clone())
    }
}

impl Drop for Inflight {
    fn drop(&mut self) {
        if self.0.inflight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.settled.notify_waiters();
        }
    }
}

impl Daemon {
    pub fn new(state_dir: &Path) -> (Arc<Daemon>, mpsc::UnboundedReceiver<()>) {
        let (events, _) = broadcast::channel(64);
        let (reload_tx, reload_rx) = mpsc::unbounded_channel();
        let daemon = Daemon {
            core: Mutex::new(Core {
                settings: Settings::default(),
                open: None,
                open_stamp: None,
                locked: None,
                busy: false,
                sleeping: false,
                epoch: 0,
                epoch_tx: tokio::sync::watch::channel(0).0,
                wiped_at: 0,
                lock_reason: None,
                last_activity: Instant::now(),
                store: Store::load(state_dir),
                searcher: Searcher::default(),
                watcher: None,
            }),
            events,
            idle_wakeup: Notify::new(),
            quit: Notify::new(),
            clipboard: Clipboard::default(),
            reload_tx,
            inflight: AtomicUsize::new(0),
            settled: Notify::new(),
        };
        (Arc::new(daemon), reload_rx)
    }

    fn core(&self) -> MutexGuard<'_, Core> {
        // A panic aborts the process (panic = "abort"), so the lock cannot be poisoned in release
        // builds; in tests, recover the guard rather than cascading.
        self.core.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.events.subscribe()
    }

    pub fn state_line(&self) -> String {
        let mut line = self.core().state().to_string();
        line.push('\n');
        line
    }

    fn emit_state(&self) {
        let _ = self.events.send(self.state_line());
        self.idle_wakeup.notify_one();
    }

    fn notice(&self, level: &str, message: &str) {
        let mut line = json!({"event": "notice", "level": level, "message": message}).to_string();
        line.push('\n');
        let _ = self.events.send(line);
    }

    pub fn idle_deadline(&self) -> Option<Instant> {
        self.core().idle_deadline()
    }

    pub async fn idle_changed(&self) {
        self.idle_wakeup.notified().await
    }

    /// Resolves when a client sent `quit`.
    pub async fn quit_requested(&self) {
        self.quit.notified().await
    }

    /// Logind announced a sleep. Called before the lock that goes with it: from here until
    /// [`woke`](Self::woke), `unlock` and `quickUnlock` are refused.
    pub fn going_to_sleep(&self) {
        self.core().sleeping = true;
    }

    /// The sleep is over, or did not happen after all.
    pub fn woke(&self) {
        self.core().sleeping = false;
    }

    /// Locks right away. The clipboard clear runs in the background; `lock_and_settle` waits
    /// for it.
    pub fn lock(self: &Arc<Self>, reason: LockReason) -> Option<tokio::task::JoinHandle<()>> {
        let changed = self.core().lock(reason);
        if !changed {
            return None;
        }
        eprintln!("omakeepickd: locked ({})", reason.as_str());
        self.emit_state();
        let daemon = self.clone();
        Some(tokio::spawn(async move { daemon.clipboard.clear_now().await }))
    }

    /// Locks, then waits (at most `limit`) until the clipboard is cleared and no request still
    /// holds secrets outside `core`. Used before suspend and on exit, where "locked" has to mean
    /// that nothing decrypted is left in RAM or on the clipboard.
    pub async fn lock_and_settle(self: &Arc<Self>, reason: LockReason, limit: Duration) {
        let deadline = Instant::now() + limit;
        let clear = self.lock(reason);
        let settle = async {
            if let Some(clear) = clear {
                let _ = clear.await;
            }
            loop {
                let waiting = self.settled.notified();
                if self.inflight.load(Ordering::SeqCst) == 0 {
                    return;
                }
                waiting.await;
            }
        };
        if tokio::time::timeout_at(deadline.into(), settle).await.is_err() {
            // An unlock or reload dropped what it held when the lock happened, and its helper
            // was killed. What is left is a copy or auto-type that `wl-copy` or `wtype` is
            // still busy with; its result is discarded either way.
            eprintln!(
                "omakeepickd: {} task(s) still not finished {:.1}s after locking",
                self.inflight.load(Ordering::SeqCst),
                limit.as_secs_f64()
            );
        }
    }

    /// Resolves once a lock has happened since `epoch`.
    async fn locked_since(&self, epoch: u64) {
        let mut epochs = self.core().epoch_tx.subscribe();
        if epochs.wait_for(|e| *e != epoch).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// Starts a helper (see `opener`) and waits until it has read the database and the key
    /// file. This is the step that touches the file system, and it can hang with it. The
    /// helper has no credential yet and the caller's are in its own frame, so a lock since
    /// `epoch` (or the timeout) makes this return at once and the caller drop them, while the
    /// helper is killed behind it.
    async fn read_files(
        self: &Arc<Self>,
        path: &Path,
        keyfile: Option<&Path>,
        epoch: u64,
    ) -> Result<(Opener, Stamp), OpenError> {
        if !self.still(epoch) {
            return Err(OpenError::Cancelled);
        }
        // /proc/self/exe rather than a path: the binary may have been replaced since we started,
        // and the helper must speak this daemon's protocol.
        let mut opener = tokio::select! {
            biased;
            () = self.locked_since(epoch) => return Err(OpenError::Cancelled),
            opener = Opener::spawn(Path::new("/proc/self/exe"), path, keyfile) => opener?,
        };
        let outcome = tokio::select! {
            biased;
            () = self.locked_since(epoch) => Err(OpenError::Cancelled),
            stamp = opener.read() => stamp.map_err(OpenError::Vault),
            () = tokio::time::sleep(READ_TIMEOUT) => Err(OpenError::Vault(VaultError::Io(READ_TOO_LONG.into()))),
        };
        match outcome {
            Ok(stamp) => Ok((opener, stamp)),
            Err(e) => {
                self.discard(opener);
                Err(e)
            }
        }
    }

    /// Gives `key` to a helper that has read the files and waits for the database. The helper
    /// only computes from here on, so a lock since `epoch` (or the timeout) kills it promptly.
    async fn decrypt(
        self: &Arc<Self>,
        mut opener: Opener,
        stamp: Stamp,
        key: KeyMaterial,
        epoch: u64,
    ) -> Result<Opened, OpenError> {
        let outcome = tokio::select! {
            biased;
            () = self.locked_since(epoch) => Err(OpenError::Cancelled),
            result = opener.decrypt(key) => result.map_err(OpenError::Vault),
            () = tokio::time::sleep(KDF_TIMEOUT) => Err(OpenError::Vault(VaultError::Io(TOOK_TOO_LONG.into()))),
        };
        let handover = match outcome {
            Ok(handover) => handover,
            Err(e) => {
                self.discard(opener);
                return Err(e);
            }
        };
        // Taking the hand-over apart is a few milliseconds of parsing in memory. It is waited
        // for rather than raced against a lock, so that nothing decrypted is ever left on a
        // thread nobody waits for; the caller checks the epoch before it installs the result.
        let unsealing = tokio::task::spawn_blocking(move || {
            test_hold("OMAKEEPICK_TEST_HOLD_HANDOVER");
            handover.unseal()
        });
        let (db, key) =
            unsealing.await.unwrap_or_else(|e| Err(VaultError::Io(format!("Database helper: {e}"))))?;
        Ok(Opened { db, key, stamp })
    }

    /// Both steps in a row, for an unlock: `read_files`, then `decrypt`.
    async fn open_database(
        self: &Arc<Self>,
        path: &Path,
        keyfile: Option<&Path>,
        key: KeyMaterial,
        epoch: u64,
    ) -> Result<Opened, OpenError> {
        let (opener, stamp) = self.read_files(path, keyfile, epoch).await?;
        self.decrypt(opener, stamp, key, epoch).await
    }

    /// Kills a helper and returns at once, so the caller can drop what it holds without
    /// waiting. `lock_and_settle` still waits until the helper is reaped: always, if it was
    /// given the credentials (it only computes then, and dies promptly), and otherwise for
    /// `STUCK_HELPER_GRACE`.
    fn discard(self: &Arc<Self>, opener: Opener) {
        let given = opener.was_given_credentials();
        let gone = opener.kill();
        let unsettled = Inflight::new(self);
        tokio::spawn(async move {
            tokio::pin!(gone);
            if given {
                gone.await;
            } else if tokio::time::timeout(STUCK_HELPER_GRACE, &mut gone).await.is_err() {
                // All it has is what it read from the files so far. Holding a suspend back any
                // longer would not make it go away.
                eprintln!("omakeepickd: a helper is stuck reading a file; it was not given credentials");
                drop(unsettled);
                gone.await;
                return;
            }
            drop(unsettled);
        });
    }

    /// Starts watching the database that was just installed under `epoch`, in the background.
    /// Adding the watch looks the file's directory up, which can hang like any file access, so
    /// it happens on a thread that holds nothing secret, and the unlock does not wait for it.
    ///
    /// Once the watch is in, one reload is asked for: the file may have changed between the
    /// helper reading it and the watch going in, and an event that came while nothing was open
    /// went nowhere. The reload's helper compares stamps and stops if they are equal.
    fn watch(self: &Arc<Self>, path: PathBuf, epoch: u64) {
        let (daemon, changed) = (self.clone(), self.reload_tx.clone());
        tokio::spawn(async move {
            let watched = path.clone();
            let added = tokio::task::spawn_blocking(move || watch::Watcher::new(&watched, changed)).await;
            let watcher = match added {
                Ok(Ok(watcher)) => Some(watcher),
                Ok(Err(e)) => {
                    eprintln!("omakeepickd: not watching {}: {e}", path.display());
                    None
                }
                Err(_) => None,
            };
            let mut core = daemon.core();
            // Locked, or another database opened, while the directory took its time.
            if core.epoch != epoch || core.open.as_ref().is_none_or(|open| open.path != path) {
                return;
            }
            core.watcher = watcher;
            drop(core);
            let _ = daemon.reload_tx.send(());
        });
    }

    /// Commands answered immediately, in request order.
    pub fn handle_sync(self: &Arc<Self>, cmd: &str, line: &[u8]) -> Reply {
        match cmd {
            "status" => ok_with(json!({"state": self.core().state()})),
            "configure" => {
                let a: ConfigureArgs = args(line)?;
                let mut core = self.core();
                core.settings = core.settings.merged(&a.settings).map_err(ApiError::bad_request)?;
                drop(core);
                self.emit_state();
                ok()
            }
            "lock" => {
                let a: LockArgs = args(line)?;
                let reason = match a.reason.as_deref() {
                    None | Some("manual") => LockReason::Manual,
                    Some("screen") => LockReason::Screen,
                    Some("idle") => LockReason::Idle,
                    Some("sleep") => LockReason::Sleep,
                    Some(other) => return Err(ApiError::bad_request(format!("Unknown lock reason {other}"))),
                };
                self.lock(reason);
                ok()
            }
            "close" => {
                let mut core = self.core();
                let had_open = core.lock(LockReason::Closed);
                let had_locked = core.locked.take().is_some();
                core.lock_reason = Some(LockReason::Closed);
                drop(core);
                if had_open || had_locked {
                    self.emit_state();
                    let daemon = self.clone();
                    tokio::spawn(async move { daemon.clipboard.clear_now().await });
                }
                ok()
            }
            "touch" => {
                self.core().touch();
                self.emit_state();
                ok()
            }
            "search" => self.search(args(line)?),
            "quit" => {
                self.quit.notify_one();
                ok()
            }
            other => Err(ApiError::new("unknown_command", format!("Unknown command {other}"))),
        }
    }

    pub fn is_async(cmd: &str) -> bool {
        matches!(cmd, "unlock" | "quickUnlock" | "act" | "pickFile")
    }

    /// Commands that may take a while; replies can overtake each other.
    pub async fn handle_async(self: &Arc<Self>, cmd: &str, line: Zeroizing<Vec<u8>>) -> Reply {
        /// The raw line can carry the master password or the PIN. It is wiped here, before
        /// anything is awaited: from then on the handler's own arguments are the only copy.
        fn parsed<T: serde::de::DeserializeOwned>(line: Zeroizing<Vec<u8>>) -> Result<T, ApiError> {
            args(&line)
        }
        match cmd {
            "unlock" => self.unlock(parsed(line)?).await,
            "quickUnlock" => self.quick_unlock(parsed(line)?).await,
            "act" => self.act(parsed(line)?).await,
            "pickFile" => self.pick_file(parsed(line)?).await,
            other => Err(ApiError::new("unknown_command", format!("Unknown command {other}"))),
        }
    }

    fn search(&self, a: SearchArgs) -> Reply {
        // Scoring is linear in atoms × entries and runs on the one runtime thread.
        if a.query.len() > MAX_QUERY_BYTES {
            return Err(ApiError::bad_request("The query is too long"));
        }
        let query: String = a.query.split_whitespace().take(MAX_QUERY_ATOMS).collect::<Vec<_>>().join(" ");
        let mut guard = self.core();
        let core = &mut *guard;
        let Some(open) = &core.open else { return Err(ApiError::locked()) };
        let limit = a.limit.unwrap_or(50).clamp(1, 500);
        let empty = Default::default();
        let usage = core.store.usage(&open.path).unwrap_or(&empty);
        let (hits, total) =
            core.searcher.search(&open.index, &query, usage, limit, core.settings.recent_count, unix_now());
        let entries: Vec<Value> = hits
            .into_iter()
            .map(|i| {
                let e = &open.index[i];
                json!({
                    "id": e.uuid,
                    "title": e.title,
                    "username": e.username,
                    "group": e.group,
                    "hasUsername": !e.username.is_empty(),
                    "hasPassword": e.has_password,
                    "hasUrl": !e.url.is_empty(),
                    "hasTotp": e.has_totp,
                    "autotype": e.autotype,
                })
            })
            .collect();
        core.touch();
        drop(guard);
        self.idle_wakeup.notify_one();
        ok_with(json!({"entries": entries, "total": total}))
    }

    /// Marks an unlock as running and returns the epoch its result must be installed under.
    fn begin_busy(&self) -> Result<u64, ApiError> {
        let mut core = self.core();
        if core.sleeping {
            return Err(Self::going_to_sleep_error());
        }
        if core.busy {
            return Err(ApiError::new("busy", "Already unlocking"));
        }
        core.busy = true;
        let epoch = core.epoch;
        drop(core);
        self.emit_state();
        Ok(epoch)
    }

    fn cancelled() -> ApiError {
        ApiError::new("cancelled", "Locked before the unlock finished")
    }

    fn going_to_sleep_error() -> ApiError {
        ApiError::new("cancelled", "The computer is going to sleep")
    }

    /// Installs a freshly opened database. If a lock arrived while it was being opened, the
    /// database is handed back (rejected) instead and the state stays as the lock left it.
    fn install(self: &Arc<Self>, open: OpenDb, stamp: Stamp, epoch: u64) -> Option<OpenDb> {
        let mut core = self.core();
        if core.epoch != epoch {
            core.busy = false;
            return Some(open);
        }
        let path = open.path.clone();
        core.store.remember(&path, open.keyfile.as_deref());
        let live: std::collections::HashSet<String> = open.index.iter().map(|e| e.uuid.clone()).collect();
        core.store.prune_usage(&path, |uuid| live.contains(uuid));
        core.open_stamp = Some(stamp);
        core.watcher = None;
        core.open = Some(open);
        core.locked = None;
        core.lock_reason = None;
        core.busy = false;
        core.touch();
        drop(core);
        self.watch(path, epoch);
        None
    }

    async fn unlock(self: &Arc<Self>, a: UnlockArgs) -> Reply {
        let path = absolute(&a.db, "database")?;
        let keyfile = match a.keyfile.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(k) => Some(absolute(k, "key file")?),
        };
        let pin = a.pin.filter(|p| !p.is_empty());
        if let Some(pin) = &pin {
            quickunlock::validate_pin(pin).map_err(ApiError::bad_request)?;
        }
        if a.password.is_empty() && keyfile.is_none() {
            return Err(VaultError::no_credentials().into());
        }
        let epoch = self.begin_busy()?;
        let _inflight = Inflight::new(self);
        #[cfg(debug_assertions)]
        let _ = tokio::task::spawn_blocking(|| test_hold("OMAKEEPICK_TEST_HOLD")).await;
        // The password alone. The key file is read by the helper, before it is given this, and
        // comes back from it joined with the password. Nothing here waits on a file.
        let key = KeyMaterial::from_password(a.password);
        let result = match self.open_database(&path, keyfile.as_deref(), key, epoch).await {
            // Locked in the instant after the helper finished: stop before the PIN work.
            Ok(_) if !self.still(epoch) => Err(OpenError::Cancelled),
            Ok(Opened { db, key, stamp }) => {
                let (p, k) = (path.clone(), keyfile);
                // The PIN's own Argon2id and the index: fixed-cost work in memory.
                tokio::task::spawn_blocking(move || -> Result<OpenDb, VaultError> {
                    let quick = pin
                        .map(|pin| QuickBlob::seal(&pin, &key, p.as_os_str().as_bytes()))
                        .transpose()
                        .map_err(VaultError::Io)?;
                    Ok(OpenDb::new(p, k, key, quick, db))
                })
                .await
                .unwrap_or_else(|e| Err(VaultError::Io(format!("Unlock task failed: {e}"))))
                .map(|open| (open, stamp))
                .map_err(OpenError::Vault)
            }
            Err(e) => Err(e),
        };
        match result {
            Ok((open, stamp)) => {
                let count = open.index.len();
                let rejected = self.install(open, stamp, epoch);
                self.emit_state();
                if rejected.is_some() {
                    return Err(Self::cancelled());
                }
                eprintln!("omakeepickd: unlocked {} ({count} entries)", path.display());
                ok()
            }
            Err(OpenError::Cancelled) => {
                self.core().busy = false;
                self.emit_state();
                Err(Self::cancelled())
            }
            Err(OpenError::Vault(err)) => {
                self.core().busy = false;
                self.emit_state();
                Err(err.into())
            }
        }
    }

    async fn quick_unlock(self: &Arc<Self>, a: PinArgs) -> Reply {
        let (path, keyfile, mut blob, epoch) = {
            let mut core = self.core();
            if core.sleeping {
                return Err(Self::going_to_sleep_error());
            }
            if core.busy {
                return Err(ApiError::new("busy", "Already unlocking"));
            }
            let Some(locked) = core.locked.as_mut() else {
                return Err(ApiError::new("no_quick_unlock", "Quick unlock is not available"));
            };
            let Some(blob) = locked.quick.take() else {
                return Err(ApiError::new("no_quick_unlock", "Quick unlock is not available"));
            };
            let taken = (locked.path.clone(), locked.keyfile.clone(), blob, core.epoch);
            core.busy = true;
            taken
        };
        let _inflight = Inflight::new(self);
        self.emit_state();
        let p = path.clone();
        // The PIN check is a fixed-cost Argon2id of our own; the database's derivation, whose
        // cost the file dictates, runs in the helper.
        let worker = tokio::task::spawn_blocking(move || {
            test_hold("OMAKEEPICK_TEST_HOLD");
            let key = blob.open(&a.pin, p.as_os_str().as_bytes());
            (blob, key)
        });
        let (blob, key) = match worker.await {
            Ok(v) => v,
            Err(e) => {
                // The blob was lost with the task; fall back to a full unlock.
                self.core().busy = false;
                self.emit_state();
                return Err(ApiError::new("failed", format!("Quick unlock failed: {e}")));
            }
        };
        // The key the PIN released is complete (it holds the key file's contents), so the
        // helper is given no key file to read.
        let opened = match key {
            Some(key) => Some(self.open_database(&path, None, key, epoch).await),
            None => None,
        };
        match opened {
            Some(Ok(Opened { db, key, stamp })) => {
                let open = OpenDb::new(path, keyfile, key, Some(blob), db);
                if let Some(rejected) = self.install(open, stamp, epoch) {
                    // A lock that keeps quick unlock (screen, idle, manual) gets the PIN key
                    // back; sleep and close have wiped it.
                    let OpenDb { quick, .. } = rejected;
                    let mut core = self.core();
                    if let Some(blob) = quick {
                        core.restore_quick(blob, epoch);
                    }
                    drop(core);
                    self.emit_state();
                    return Err(Self::cancelled());
                }
                self.emit_state();
                ok()
            }
            Some(Err(OpenError::Cancelled)) => {
                // Locked before the helper was done, which killed it. Same rule as a rejected
                // install.
                let mut core = self.core();
                core.busy = false;
                core.restore_quick(blob, epoch);
                drop(core);
                self.emit_state();
                Err(Self::cancelled())
            }
            Some(Err(OpenError::Vault(err))) => {
                let mut core = self.core();
                core.busy = false;
                // A file that could not be read or is not whole (unmounted, caught mid-save)
                // keeps the PIN key; a file that no longer opens with the stored key does not.
                // A wrong key is never a format error: the header is checked before the key
                // is used, and what the key decrypts is checked against it.
                if matches!(err, VaultError::Io(_) | VaultError::NotFound(_) | VaultError::Format(_)) {
                    core.restore_quick(blob, epoch);
                }
                drop(core);
                self.emit_state();
                Err(err.into())
            }
            None => {
                let left = blob.attempts_left();
                let mut core = self.core();
                core.busy = false;
                if left == 0 {
                    core.lock_reason = Some(LockReason::Pin);
                } else if !core.restore_quick(blob, epoch) {
                    // Suspended or closed while the PIN was being checked: the key is gone.
                    drop(core);
                    self.emit_state();
                    return Err(ApiError::new("no_quick_unlock", "Quick unlock is no longer available"));
                }
                drop(core);
                self.emit_state();
                if left == 0 {
                    return Err(ApiError::new("bad_pin", "Wrong PIN. Unlock with the master password")
                        .with("attemptsLeft", 0));
                }
                Err(ApiError::new(
                    "bad_pin",
                    format!("Wrong PIN, {left} {} left", if left == 1 { "try" } else { "tries" }),
                )
                .with("attemptsLeft", left))
            }
        }
    }

    /// Resolves an action's secrets. Returns the epoch too: the caller stops if it changes.
    fn prepare(&self, a: &ActArgs) -> Result<(Prepared, u64), ApiError> {
        let mut guard = self.core();
        let core = &mut *guard;
        let Some(open) = &core.open else { return Err(ApiError::locked()) };
        let (Some(indexed), Some(entry)) = (open.indexed(&a.entry), open.entry(&a.entry)) else {
            return Err(ApiError::new("not_found", "The entry no longer exists"));
        };
        let fields = EntryFields(&entry);
        let need = |name: &str, what: &str| -> Result<Zeroizing<String>, ApiError> {
            fields
                .field(name)
                .map_err(|e| ApiError::new("failed", e))?
                .filter(|v| !v.is_empty())
                .ok_or_else(|| ApiError::new("no_field", format!("This entry has no {what}")))
        };
        let prepared = match a.action.as_str() {
            "copyUsername" => Prepared::Copy { value: need("USERNAME", "username")?, what: "username" },
            "copyPassword" => Prepared::Copy { value: need("PASSWORD", "password")?, what: "password" },
            "copyUrl" => Prepared::Copy { value: need("URL", "URL")?, what: "URL" },
            "copyTotp" => {
                if !indexed.has_totp {
                    return Err(ApiError::new("no_field", "This entry has no TOTP"));
                }
                Prepared::Copy { value: need("TOTP", "TOTP")?, what: "TOTP code" }
            }
            "autotype" | "typePassword" => {
                if !indexed.autotype {
                    return Err(ApiError::new("autotype_disabled", "Auto-type is disabled for this entry"));
                }
                let sequence = if a.action == "autotype" {
                    vault::autotype_sequence(&open.db, &entry, &core.settings.autotype_sequence)
                } else {
                    "{PASSWORD}".to_string()
                };
                let tokens = autotype::parse(&sequence, &fields).map_err(|e| ApiError::new("failed", e))?;
                Prepared::Type { tokens }
            }
            other => return Err(ApiError::bad_request(format!("Unknown action {other}"))),
        };
        let path = open.path.clone();
        core.store.record_use(&path, &a.entry, unix_now());
        core.touch();
        Ok((prepared, core.epoch))
    }

    /// Whether no lock happened since `epoch`.
    fn still(&self, epoch: u64) -> bool {
        self.core().epoch == epoch
    }

    async fn act(self: &Arc<Self>, a: ActArgs) -> Reply {
        let (prepared, epoch) = self.prepare(&a)?;
        let _inflight = Inflight::new(self);
        self.emit_state();
        let (settings, ttl) = {
            let core = self.core();
            (core.settings.clone(), core.settings.clipboard_clear_seconds)
        };
        let tool_error = |e: String| match e.strip_prefix("tool_missing:") {
            Some(msg) => ApiError::new("tool_missing", msg),
            None if e == autotype::CANCELLED => Self::cancelled(),
            None => ApiError::new("failed", e),
        };
        match prepared {
            Prepared::Copy { value, what } => {
                let ticket = self.clipboard.copy(value.as_bytes()).await.map_err(tool_error)?;
                if !self.still(epoch) {
                    // Locked while wl-copy ran: the lock's own clear may have missed this value.
                    self.clipboard.clear_if_unchanged(ticket, Duration::ZERO).await;
                    return Err(Self::cancelled());
                }
                if ttl > 0 {
                    let daemon = self.clone();
                    tokio::spawn(async move {
                        daemon.clipboard.clear_if_unchanged(ticket, Duration::from_secs(u64::from(ttl))).await
                    });
                }
                ok_with(json!({"clearsIn": ttl, "copied": what}))
            }
            Prepared::Type { tokens } => {
                tokio::time::sleep(Duration::from_millis(u64::from(settings.autotype_start_delay_ms))).await;
                let delay = u64::from(settings.type_delay_ms);
                // A lock during the delay or mid-sequence stops the typing: the focused window
                // may be the lock screen by now.
                let keep_going = || self.still(epoch);
                let result = if focused_is_xwayland().await {
                    let mut typist = PasteTypist::default();
                    let result = autotype::run(&tokens, &mut typist, delay, keep_going).await;
                    typist.finish().await;
                    result
                } else {
                    autotype::run(&tokens, &mut Wtype, delay, keep_going).await
                };
                result.map_err(tool_error)?;
                ok()
            }
        }
    }

    async fn pick_file(self: &Arc<Self>, a: PickArgs) -> Reply {
        let kind = portal::FileKind::parse(&a.kind)
            .ok_or_else(|| ApiError::bad_request(format!("Unknown file kind {}", a.kind)))?;
        let folder = {
            let core = self.core();
            let current = core
                .open
                .as_ref()
                .map(|o| (o.path.clone(), o.keyfile.clone()))
                .or_else(|| core.locked.as_ref().map(|l| (l.path.clone(), l.keyfile.clone())))
                .unwrap_or_else(|| {
                    let last = core.store.data.last_db.clone().unwrap_or_default();
                    let keyfile = core.store.keyfile_for(&last);
                    (last, keyfile)
                });
            match kind {
                portal::FileKind::Database => current.0.parent().map(Path::to_path_buf),
                portal::FileKind::KeyFile => current
                    .1
                    .as_deref()
                    .or(Some(current.0.as_path()))
                    .and_then(Path::parent)
                    .map(Path::to_path_buf),
            }
        };
        let path = portal::choose_file(kind, folder.as_deref())
            .await
            .map_err(|e| ApiError::new("failed", e))?
            .ok_or_else(|| ApiError::new("cancelled", "No file chosen"))?;
        let keyfile =
            (kind == portal::FileKind::Database).then(|| self.core().store.keyfile_for(&path)).flatten();
        ok_with(json!({"path": path, "keyfile": keyfile}))
    }

    /// Re-reads the database after it changed on disk (e.g. a Syncthing update).
    pub async fn reload(self: &Arc<Self>) {
        let (path, previous, epoch) = {
            let core = self.core();
            let Some(open) = &core.open else { return };
            (open.path.clone(), core.open_stamp, core.epoch)
        };
        let _inflight = Inflight::new(self);
        let mut last_error = None;
        let mut seen = None;
        // Writers that truncate-and-write can be caught mid-save; retry once.
        for attempt in 0..2 {
            if attempt > 0 {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_millis(1500)) => {}
                    () = self.locked_since(epoch) => return,
                }
            }
            let (opener, stamp) = match self.read_files(&path, None, epoch).await {
                Ok(read) => read,
                // Locked meanwhile: the helper was killed, and this copy would be stale anyway.
                Err(OpenError::Cancelled) => return,
                // Gone for now (mid-rename, unmounted): the next file event tries again.
                Err(OpenError::Vault(VaultError::NotFound(_))) => return,
                Err(OpenError::Vault(e)) => {
                    last_error = Some(e);
                    continue;
                }
            };
            if Some(stamp) == previous {
                // A spurious event: the file is the one that is open.
                self.discard(opener);
                return;
            }
            seen = Some(stamp);
            // The key is taken only now that the file is read, so this task never waits on a
            // file with it in hand.
            let key = {
                let core = self.core();
                match &core.open {
                    Some(open) if core.epoch == epoch && open.path == path => Some(open.key.clone()),
                    _ => None,
                }
            };
            let Some(key) = key else {
                self.discard(opener);
                return;
            };
            match self.decrypt(opener, stamp, key, epoch).await {
                Err(OpenError::Cancelled) => return,
                Ok(opened) => {
                    let mut core = self.core();
                    // Locked meanwhile: this copy is stale even if the same file was unlocked again.
                    if core.epoch != epoch {
                        return;
                    }
                    let Some(open) = core.open.as_mut().filter(|o| o.path == path) else { return };
                    open.replace_database(opened.db);
                    let count = open.index.len();
                    core.open_stamp = Some(opened.stamp);
                    drop(core);
                    eprintln!("omakeepickd: reloaded {} ({count} entries)", path.display());
                    self.emit_state();
                    return;
                }
                Err(OpenError::Vault(e)) => last_error = Some(e),
            }
        }
        if let Some(e) = last_error {
            eprintln!("omakeepickd: reload failed: {e}");
            if !self.still(epoch) {
                return;
            }
            // Do not try this version of the file again on every event.
            if let Some(stamp) = seen {
                self.core().open_stamp = Some(stamp);
            }
            // The parser's message can quote text from a malformed file; keep it to the log.
            self.notice("warning", "The database changed on disk but could not be reloaded");
        }
    }
}

async fn focused_is_xwayland() -> bool {
    let Ok(out) = tokio::process::Command::new("hyprctl")
        .args(["activewindow", "-j"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await
    else {
        return false;
    };
    serde_json::from_slice::<Value>(&out.stdout)
        .ok()
        .and_then(|v| v.get("xwayland").and_then(Value::as_bool))
        .unwrap_or(false)
}
