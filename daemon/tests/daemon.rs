//! End-to-end tests: run `omakeepickd serve` in an isolated runtime/state directory and talk to
//! it over its socket, through `attach`, and with `ctl`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use keepass::{Database, DatabaseKey};
use serde_json::{Value, json};
use zbus::{ObjectPath, OwnedVariant, Variant};

mod kdbx4;

const BIN: &str = env!("CARGO_BIN_EXE_omakeepickd");
const PASSWORD: &str = "test-password";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        Env { dir: tempfile::tempdir().unwrap() }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .env("OMAKEEPICK_RUNTIME_DIR", self.dir.path().join("run"))
            .env("OMAKEEPICK_STATE_DIR", self.dir.path().join("state"))
            .env("OMAKEEPICK_NO_LOGIND", "1");
        cmd
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("run/sock")
    }

    fn serve(&self) -> Daemon {
        self.serve_with(self.command(&["serve"]))
    }

    fn serve_with(&self, mut serve: Command) -> Daemon {
        let child = serve.stdin(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(self.socket()).is_err() {
            assert!(Instant::now() < deadline, "daemon did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        Daemon { child }
    }

    fn connect(&self) -> Conn {
        let stream = UnixStream::connect(self.socket()).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        Conn {
            reader: BufReader::new(stream.try_clone().unwrap()),
            writer: stream,
            next_id: 1,
            events: vec![],
        }
    }

    fn db_copy(&self) -> PathBuf {
        let path = self.dir.path().join("Secrets.kdbx");
        std::fs::copy(fixture("password.kdbx"), &path).unwrap();
        path
    }
}

/// The stand-ins for `wtype`, `wl-copy`, `wl-paste` and `hyprctl` in `tests/fixtures/bin`, as a
/// daemon started with [`Env::fake_tools`] runs them: this is the directory they record in.
struct Fake(PathBuf);

impl Fake {
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.0.join(name)).unwrap_or_default()
    }

    /// What is on the selection `which`: something only while the `wl-copy` that offered it
    /// is alive.
    fn selection(&self, which: &str) -> Option<String> {
        let pid: u32 = self.read(&format!("{which}.pid")).trim().parse().ok()?;
        is_alive(pid).then(|| self.read(which))
    }
}

impl Env {
    /// Makes the daemon that `serve` starts find the stand-ins before the real tools.
    fn fake_tools(&self, serve: &mut Command) -> Fake {
        let dir = self.dir.path().join("fake");
        std::fs::create_dir_all(&dir).unwrap();
        let path = format!("{}:{}", fixture("bin").display(), std::env::var("PATH").unwrap_or_default());
        serve.env("PATH", path).env("FAKE_DIR", &dir);
        Fake(dir)
    }
}

/// The ID of the first entry that `query` finds.
fn entry_id(conn: &mut Conn, query: &str) -> String {
    conn.request("search", json!({"query": query}))["entries"][0]["id"].as_str().unwrap().to_string()
}

fn configure(conn: &mut Conn, settings: Value) {
    assert_eq!(conn.request("configure", json!({"settings": settings}))["ok"], true);
}

struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Conn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: i64,
    events: Vec<Value>,
}

impl Conn {
    fn read(&mut self) -> Value {
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "connection closed");
        serde_json::from_str(&line).unwrap()
    }

    fn request(&mut self, cmd: &str, args: Value) -> Value {
        let id = self.send(cmd, args);
        self.reply(id)
    }

    /// Sends a request without waiting; `reply` collects its answer later.
    fn send(&mut self, cmd: &str, args: Value) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let mut req = args.as_object().cloned().unwrap_or_default();
        req.insert("id".into(), json!(id));
        req.insert("cmd".into(), json!(cmd));
        writeln!(self.writer, "{}", Value::Object(req)).unwrap();
        id
    }

    fn reply(&mut self, id: i64) -> Value {
        if let Some(i) = self.events.iter().position(|m| m.get("id") == Some(&json!(id))) {
            return self.events.remove(i);
        }
        loop {
            let msg = self.read();
            if msg.get("id") == Some(&json!(id)) {
                return msg;
            }
            self.events.push(msg);
        }
    }

    fn state(&mut self) -> Value {
        self.request("status", json!({}))["state"].clone()
    }

    fn wait_event(&mut self, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
        if let Some(i) = self.events.iter().position(&pred) {
            return self.events.remove(i);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            let msg = self.read();
            if pred(&msg) {
                return msg;
            }
        }
    }
}

fn unlock(conn: &mut Conn, db: &Path, pin: Option<&str>) -> Value {
    conn.request("unlock", json!({"db": db, "keyfile": null, "password": PASSWORD, "pin": pin}))
}

#[test]
fn lifecycle_search_and_quick_unlock() {
    let env = Env::new();
    let _daemon = env.serve();
    let mut conn = env.connect();
    let db = env.db_copy();

    let hello = conn.read();
    assert_eq!(hello["event"], "state");
    assert_eq!(hello["phase"], "closed");
    assert_eq!(conn.request("search", json!({"query": "git"}))["error"], "locked");

    let bad = conn.request("unlock", json!({"db": db, "password": "wrong"}));
    assert_eq!((bad["ok"].clone(), bad["error"].clone()), (json!(false), json!("bad_credentials")));
    assert_eq!(unlock(&mut conn, &db, Some("12"))["error"], "bad_request");
    assert_eq!(
        conn.request("unlock", json!({"db": "relative.kdbx", "password": "x"}))["error"],
        "bad_request"
    );

    assert_eq!(unlock(&mut conn, &db, Some("2468"))["ok"], true);
    let state = conn.state();
    assert_eq!(state["phase"], "unlocked");
    assert_eq!(state["entryCount"], 7);
    assert_eq!(state["dbName"], "Secrets");
    assert!(state["lockAt"].as_i64().unwrap() > 0);

    let found = conn.request("search", json!({"query": "git"}));
    let entries = found["entries"].as_array().unwrap();
    assert_eq!(entries[0]["title"], "GitHub");
    assert_eq!(entries[0]["group"], "Personal/Dev");
    assert_eq!(entries[0]["hasTotp"], true);
    let keys: Vec<&String> = entries[0].as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["autotype", "group", "hasPassword", "hasTotp", "hasUrl", "hasUsername", "id", "title", "username"]
    );
    assert!(!found.to_string().contains("gh-Pa55!"), "search results must not contain secrets");
    assert_eq!(conn.request("search", json!({"query": ""}))["entries"], json!([]));

    let id_of = |conn: &mut Conn, q: &str| {
        conn.request("search", json!({"query": q}))["entries"][0]["id"].as_str().unwrap().to_string()
    };
    let router = id_of(&mut conn, "router");
    assert_eq!(
        conn.request("act", json!({"entry": router, "action": "autotype"}))["error"],
        "autotype_disabled"
    );
    let gitea = id_of(&mut conn, "gitea");
    assert_eq!(conn.request("act", json!({"entry": gitea, "action": "copyTotp"}))["error"], "no_field");
    assert_eq!(conn.request("act", json!({"entry": "nope", "action": "copyPassword"}))["error"], "not_found");
    assert_eq!(conn.request("act", json!({"entry": gitea, "action": "explode"}))["error"], "bad_request");

    // Quick unlock: wrong PIN costs a try, the right one resets them.
    assert_eq!(conn.request("lock", json!({}))["ok"], true);
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["quickUnlock"].clone()), (json!("locked"), json!(true)));
    assert_eq!(state["pinAttemptsLeft"], 3);
    let wrong = conn.request("quickUnlock", json!({"pin": "0000"}));
    assert_eq!((wrong["error"].clone(), wrong["attemptsLeft"].clone()), (json!("bad_pin"), json!(2)));
    assert_eq!(conn.request("quickUnlock", json!({"pin": "2468"}))["ok"], true);
    assert_eq!(conn.state()["phase"], "unlocked");

    // Screen lock keeps the PIN; three wrong PINs drop it.
    conn.request("lock", json!({"reason": "screen"}));
    assert_eq!(conn.state()["lockReason"], "screen");
    for left in [2, 1, 0] {
        assert_eq!(conn.request("quickUnlock", json!({"pin": "1111"}))["attemptsLeft"], left);
    }
    let state = conn.state();
    assert_eq!((state["quickUnlock"].clone(), state["lockReason"].clone()), (json!(false), json!("pin")));
    assert_eq!(conn.request("quickUnlock", json!({"pin": "2468"}))["error"], "no_quick_unlock");

    // Suspend wipes the PIN too.
    assert_eq!(unlock(&mut conn, &db, Some("2468"))["ok"], true);
    conn.request("lock", json!({"reason": "sleep"}));
    assert_eq!(conn.state()["quickUnlock"], false);

    // Closing forgets the database but remembers it for the unlock form.
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    conn.request("close", json!({}));
    let state = conn.state();
    assert_eq!(state["phase"], "closed");
    assert_eq!(state["db"], json!(db));
    assert_eq!(state["keyfile"], Value::Null);

    // Usage is remembered: the empty query now lists recent entries.
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    let recent = conn.request("search", json!({"query": ""}));
    let titles: Vec<&str> =
        recent["entries"].as_array().unwrap().iter().map(|e| e["title"].as_str().unwrap()).collect();
    assert!(titles.is_empty(), "failed actions must not count as use: {titles:?}");

    assert_eq!(conn.request("configure", json!({"settings": {"idleLockMinutes": 5}}))["ok"], true);
    assert_eq!(conn.state()["idleLockMinutes"], 5);
    assert_eq!(
        conn.request("configure", json!({"settings": {"idleLockMinutes": "x"}}))["error"],
        "bad_request"
    );
    assert_eq!(conn.request("frobnicate", json!({}))["error"], "unknown_command");
}

/// A lock, close or suspend that arrives while an unlock is still running must win: the
/// unlock's result is dropped instead of reopening the database afterwards.
#[test]
fn a_lock_during_an_unlock_wins() {
    // The hold hook exists in debug builds only; the binary under test has the same profile
    // as this test, so in a release run (release.yml) nothing would ever read the FIFO.
    if !cfg!(debug_assertions) {
        eprintln!("skipped: needs a debug build of omakeepickd");
        return;
    }
    let env = Env::new();
    // With OMAKEEPICK_TEST_HOLD (debug builds), every unlock first blocks reading this FIFO
    // until the test feeds it, so a lock can be sent while the unlock is in flight.
    let fifo = env.dir.path().join("hold");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let mut serve = env.command(&["serve"]);
    serve.env("OMAKEEPICK_TEST_HOLD", &fifo);
    let _daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let db = env.db_copy();
    let feed = || std::fs::write(&fifo, b"go").unwrap();
    // For unlocks that are meant to succeed: feed from a thread while the request runs.
    let unlock_fed = |conn: &mut Conn, pin: Option<&str>| {
        let fifo = fifo.clone();
        let feeder = std::thread::spawn(move || std::fs::write(&fifo, b"go").unwrap());
        let reply = unlock(conn, &db, pin);
        feeder.join().unwrap();
        reply
    };
    // Sends an unlock and returns once the daemon reports it as running. Older state events
    // are dropped first, so a `busy` left over from an earlier step cannot satisfy the wait.
    let start = |conn: &mut Conn, cmd: &str, args: Value| {
        conn.events.clear();
        let id = conn.send(cmd, args);
        conn.wait_event("busy", |m| m["event"] == "state" && m["busy"] == true);
        id
    };

    // Full unlock, cancelled by a screen lock.
    let id = start(&mut conn, "unlock", json!({"db": db, "password": PASSWORD, "pin": "2468"}));
    assert_eq!(conn.request("lock", json!({"reason": "screen"}))["ok"], true);
    feed();
    assert_eq!(conn.reply(id)["error"], "cancelled");
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["busy"].clone()), (json!("closed"), json!(false)));
    assert_eq!(state["quickUnlock"], false);
    assert_eq!(conn.request("search", json!({"query": "git"}))["error"], "locked");

    // A quick unlock, right PIN or wrong, cancelled by a screen lock keeps the PIN key;
    // cancelled by suspend, it loses it.
    // A wrong PIN still costs a try, and a right one still resets them.
    for (reason, pin, expect, keeps_pin, attempts) in [
        ("screen", "0000", "bad_pin", true, 2),
        ("screen", "2468", "cancelled", true, 3),
        ("sleep", "0000", "no_quick_unlock", false, 0),
        ("sleep", "2468", "cancelled", false, 0),
    ] {
        let what = format!("{reason} with PIN {pin}");
        if conn.state()["quickUnlock"] != true {
            assert_eq!(unlock_fed(&mut conn, Some("2468"))["ok"], true, "{what}");
            assert_eq!(conn.request("lock", json!({}))["ok"], true, "{what}");
        }
        let id = start(&mut conn, "quickUnlock", json!({"pin": pin}));
        assert_eq!(conn.request("lock", json!({"reason": reason}))["ok"], true, "{what}");
        feed();
        assert_eq!(conn.reply(id)["error"], expect, "{what}");
        let state = conn.state();
        assert_eq!(state["phase"], "locked", "{what}");
        assert_eq!(state["busy"], false, "{what}");
        assert_eq!(state["quickUnlock"], keeps_pin, "{what}");
        assert_eq!(state["pinAttemptsLeft"], attempts, "{what}");
        assert_eq!(state["lockReason"], reason, "{what}");
        if !keeps_pin {
            assert_eq!(
                conn.request("quickUnlock", json!({"pin": "2468"}))["error"],
                "no_quick_unlock",
                "{what}"
            );
        }
    }

    // Close during a full unlock: nothing is left to reopen.
    let id = start(&mut conn, "unlock", json!({"db": db, "password": PASSWORD, "pin": "2468"}));
    assert_eq!(conn.request("close", json!({}))["ok"], true);
    feed();
    assert_eq!(conn.reply(id)["error"], "cancelled");
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["quickUnlock"].clone()), (json!("closed"), json!(false)));

    // Without an interruption the same path unlocks.
    assert_eq!(unlock_fed(&mut conn, None)["ok"], true);
    assert_eq!(conn.state()["entryCount"], 7);
}

/// The `open-db` helper that `daemon` is running, found through /proc. One that has ended and
/// only waits to be reaped does not count.
fn helper_of(daemon: &Daemon) -> Option<u32> {
    let parent = daemon.child.id();
    std::fs::read_dir("/proc").unwrap().flatten().find_map(|entry| {
        let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
        let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
        // "pid (comm) state ppid ..."; comm may contain spaces, so split after its ')'.
        let mut after_comm = stat[stat.rfind(')')? + 2..].split(' ');
        let state = after_comm.next()?;
        let ppid: u32 = after_comm.next()?.parse().ok()?;
        (ppid == parent && state != "Z").then_some(pid)
    })
}

/// Waits until something has reached the hold hook on `fifo` (it is blocked opening it for
/// reading), and keeps it there: the returned writer never writes. Dropping it lets go of the
/// hold.
fn held_at(fifo: &Path) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt;
    let mut writer = None;
    wait_until("the hold is reached", || {
        // Without a reader, a non-blocking open for writing fails (ENXIO).
        writer = std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(fifo).ok();
        writer.is_some()
    });
    writer.unwrap()
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn is_alive(pid: u32) -> bool {
    // A zombie is dead for our purposes: its memory is gone, only the exit status waits.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| stat[stat.rfind(')')? + 2..].chars().next())
        .is_some_and(|state| state != 'Z')
}

/// A key derivation runs in a helper process. A lock, `quit` or the daemon's death kills it at
/// once; nobody waits for it to finish.
#[test]
fn a_lock_kills_a_running_derivation() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: needs a debug build of omakeepickd");
        return;
    }
    let env = Env::new();
    // With OMAKEEPICK_TEST_HOLD_KDF (debug builds), the helper blocks on this FIFO where its
    // derivation would run. Nothing ever writes to it, and the test keeps it from seeing an
    // end of file: a killed helper is the only way out.
    let fifo = env.dir.path().join("hold-kdf");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let serve = |env: &Env| {
        let mut serve = env.command(&["serve"]);
        serve.env("OMAKEEPICK_TEST_HOLD_KDF", &fifo);
        env.serve_with(serve)
    };
    let db = env.db_copy();
    let start_unlock = |conn: &mut Conn, daemon: &Daemon| {
        conn.events.clear();
        let id = conn.send("unlock", json!({"db": db, "password": PASSWORD, "pin": "2468"}));
        conn.wait_event("busy", |m| m["event"] == "state" && m["busy"] == true);
        // The hold is where the derivation would run: the helper has read the files and has
        // been given the credentials.
        let hold = held_at(&fifo);
        let helper = helper_of(daemon).expect("a helper at the hold");
        // The credentials went to the helper on stdin: not on its command line, which every
        // process can read, and not in its environment. The helper is non-dumpable like the
        // daemon, so its environment is not readable at all (except by root).
        let cmdline = std::fs::read(format!("/proc/{helper}/cmdline")).unwrap();
        assert_eq!(cmdline, b"omakeepickd\0open-db\0");
        match std::fs::read(format!("/proc/{helper}/environ")) {
            Ok(environ) => assert!(!environ.windows(PASSWORD.len()).any(|w| w == PASSWORD.as_bytes())),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}"),
        }
        (id, helper, hold)
    };

    // A screen lock: the request fails at once and the helper is gone.
    let daemon = serve(&env);
    let mut conn = env.connect();
    let (id, helper, _hold) = start_unlock(&mut conn, &daemon);
    assert_eq!(conn.request("lock", json!({"reason": "screen"}))["ok"], true);
    let started = Instant::now();
    assert_eq!(conn.reply(id)["error"], "cancelled");
    assert!(started.elapsed() < Duration::from_secs(5), "the cancel waited for the derivation");
    wait_until("the helper is dead", || !is_alive(helper));
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["busy"].clone()), (json!("closed"), json!(false)));

    // `quit` (and so suspend, which locks the same way) does not wait for it either.
    let (_, helper, _hold) = start_unlock(&mut conn, &daemon);
    assert_eq!(conn.request("quit", json!({}))["ok"], true);
    let mut daemon = daemon;
    wait_until("the daemon has exited", || daemon.child.try_wait().unwrap().is_some());
    assert!(!is_alive(helper));
    drop(daemon);

    // The daemon dying takes the helper with it (PR_SET_PDEATHSIG).
    let daemon = serve(&env);
    let mut conn = env.connect();
    let (_, helper, _hold) = start_unlock(&mut conn, &daemon);
    unsafe { libc::kill(daemon.child.id() as i32, libc::SIGKILL) };
    wait_until("the helper is dead", || !is_alive(helper));
}

/// Reading the database or the key file can hang for as long as the file system likes (a
/// network mount that stopped answering). The helper does the reading, before the daemon gives
/// it any credential, so a lock does not wait for the read.
///
/// The hold here stands in for the hang. Unlike a read on a dead FUSE mount it ends when the
/// helper is killed, so this cannot show that the daemon does not wait for the helper to die:
/// `tests/manual/hung-mount.py` does, on a mount that really stops answering.
#[test]
fn a_lock_does_not_wait_for_a_file_that_hangs() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: needs a debug build of omakeepickd");
        return;
    }
    let env = Env::new();
    // With OMAKEEPICK_TEST_HOLD_READ (debug builds), the helper blocks on this FIFO where it
    // would read the files. Nothing ever writes to it: the read never returns.
    let fifo = env.dir.path().join("hold-read");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let mut serve = env.command(&["serve"]);
    serve.env("OMAKEEPICK_TEST_HOLD_READ", &fifo);
    let mut daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let db = env.dir.path().join("Secrets.kdbx");
    std::fs::copy(fixture("password-keyfile.kdbx"), &db).unwrap();
    let keyfile = fixture("password-keyfile.keyx");
    let start_unlock = |conn: &mut Conn, daemon: &Daemon| {
        conn.events.clear();
        let unlock = json!({"db": db, "keyfile": keyfile, "password": PASSWORD, "pin": "2468"});
        let id = conn.send("unlock", unlock);
        conn.wait_event("busy", |m| m["event"] == "state" && m["busy"] == true);
        let hold = held_at(&fifo);
        (id, helper_of(daemon).expect("a helper at the hold"), hold)
    };

    // Suspend: the unlock ends at once, the helper is killed, and the daemon is ready again.
    let (id, helper, _hold) = start_unlock(&mut conn, &daemon);
    let started = Instant::now();
    assert_eq!(conn.request("lock", json!({"reason": "sleep"}))["ok"], true);
    assert_eq!(conn.reply(id)["error"], "cancelled");
    assert!(started.elapsed() < Duration::from_secs(5), "the lock waited for the read");
    wait_until("the helper is dead", || !is_alive(helper));
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["busy"].clone()), (json!("closed"), json!(false)));

    // `quit` (which settles the same way suspend does) is not held up by it either.
    let (_, helper, _hold) = start_unlock(&mut conn, &daemon);
    assert_eq!(conn.request("quit", json!({}))["ok"], true);
    wait_until("the daemon has exited", || daemon.child.try_wait().unwrap().is_some());
    assert!(!is_alive(helper));
}

/// The daemon opens neither the database nor the key file: the helper does, in its first step.
/// Here that step is held up, and the two files only come into being while it waits. A daemon
/// that looked at either one itself would have failed the unlock by then.
#[test]
fn the_daemon_leaves_both_files_to_the_helper() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: needs a debug build of omakeepickd");
        return;
    }
    let env = Env::new();
    let fifo = env.dir.path().join("hold-read");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let mut serve = env.command(&["serve"]);
    serve.env("OMAKEEPICK_TEST_HOLD_READ", &fifo);
    let _daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let db = env.dir.path().join("Secrets.kdbx");
    let keyfile = env.dir.path().join("Secrets.keyx");

    let id = conn.send("unlock", json!({"db": db, "keyfile": keyfile, "password": PASSWORD}));
    conn.wait_event("busy", |m| m["event"] == "state" && m["busy"] == true);
    let hold = held_at(&fifo);
    assert!(!db.exists() && !keyfile.exists());
    std::fs::copy(fixture("password-keyfile.kdbx"), &db).unwrap();
    std::fs::copy(fixture("password-keyfile.keyx"), &keyfile).unwrap();
    drop(hold);
    assert_eq!(conn.reply(id)["ok"], true);
    assert_eq!(conn.state()["entryCount"], 7);
}

/// A lock still wins when it arrives after the helper is done: while the daemon takes the
/// handed-over database apart, and before it is installed.
#[test]
fn a_lock_wins_after_the_helper_is_done() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: needs a debug build of omakeepickd");
        return;
    }
    let env = Env::new();
    // With OMAKEEPICK_TEST_HOLD_HANDOVER (debug builds), the daemon blocks on this FIFO once
    // the helper has handed the database over.
    let fifo = env.dir.path().join("hold-handover");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let mut serve = env.command(&["serve"]);
    serve.env("OMAKEEPICK_TEST_HOLD_HANDOVER", &fifo);
    let _daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let db = env.db_copy();
    // Sends an unlock, lets it run up to the hold, sends `then` and lets go of the hold.
    let interrupted = |conn: &mut Conn, cmd: &str, args: Value, then: Option<(&str, Value)>| {
        let id = conn.send(cmd, args);
        let hold = held_at(&fifo);
        if let Some((cmd, args)) = then {
            assert_eq!(conn.request(cmd, args)["ok"], true);
        }
        drop(hold);
        conn.reply(id)
    };
    let unlock = json!({"db": db, "password": PASSWORD, "pin": "2468"});
    let pin = json!({"pin": "2468"});

    // A full unlock: nothing is installed, and no PIN key is made.
    let lock = Some(("lock", json!({"reason": "screen"})));
    assert_eq!(interrupted(&mut conn, "unlock", unlock.clone(), lock.clone())["error"], "cancelled");
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["busy"].clone()), (json!("closed"), json!(false)));
    assert_eq!(state["quickUnlock"], false);
    assert_eq!(conn.request("search", json!({"query": "git"}))["error"], "locked");
    assert_eq!(
        interrupted(&mut conn, "unlock", unlock.clone(), Some(("close", json!({}))))["error"],
        "cancelled"
    );
    assert_eq!(conn.state()["phase"], "closed");

    // A quick unlock interrupted by a screen lock gets the PIN key back; by suspend, it does not.
    assert_eq!(interrupted(&mut conn, "unlock", unlock.clone(), None)["ok"], true);
    assert_eq!(conn.request("lock", json!({}))["ok"], true);
    assert_eq!(interrupted(&mut conn, "quickUnlock", pin.clone(), lock)["error"], "cancelled");
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["busy"].clone()), (json!("locked"), json!(false)));
    assert_eq!((state["quickUnlock"].clone(), state["pinAttemptsLeft"].clone()), (json!(true), json!(3)));
    let sleep = Some(("lock", json!({"reason": "sleep"})));
    assert_eq!(interrupted(&mut conn, "quickUnlock", pin.clone(), sleep)["error"], "cancelled");
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["quickUnlock"].clone()), (json!("locked"), json!(false)));
    assert_eq!(conn.request("quickUnlock", pin)["error"], "no_quick_unlock");

    // Left alone, the same path unlocks.
    assert_eq!(interrupted(&mut conn, "unlock", unlock, None)["ok"], true);
    assert_eq!(conn.state()["entryCount"], 7);
}

/// The helper hands the key file's contents back with the database, so quick unlock and
/// reloads work from memory afterwards: the key file is not needed again.
#[test]
fn quick_unlock_and_reloads_do_not_need_the_key_file_again() {
    let env = Env::new();
    let _daemon = env.serve();
    let mut conn = env.connect();
    let db = env.dir.path().join("Secrets.kdbx");
    std::fs::copy(fixture("password-keyfile.kdbx"), &db).unwrap();
    let keyfile = env.dir.path().join("Secrets.keyx");
    std::fs::copy(fixture("password-keyfile.keyx"), &keyfile).unwrap();
    let unlock = |conn: &mut Conn, keyfile: Option<&Path>, password: &str| {
        conn.request("unlock", json!({"db": db, "keyfile": keyfile, "password": password, "pin": "2468"}))
    };

    assert_eq!(unlock(&mut conn, None, PASSWORD)["error"], "bad_credentials");
    assert_eq!(unlock(&mut conn, Some(&env.dir.path().join("nope.keyx")), PASSWORD)["error"], "not_found");
    assert_eq!(unlock(&mut conn, Some(env.dir.path()), PASSWORD)["error"], "keyfile_error");
    assert_eq!(unlock(&mut conn, Some(&keyfile), "wrong")["error"], "bad_credentials");
    assert_eq!(unlock(&mut conn, None, "")["error"], "bad_request");
    assert_eq!(conn.state()["busy"], false);
    assert_eq!(unlock(&mut conn, Some(&keyfile), PASSWORD)["ok"], true);
    let state = conn.state();
    assert_eq!((state["entryCount"].clone(), state["keyfile"].clone()), (json!(7), json!(keyfile)));

    // The key file goes away, like a USB stick pulled out after unlocking.
    let key = || {
        DatabaseKey::new()
            .with_password(PASSWORD)
            .with_keyfile(&mut std::fs::File::open(fixture("password-keyfile.keyx")).unwrap())
            .unwrap()
    };
    std::fs::remove_file(&keyfile).unwrap();
    assert_eq!(conn.request("lock", json!({}))["ok"], true);
    assert_eq!(conn.request("quickUnlock", json!({"pin": "2468"}))["ok"], true);
    assert_eq!(conn.state()["entryCount"], 7);

    // A changed database is reloaded with the key that is in memory.
    let mut changed = Database::open(&mut std::fs::File::open(&db).unwrap(), key()).unwrap();
    changed.config.version = keepass::config::DatabaseVersion::KDB4(1);
    changed.root_mut().add_entry().set_unprotected("Title", "Brand new");
    let tmp = db.with_extension("tmp");
    changed.save(&mut std::fs::File::create(&tmp).unwrap(), key()).unwrap();
    std::fs::rename(&tmp, &db).unwrap();
    conn.wait_event("reload", |m| m["event"] == "state" && m["entryCount"] == 8);

    // A database caught half-written, here cut off inside its header, is no reason to forget
    // the PIN key either. (Cut off further in, a KDBX 3.1 file cannot be told from one that
    // was given the wrong key, and that still costs the PIN key.)
    assert_eq!(conn.request("lock", json!({}))["ok"], true);
    let whole = std::fs::read(&db).unwrap();
    std::fs::write(&db, &whole[..40]).unwrap();
    assert_eq!(conn.request("quickUnlock", json!({"pin": "2468"}))["error"], "format_error");
    assert_eq!(conn.state()["quickUnlock"], true);
    std::fs::write(&db, &whole).unwrap();
    assert_eq!(conn.request("quickUnlock", json!({"pin": "2468"}))["ok"], true);
    assert_eq!(conn.state()["entryCount"], 8);
}

#[test]
fn reloads_when_the_file_changes() {
    let env = Env::new();
    let _daemon = env.serve();
    let mut conn = env.connect();
    let db = env.db_copy();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    assert_eq!(conn.state()["entryCount"], 7);

    // Write a changed copy next to it and rename it over, like KeePassXC and Syncthing do.
    let mut changed =
        Database::open(&mut std::fs::File::open(&db).unwrap(), DatabaseKey::new().with_password(PASSWORD))
            .unwrap();
    changed.config.version = keepass::config::DatabaseVersion::KDB4(1);
    changed.root_mut().add_entry().set_unprotected("Title", "Brand new");
    let tmp = db.with_extension("tmp");
    changed
        .save(&mut std::fs::File::create(&tmp).unwrap(), DatabaseKey::new().with_password(PASSWORD))
        .unwrap();
    std::fs::rename(&tmp, &db).unwrap();

    conn.wait_event("reload", |m| m["event"] == "state" && m["entryCount"] == 8);
    let found = conn.request("search", json!({"query": "brand new"}));
    assert_eq!(found["entries"][0]["title"], "Brand new");
}

/// A database that unpacks to gigabytes (see `tests/vault.rs`) costs an unlock and nothing
/// more. Unlocking it fails with what is wrong with it. Saved over the database that is open,
/// as a sync peer could do it, it is not loaded, and the one that was open stays open.
#[test]
fn a_database_that_unpacks_to_gigabytes_is_not_opened() {
    use std::os::unix::process::CommandExt;
    let env = Env::new();
    // The daemon and with it its helpers under a limit from outside, a little above the one
    // a helper sets itself. Should that one ever be missing, this test fails there and does
    // not fill the memory of the machine it runs on.
    let mut serve = env.command(&["serve"]);
    let outside: libc::rlim_t = 2 << 30;
    unsafe {
        serve.pre_exec(move || {
            let limit = libc::rlimit { rlim_cur: outside, rlim_max: outside };
            match libc::setrlimit(libc::RLIMIT_DATA, &limit) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        });
    }
    let _daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let unpacks_to_gigabytes = kdbx4::with_attachment(PASSWORD, 2 << 30, 8 << 20);

    let large = env.dir.path().join("Large.kdbx");
    std::fs::write(&large, &unpacks_to_gigabytes).unwrap();
    let refused = unlock(&mut conn, &large, None);
    assert_eq!((refused["ok"].clone(), refused["error"].clone()), (json!(false), json!("format_error")));
    assert_eq!(
        refused["message"],
        "Not a readable KeePass database: it takes more memory to open than the 1.5 GiB this app gives it"
    );
    assert_eq!(conn.request("search", json!({"query": "git"}))["error"], "locked");

    let db = env.db_copy();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    let tmp = db.with_extension("tmp");
    std::fs::write(&tmp, &unpacks_to_gigabytes).unwrap();
    std::fs::rename(&tmp, &db).unwrap();
    conn.wait_event("the refusal", |m| m["event"] == "notice" && m["level"] == "warning");
    assert_eq!(conn.state()["entryCount"], 7);
    let found = conn.request("search", json!({"query": "git"}));
    assert_eq!((found["total"].clone(), found["entries"][0]["title"].clone()), (json!(3), json!("GitHub")));
}

/// Saves `db` under `PASSWORD` with a key derivation that costs nothing.
fn save(mut db: Database, path: &Path) {
    db.config.version = keepass::config::DatabaseVersion::KDB4(1);
    db.config.kdf_config = keepass::config::KdfConfig::Aes { rounds: 1 };
    db.save(&mut std::fs::File::create(path).unwrap(), DatabaseKey::new().with_password(PASSWORD)).unwrap();
}

/// Asks a daemon for its status over and over on a connection of its own, to see whether
/// something else the daemon is doing keeps it from answering.
struct Asking {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<(Duration, u32)>,
}

impl Asking {
    fn start(env: &Env) -> Asking {
        let mut conn = env.connect();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            let (mut longest, mut answers) = (Duration::ZERO, 0);
            while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                let asked = Instant::now();
                conn.state();
                longest = longest.max(asked.elapsed());
                answers += 1;
                std::thread::sleep(Duration::from_millis(1));
            }
            (longest, answers)
        });
        Asking { stop, thread }
    }

    /// The longest it waited for an answer, and how many answers it got.
    fn stop(self) -> (Duration, u32) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.thread.join().unwrap()
    }
}

/// How long the daemon may leave a request waiting while it does something else. What it
/// guards against takes seconds; what is normal takes a few milliseconds.
const KEPT_WAITING: Duration = Duration::from_secs(1);

/// The name of a group is in the file once, however many entries the group has. In the index
/// it is once as well, and cut to a length that is not the file's to choose. With the name
/// in every entry, this file of half a megabyte asked for an index of more than a gigabyte,
/// and a daemon that cannot have that much is gone: on unlock, and on the reload that
/// follows when a sync peer saves such a file over the open one.
#[test]
fn a_group_name_is_in_the_index_once() {
    use std::os::unix::process::CommandExt;
    let env = Env::new();
    let mut serve = env.command(&["serve"]);
    // Room for this database several times over, and less than half of what the index took.
    let room: libc::rlim_t = 512 << 20;
    unsafe {
        serve.pre_exec(move || {
            let limit = libc::rlimit { rlim_cur: room, rlim_max: room };
            match libc::setrlimit(libc::RLIMIT_DATA, &limit) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        });
    }
    let _daemon = env.serve_with(serve);
    let mut conn = env.connect();

    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut group = root.add_group();
        group.name = "g".repeat(64 << 10);
        for i in 0..20_000 {
            group.add_entry().set_unprotected("Title", format!("Entry {i}"));
        }
    }
    let named = env.dir.path().join("Named.kdbx");
    save(db, &named);
    assert!(std::fs::metadata(&named).unwrap().len() < 1 << 20);

    let check = |conn: &mut Conn| {
        assert_eq!(conn.state()["entryCount"], 20_000);
        let found = conn.request("search", json!({"query": "'19999"}));
        assert_eq!(
            (found["total"].clone(), found["entries"][0]["title"].clone()),
            (json!(1), json!("Entry 19999"))
        );
        let group = found["entries"][0]["group"].as_str().unwrap();
        assert!(group.len() <= 256 && group.starts_with("ggg") && group.ends_with('…'), "{group}");
    };
    assert_eq!(unlock(&mut conn, &named, None)["ok"], true);
    check(&mut conn);
    assert_eq!(conn.request("lock", json!({}))["ok"], true);

    let db = env.db_copy();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    assert_eq!(conn.state()["entryCount"], 7);
    // What the first unlock announced is not what is waited for below.
    conn.events.clear();
    let tmp = db.with_extension("tmp");
    std::fs::copy(&named, &tmp).unwrap();
    std::fs::rename(&tmp, &db).unwrap();
    conn.wait_event("reload", |m| m["event"] == "state" && m["entryCount"] == 20_000);
    check(&mut conn);
}

/// A search takes as long as there is text to look through, and how much there is is up to
/// the database. Everything else is answered while a search goes on, and a lock ends it.
#[test]
fn a_search_keeps_nothing_waiting() {
    let env = Env::new();
    let _daemon = env.serve();
    let mut conn = env.connect();

    // Notes that are not plain ASCII, with the words that are looked for at their very end.
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        for i in 0..600 {
            let mut entry = root.add_entry();
            entry.set_unprotected("Title", format!("Entry {i}"));
            entry.set_unprotected("Notes", format!("{} last words", "ž".repeat(8000)));
        }
    }
    let path = env.dir.path().join("Notes.kdbx");
    save(db, &path);
    assert_eq!(unlock(&mut conn, &path, None)["ok"], true);
    let query = json!({"query": "last words ords", "limit": 500});

    let asking = Asking::start(&env);
    let started = Instant::now();
    let found = conn.request("search", query.clone());
    let took = started.elapsed();
    let (longest, answers) = asking.stop();
    assert_eq!((found["ok"].clone(), found["total"].clone()), (json!(true), json!(600)), "{found}");
    // A daemon that does nothing else while it searches answers when the search is over.
    assert!(longest < KEPT_WAITING.min(took / 2), "an answer took {longest:?} during a search of {took:?}");
    // The search was long enough for the question to mean something.
    assert!(answers >= 10, "{answers} answers during a search of {took:?}");

    // A lock in the middle of a search does not wait for it, and ends it.
    let search = conn.send("search", query);
    std::thread::sleep(took / 4);
    let mut other = env.connect();
    let started = Instant::now();
    assert_eq!(other.request("lock", json!({}))["ok"], true);
    let locked_after = started.elapsed();
    assert!(locked_after < KEPT_WAITING, "the lock took {locked_after:?}");
    // The search stops there, with three quarters of its work not done, instead of going
    // through the rest of the entries it still holds.
    assert_eq!(conn.reply(search)["error"], "locked");
    let ended_after = started.elapsed();
    assert!(ended_after < took / 2, "the search went on for {ended_after:?} of its {took:?}");
}

/// A database that is saved over the open one is taken over and indexed without the daemon
/// standing still for it, whatever its shape: here forty thousand entries a hundred groups
/// deep, where asking every group above every entry is four million questions.
#[test]
fn a_reload_keeps_nothing_waiting() {
    let env = Env::new();
    let _daemon = env.serve();
    let mut conn = env.connect();
    let db = env.db_copy();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);

    let mut deep = Database::new();
    let mut at = deep.root().id();
    for _ in 0..100 {
        at = deep.group_mut(at).unwrap().add_group().id();
    }
    {
        let mut deepest = deep.group_mut(at).unwrap();
        for _ in 0..40_000 {
            deepest.add_entry();
        }
    }
    let tmp = db.with_extension("tmp");
    save(deep, &tmp);

    let asking = Asking::start(&env);
    std::fs::rename(&tmp, &db).unwrap();
    conn.wait_event("reload", |m| m["event"] == "state" && m["entryCount"] == 40_000);
    let (longest, _) = asking.stop();
    assert!(longest < KEPT_WAITING, "an answer took {longest:?} during the reload");
}

/// A database that is replaced while its unlock is still running: the unlock opens the copy its
/// helper had read, and the new one is loaded right after it instead of going unnoticed.
#[test]
fn a_change_during_the_unlock_is_loaded_after_it() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: needs a debug build of omakeepickd");
        return;
    }
    let env = Env::new();
    let fifo = env.dir.path().join("hold-kdf");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let mut serve = env.command(&["serve"]);
    serve.env("OMAKEEPICK_TEST_HOLD_KDF", &fifo);
    let _daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let db = env.db_copy();

    // The helper has read the file and is where it would derive the key.
    let id = conn.send("unlock", json!({"db": db, "password": PASSWORD}));
    let hold = held_at(&fifo);
    let mut changed =
        Database::open(&mut std::fs::File::open(&db).unwrap(), DatabaseKey::new().with_password(PASSWORD))
            .unwrap();
    changed.config.version = keepass::config::DatabaseVersion::KDB4(1);
    changed.root_mut().add_entry().set_unprotected("Title", "Brand new");
    let tmp = db.with_extension("tmp");
    changed
        .save(&mut std::fs::File::create(&tmp).unwrap(), DatabaseKey::new().with_password(PASSWORD))
        .unwrap();
    std::fs::rename(&tmp, &db).unwrap();
    drop(hold);
    assert_eq!(conn.reply(id)["ok"], true);

    // The reload that follows the unlock reaches the same hold with the new file.
    drop(held_at(&fifo));
    conn.wait_event("reload", |m| m["event"] == "state" && m["entryCount"] == 8);
}

#[test]
fn attach_bridges_and_spawns_the_daemon() {
    let env = Env::new();
    // No daemon yet: attach must start one.
    let mut attach = env
        .command(&["attach"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = attach.stdin.take().unwrap();
    let mut stdout = BufReader::new(attach.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let hello: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(hello["event"], "state");

    writeln!(stdin, r#"{{"id": 7, "cmd": "status"}}"#).unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!((reply["id"].clone(), reply["ok"].clone()), (json!(7), json!(true)));

    // ctl talks to the same daemon; `quit` stops it, and attach exits with it.
    let status = env.command(&["ctl", "status"]).output().unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("\"phase\":\"closed\""));
    let quit = env.command(&["ctl", "quit"]).output().unwrap();
    assert!(quit.status.success());
    assert!(attach.wait().unwrap().success());
    assert_eq!(env.command(&["ctl", "status"]).output().unwrap().status.code(), Some(3));
}

#[test]
fn ctl_usage_errors() {
    let env = Env::new();
    assert_eq!(env.command(&["ctl"]).output().unwrap().status.code(), Some(2));
    assert_eq!(env.command(&["ctl", "status", "[1]"]).output().unwrap().status.code(), Some(2));
    assert_eq!(env.command(&["bogus"]).output().unwrap().status.code(), Some(2));
}

/// Starts a private message bus with its socket at `dir`/`name`. `None` if `dbus-daemon` is not
/// installed.
fn start_bus(dir: &Path, name: &str) -> Option<(Child, String)> {
    let config = dir.join(format!("{name}.conf"));
    std::fs::write(
        &config,
        format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>"#,
            dir.join(name).display()
        ),
    )
    .unwrap();
    let mut bus = Command::new("dbus-daemon")
        .arg(format!("--config-file={}", config.display()))
        .args(["--nofork", "--print-address"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut address = String::new();
    BufReader::new(bus.stdout.take().unwrap()).read_line(&mut address).unwrap();
    let address = address.trim().to_string();
    assert!(!address.is_empty(), "dbus-daemon did not start");
    Some((bus, address))
}

/// A private bus whose one service stands in for systemd-logind as the daemon uses it: it hands
/// out sleep inhibitors and announces a sleep and the wake-up. An inhibitor is the writing end
/// of a pipe, so the test sees the moment the daemon lets go of it, which is what allows the
/// real logind to put the machine to sleep.
struct FakeLogind {
    bus: Child,
    address: String,
    announce: tokio::sync::mpsc::UnboundedSender<bool>,
    inhibitors: mpsc::Receiver<std::io::PipeReader>,
}

/// The reading end of the pipe whose writing end the daemon holds as its inhibitor.
struct Inhibitor(std::io::PipeReader);

impl Inhibitor {
    /// Whether the daemon has closed its end.
    fn released(&self) -> bool {
        use std::os::fd::AsRawFd;
        let mut poll = libc::pollfd { fd: self.0.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut poll, 1, 0) > 0 && poll.revents & libc::POLLHUP != 0 }
    }
}

impl FakeLogind {
    /// `None` if `dbus-daemon` is not installed.
    fn start(dir: &Path) -> Option<FakeLogind> {
        FakeLogind::patient_for(dir, Duration::from_secs(3))
    }

    /// One that says it waits `delay_max` for inhibitors (`InhibitDelayMaxSec`).
    fn patient_for(dir: &Path, delay_max: Duration) -> Option<FakeLogind> {
        let (bus, address) = start_bus(dir, "system-bus")?;
        let (ready, started) = mpsc::channel();
        let (taken, inhibitors) = mpsc::channel();
        let (announce, announcements) = tokio::sync::mpsc::unbounded_channel();
        let bus_address = address.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            // Also ends, with an error, when the bus goes away at the end of the test.
            let served = serve_logind(&bus_address, delay_max, ready, taken, announcements);
            if let Err(e) = runtime.block_on(served) {
                eprintln!("fake logind: {e}");
            }
        });
        started.recv_timeout(Duration::from_secs(10)).expect("the fake logind did not start");
        Some(FakeLogind { bus, address, announce, inhibitors })
    }

    /// A daemon that takes this bus for the system bus.
    fn serve(&self, env: &Env, configure: impl FnOnce(&mut Command)) -> Daemon {
        let mut serve = env.command(&["serve"]);
        serve.env_remove("OMAKEEPICK_NO_LOGIND").env("DBUS_SYSTEM_BUS_ADDRESS", &self.address);
        configure(&mut serve);
        env.serve_with(serve)
    }

    /// The inhibitor the daemon takes next: one at startup, and one after each wake-up.
    fn next_inhibitor(&self) -> Inhibitor {
        Inhibitor(self.inhibitors.recv_timeout(Duration::from_secs(10)).expect("no Inhibit call"))
    }

    /// Emits `PrepareForSleep`: `true` before a sleep, `false` after it.
    fn prepare_for_sleep(&self, start: bool) {
        self.announce.send(start).unwrap();
    }
}

impl Drop for FakeLogind {
    fn drop(&mut self) {
        let _ = self.bus.kill();
        let _ = self.bus.wait();
    }
}

async fn serve_logind(
    address: &str,
    delay_max: Duration,
    ready: mpsc::Sender<()>,
    taken: mpsc::Sender<std::io::PipeReader>,
    mut announcements: tokio::sync::mpsc::UnboundedReceiver<bool>,
) -> zbus::Result<()> {
    let conn = zbus::connection::Builder::address(address).build().await?;
    let mut messages = zbus::MessageStream::from(&conn);
    conn.request_name("org.freedesktop.login1").await?;
    ready.send(()).unwrap();
    // `InhibitDelayMaxSec`: how long the real logind would wait for the inhibitor.
    let delay_max = || Variant::from(delay_max.as_micros() as u64);
    loop {
        tokio::select! {
            start = announcements.recv() => {
                let Some(start) = start else { return Ok(()) };
                conn.emit_signal(
                    None::<&str>,
                    "/org/freedesktop/login1",
                    "org.freedesktop.login1.Manager",
                    "PrepareForSleep",
                    &(start,),
                )
                .await?;
            }
            message = messages.next() => {
                let Some(message) = message else { return Ok(()) };
                let message = message?;
                let header = message.header();
                if header.message_type() != zbus::message::Type::MethodCall {
                    continue;
                }
                match header.member().map(|m| m.as_str()) {
                    Some("Inhibit") => {
                        let (reader, writer) = std::io::pipe()?;
                        conn.reply(&header, &zbus::Fd::from(std::os::fd::OwnedFd::from(writer))).await?;
                        taken.send(reader).unwrap();
                    }
                    Some("GetAll") => {
                        conn.reply(&header, &HashMap::from([("InhibitDelayMaxUSec", delay_max())])).await?;
                    }
                    Some("Get") => conn.reply(&header, &delay_max()).await?,
                    // GetSession, for one: the daemon then goes without the session's lock signal.
                    _ => {
                        let error = "org.freedesktop.DBus.Error.UnknownMethod";
                        conn.reply_error(&header, error, &"not in this stand-in").await?;
                    }
                }
            }
        }
    }
}

/// Suspend from start to finish, against a stand-in for logind. The daemon lets go of its
/// sleep inhibitor only once it is locked, and from the announcement until the wake-up it
/// unlocks nothing: an unlock that starts after the sleep's lock is not cancelled by it, and
/// would leave the machine asleep with an open database.
#[test]
fn a_sleep_locks_and_nothing_unlocks_until_the_wake_up() {
    let env = Env::new();
    let Some(logind) = FakeLogind::start(env.dir.path()) else {
        eprintln!("skipped: dbus-daemon is not installed");
        return;
    };
    let _daemon = logind.serve(&env, |_| {});
    let mut conn = env.connect();
    let db = env.db_copy();
    let inhibitor = logind.next_inhibitor();
    assert_eq!(unlock(&mut conn, &db, Some("2468"))["ok"], true);
    assert!(!inhibitor.released());

    logind.prepare_for_sleep(true);
    wait_until("the inhibitor is released", || inhibitor.released());
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["quickUnlock"].clone()), (json!("locked"), json!(false)));
    assert_eq!(state["lockReason"], "sleep");
    // The machine can take a while to go down, and the daemon keeps answering until it does.
    assert_eq!(unlock(&mut conn, &db, Some("2468"))["error"], "cancelled");
    assert_eq!(conn.request("quickUnlock", json!({"pin": "2468"}))["error"], "cancelled");
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["busy"].clone()), (json!("locked"), json!(false)));

    // Awake again: a new inhibitor is taken, and unlocking works.
    logind.prepare_for_sleep(false);
    let inhibitor = logind.next_inhibitor();
    assert_eq!(unlock(&mut conn, &db, Some("2468"))["ok"], true);
    assert_eq!(conn.state()["phase"], "unlocked");
    assert!(!inhibitor.released());
}

/// The inhibitor is held for as long as something still has secrets in hand. Here that is an
/// unlock the daemon is taking over from its helper when the sleep is announced: the sleep has
/// to wait for it, and it is not installed.
#[test]
fn a_sleep_waits_for_what_is_still_in_flight() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: needs a debug build of omakeepickd");
        return;
    }
    let env = Env::new();
    let Some(logind) = FakeLogind::start(env.dir.path()) else {
        eprintln!("skipped: dbus-daemon is not installed");
        return;
    };
    let fifo = env.dir.path().join("hold-handover");
    assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let _daemon = logind.serve(&env, |serve| {
        serve.env("OMAKEEPICK_TEST_HOLD_HANDOVER", &fifo);
    });
    let mut conn = env.connect();
    let db = env.db_copy();
    let inhibitor = logind.next_inhibitor();

    let id = conn.send("unlock", json!({"db": db, "password": PASSWORD, "pin": "2468"}));
    let hold = held_at(&fifo);
    logind.prepare_for_sleep(true);
    // The stand-in's logind would wait 3 s for the inhibitor; well within that, it is still held.
    std::thread::sleep(Duration::from_millis(500));
    assert!(!inhibitor.released(), "the inhibitor was let go of with an unlock still in flight");
    drop(hold);
    assert_eq!(conn.reply(id)["error"], "cancelled");
    wait_until("the inhibitor is released", || inhibitor.released());
    let state = conn.state();
    assert_eq!((state["phase"].clone(), state["busy"].clone()), (json!("closed"), json!(false)));
    assert_eq!(state["quickUnlock"], false);
}

/// Waits until an auto-type of `{USERNAME}{DELAY 10000}{PASSWORD}` for the Jira entry is in its
/// pause: the user name is typed, the `wtype` that typed it has ended, and the moment the
/// daemon takes between two of them has passed.
fn in_the_pause(daemon: &Daemon, fake: &Fake) {
    wait_until("the user name is typed", || fake.read("typed") == "madev@work");
    wait_until("wtype has ended", || helper_of(daemon).is_none());
    std::thread::sleep(Duration::from_millis(100));
}

/// A lock ends an auto-type wherever it is, and what the action has in hand at that point is
/// as little as it can be: nothing in a pause, since a field's value is taken from the database
/// only when it is typed, and otherwise the value being typed, which goes with the action.
#[test]
fn a_lock_ends_an_auto_type_wherever_it_is() {
    let env = Env::new();
    let mut serve = env.command(&["serve"]);
    let fake = env.fake_tools(&mut serve);
    serve.env("FAKE_KEY_SECONDS", "0.05");
    let daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let db = env.db_copy();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    // User name "madev@work", password "jira pw", and a note of thirty characters.
    let jira = entry_id(&mut conn, "jira");
    let sequence = |sequence: &str, key_delay: u32| json!({"autotypeSequence": sequence, "autotypeStartDelayMs": 50, "typeDelayMs": key_delay});

    // In a pause, which nothing but the lock ends for ten seconds.
    configure(&mut conn, sequence("{USERNAME}{DELAY 10000}{PASSWORD}", 0));
    let id = conn.send("act", json!({"entry": jira, "action": "autotype"}));
    in_the_pause(&daemon, &fake);
    let locked = Instant::now();
    assert_eq!(conn.request("lock", json!({"reason": "screen"}))["ok"], true);
    assert_eq!(conn.reply(id)["error"], "cancelled");
    assert!(locked.elapsed() < Duration::from_secs(2), "the lock waited for the pause");
    wait_until("wtype has ended", || helper_of(&daemon).is_none());
    assert_eq!(fake.read("typed"), "madev@work");

    // While a value is being typed. The daemon drops it at once; wtype is not killed (it
    // could have a key down) and types what it was handed, which is no more than it types in
    // half a second: two characters, with the keys set this slow.
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    configure(&mut conn, sequence("{NOTES}", 200));
    let note = "Ask IT for the recovery codes.";
    let typed_note = || fake.read("typed")["madev@work".len()..].to_string();
    let id = conn.send("act", json!({"entry": jira, "action": "autotype"}));
    wait_until("the note is being typed", || typed_note().len() >= 2);
    assert_eq!(conn.request("lock", json!({"reason": "screen"}))["ok"], true);
    assert_eq!(conn.reply(id)["error"], "cancelled");
    wait_until("wtype has ended", || helper_of(&daemon).is_none());
    let typed = typed_note();
    assert!(note.starts_with(&typed) && typed.len() < note.len() / 2, "{typed:?}");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(typed_note(), typed, "something was typed after the lock");
    assert_eq!(conn.state()["phase"], "locked");
}

/// A sleep is not held back by an action, whatever the action was waiting for: a pause in an
/// auto-type sequence, or a `wl-copy` that never takes the value because the compositor does
/// not answer. The lock ends both at once, so the inhibitor goes as soon as they are gone, and
/// not when logind's patience (three seconds in the stand-in) runs out.
#[test]
fn a_sleep_is_not_held_back_by_an_action() {
    let env = Env::new();
    let Some(logind) = FakeLogind::start(env.dir.path()) else {
        eprintln!("skipped: dbus-daemon is not installed");
        return;
    };
    let mut fake = None;
    let daemon = logind.serve(&env, |serve| {
        fake = Some(env.fake_tools(serve));
        serve.env("FAKE_WL_COPY", "stalls");
    });
    let fake = fake.unwrap();
    let mut conn = env.connect();
    let db = env.db_copy();
    let asleep_within = |inhibitor: &Inhibitor, what: &str| {
        let announced = Instant::now();
        logind.prepare_for_sleep(true);
        wait_until("the inhibitor is released", || inhibitor.released());
        assert!(announced.elapsed() < Duration::from_millis(1500), "the sleep waited for {what}");
    };

    let inhibitor = logind.next_inhibitor();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    let jira = entry_id(&mut conn, "jira");
    configure(
        &mut conn,
        json!({"autotypeSequence": "{USERNAME}{DELAY 10000}{PASSWORD}", "autotypeStartDelayMs": 50}),
    );
    let id = conn.send("act", json!({"entry": jira, "action": "autotype"}));
    in_the_pause(&daemon, &fake);
    asleep_within(&inhibitor, "the pause");
    assert_eq!(conn.reply(id)["error"], "cancelled");
    assert_eq!(fake.read("typed"), "madev@work");

    logind.prepare_for_sleep(false);
    let inhibitor = logind.next_inhibitor();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    let id = conn.send("act", json!({"entry": jira, "action": "copyPassword"}));
    wait_until("wl-copy is running", || fake.read("wl-copy.log").contains("stalled"));
    assert!(helper_of(&daemon).is_some());
    asleep_within(&inhibitor, "wl-copy");
    assert_eq!(conn.reply(id)["error"], "cancelled");
    // It was killed, with the password it was never going to take still in its pipe.
    assert_eq!(helper_of(&daemon), None);
    assert_eq!(fake.selection("clipboard"), None);
}

/// When logind's time is nearly up, a `wtype` that is still at it is killed rather than left to
/// finish: here one that never finishes, with keys set so slow that its own allowance (the time
/// a key takes, and half a second) is longer than the second this logind waits.
#[test]
fn a_sleep_that_can_wait_no_longer_kills_what_is_left() {
    let env = Env::new();
    let Some(logind) = FakeLogind::patient_for(env.dir.path(), Duration::from_millis(1500)) else {
        eprintln!("skipped: dbus-daemon is not installed");
        return;
    };
    let mut fake = None;
    let daemon = logind.serve(&env, |serve| {
        fake = Some(env.fake_tools(serve));
        serve.env("FAKE_KEY_SECONDS", "30");
    });
    let fake = fake.unwrap();
    let mut conn = env.connect();
    let db = env.db_copy();
    let inhibitor = logind.next_inhibitor();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    let jira = entry_id(&mut conn, "jira");
    configure(&mut conn, json!({"autotypeSequence": "{DELAY=1000}{PASSWORD}", "autotypeStartDelayMs": 50}));
    let id = conn.send("act", json!({"entry": jira, "action": "autotype"}));
    wait_until("wtype is typing", || !fake.read("typed").is_empty());
    assert_eq!(fake.read("wtype.log"), "-d 1000 -\n");

    logind.prepare_for_sleep(true);
    // The request ends with the lock; the wtype it started is still there.
    assert_eq!(conn.reply(id)["error"], "cancelled");
    assert!(helper_of(&daemon).is_some());
    wait_until("the inhibitor is released", || inhibitor.released());
    assert_eq!(helper_of(&daemon), None, "the machine went to sleep with a wtype that had a key to type");
    assert_eq!(fake.read("typed"), "j");
}

/// A copied value is on the clipboard for as long as the `wl-copy` that the daemon keeps for it
/// lives. A lock, the clear timer and the daemon's exit all take the value back by killing that
/// process: nothing has to answer for it to be gone.
#[test]
fn a_copied_value_is_taken_back() {
    let env = Env::new();
    let mut serve = env.command(&["serve"]);
    let fake = env.fake_tools(&mut serve);
    let mut daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let db = env.db_copy();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    let gitea = entry_id(&mut conn, "gitea");
    let copy = |conn: &mut Conn, action: &str| conn.request("act", json!({"entry": gitea, "action": action}));

    let copied = copy(&mut conn, "copyPassword");
    assert_eq!((copied["copied"].clone(), copied["clearsIn"].clone()), (json!("password"), json!(15)));
    wait_until("the password is on the clipboard", || {
        fake.selection("clipboard").as_deref() == Some("admin-pw")
    });
    assert_eq!(conn.request("lock", json!({}))["ok"], true);
    wait_until("the clipboard is empty", || fake.selection("clipboard").is_none());

    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    configure(&mut conn, json!({"clipboardClearSeconds": 1}));
    assert_eq!(copy(&mut conn, "copyUsername")["clearsIn"], 1);
    wait_until("the user name is on the clipboard", || {
        fake.selection("clipboard").as_deref() == Some("admin")
    });
    wait_until("the clipboard is empty", || fake.selection("clipboard").is_none());
    assert_eq!(conn.state()["phase"], "unlocked");

    configure(&mut conn, json!({"clipboardClearSeconds": 0}));
    assert_eq!(copy(&mut conn, "copyUrl")["ok"], true);
    wait_until("the URL is on the clipboard", || {
        fake.selection("clipboard").as_deref() == Some("http://gitea.lan:3000")
    });
    assert_eq!(conn.request("quit", json!({}))["ok"], true);
    wait_until("the daemon has exited", || daemon.child.try_wait().unwrap().is_some());
    assert_eq!(fake.selection("clipboard"), None);
    // The value was only ever taken back by ending its wl-copy.
    assert!(!fake.read("wl-copy.log").contains("clear"), "{}", fake.read("wl-copy.log"));
    // wl-copy's buffer files were in the daemon's runtime directory, and are gone with it.
    let left: Vec<_> = std::fs::read_dir(env.dir.path().join("run/clip")).unwrap().flatten().collect();
    assert!(left.is_empty(), "{left:?}");
}

/// In an XWayland window the text is pasted, a piece at a time. Each piece is on the two
/// selections for its paste only, and a lock takes it off them at once.
#[test]
fn pasting_into_xwayland_leaves_nothing_on_the_clipboard() {
    let env = Env::new();
    let mut serve = env.command(&["serve"]);
    let fake = env.fake_tools(&mut serve);
    serve.env("FAKE_XWAYLAND", "true");
    let daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let db = env.db_copy();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);
    configure(&mut conn, json!({"autotypeStartDelayMs": 50}));
    let gitea = entry_id(&mut conn, "gitea");

    assert_eq!(conn.request("act", json!({"entry": gitea, "action": "autotype"}))["ok"], true);
    let paste = "-M shift -k Insert -m shift\n";
    assert_eq!(
        fake.read("wtype.log"),
        format!("{paste}pasted admin|admin\n-k Tab\n{paste}pasted admin-pw|admin-pw\n-k Return\n")
    );
    assert_eq!(fake.read("typed"), "");
    wait_until("the selections are empty", || {
        fake.selection("clipboard").is_none() && fake.selection("primary").is_none()
    });

    let id = conn.send("act", json!({"entry": gitea, "action": "typePassword"}));
    wait_until("the password is on the clipboard", || fake.selection("clipboard").is_some());
    assert_eq!(conn.request("lock", json!({}))["ok"], true);
    assert_eq!(conn.reply(id)["error"], "cancelled");
    wait_until("the tools are gone", || helper_of(&daemon).is_none());
    assert_eq!((fake.selection("clipboard"), fake.selection("primary")), (None, None));
}

/// A private session bus whose one service stands in for xdg-desktop-portal's FileChooser. Like
/// the real portal it turns away callers whose `/proc/<pid>/root` it cannot open, which is what
/// `PR_SET_DUMPABLE=0` does to the daemon. Each `OpenFile` answers with the next of `responses`
/// (a portal response code and the URI picked) and reports the call on `calls`.
struct FakePortal {
    bus: Child,
    address: String,
    calls: mpsc::Receiver<PortalCall>,
}

struct PortalCall {
    pid: u32,
    title: String,
    folder: Option<Vec<u8>>,
}

impl FakePortal {
    /// `None` if `dbus-daemon` is not installed.
    fn start(dir: &Path, responses: Vec<(u32, &'static str)>) -> Option<FakePortal> {
        let (bus, address) = start_bus(dir, "bus")?;
        let (ready, started) = mpsc::channel();
        let (report, calls) = mpsc::channel();
        let bus_address = address.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            // Also ends, with an error, when the bus goes away at the end of the test.
            if let Err(e) = runtime.block_on(serve_portal(&bus_address, responses, ready, report)) {
                eprintln!("fake portal: {e}");
            }
        });
        started.recv_timeout(Duration::from_secs(10)).expect("the fake portal did not start");
        Some(FakePortal { bus, address, calls })
    }

    fn next_call(&self) -> PortalCall {
        self.calls.recv_timeout(Duration::from_secs(10)).expect("no OpenFile call")
    }
}

impl Drop for FakePortal {
    fn drop(&mut self) {
        let _ = self.bus.kill();
        let _ = self.bus.wait();
    }
}

async fn serve_portal(
    address: &str,
    responses: Vec<(u32, &'static str)>,
    ready: mpsc::Sender<()>,
    report: mpsc::Sender<PortalCall>,
) -> zbus::Result<()> {
    let conn = zbus::connection::Builder::address(address).build().await?;
    let mut messages = zbus::MessageStream::from(&conn);
    conn.request_name("org.freedesktop.portal.Desktop").await?;
    let dbus = zbus::fdo::DBusProxy::new(&conn).await?;
    ready.send(()).unwrap();
    let mut responses = responses.into_iter();
    while let Some(message) = messages.next().await {
        let message = message?;
        let header = message.header();
        if header.member().map(|m| m.as_str()) != Some("OpenFile") {
            continue;
        }
        let sender = header.sender().unwrap().to_owned();
        let pid = dbus.get_connection_unix_process_id(sender.clone().into()).await?;
        // How xdg-desktop-portal tells a Flatpak from a host app.
        if std::fs::read_dir(format!("/proc/{pid}/root")).is_err() {
            let error = format!("Portal operation not allowed: Unable to open /proc/{pid}/root");
            conn.reply_error(&header, "org.freedesktop.DBus.Error.AccessDenied", &error).await?;
            continue;
        }
        let (_parent, title, mut options): (String, String, HashMap<String, OwnedVariant>) =
            message.body().deserialize()?;
        let token = String::try_from(options.remove("handle_token").unwrap()).unwrap();
        let folder = options.remove("current_folder").map(|v| Vec::<u8>::try_from(v).unwrap());
        report.send(PortalCall { pid, title, folder }).unwrap();

        let handle = format!(
            "/org/freedesktop/portal/desktop/request/{}/{token}",
            sender.trim_start_matches(':').replace('.', "_")
        );
        let handle = ObjectPath::try_from(handle.as_str()).unwrap();
        conn.reply(&header, &handle).await?;
        let (code, uri) = responses.next().expect("an unexpected OpenFile call");
        let mut results: HashMap<&str, Variant<'_>> = HashMap::new();
        if code == 0 {
            results.insert("uris", Variant::from(vec![uri]));
        }
        conn.emit_signal(
            Some(&sender),
            &handle,
            "org.freedesktop.portal.Request",
            "Response",
            &(code, results),
        )
        .await?;
    }
    Ok(())
}

#[test]
fn pick_file_asks_the_portal_from_a_process_it_accepts() {
    let env = Env::new();
    let responses = vec![(0, "file:///srv/My%20Vault/K%C3%BD.kdbx"), (2, "")];
    let Some(portal) = FakePortal::start(env.dir.path(), responses) else {
        eprintln!("skipped: dbus-daemon is not installed");
        return;
    };
    let mut serve = env.command(&["serve"]);
    serve.env("DBUS_SESSION_BUS_ADDRESS", &portal.address);
    let daemon = env.serve_with(serve);
    let mut conn = env.connect();
    let db = env.db_copy();
    assert_eq!(unlock(&mut conn, &db, None)["ok"], true);

    // The premise: the hardened daemon itself would be turned away (root can read it anyway).
    if unsafe { libc::geteuid() } != 0 {
        assert!(std::fs::read_dir(format!("/proc/{}/root", daemon.child.id())).is_err());
    }

    let picked = conn.request("pickFile", json!({"kind": "db"}));
    assert_eq!(picked["ok"], true, "{picked}");
    assert_eq!(picked["path"], "/srv/My Vault/Ký.kdbx");
    assert_eq!(picked["keyfile"], Value::Null);
    let call = portal.next_call();
    assert_ne!(call.pid, daemon.child.id());
    assert_eq!(call.title, "Open KeePass database");
    let mut folder = db.parent().unwrap().as_os_str().as_bytes().to_vec();
    folder.push(0);
    assert_eq!(call.folder, Some(folder));

    // Closing the dialog (Esc, or the compositor) is response 2: a cancel, not a failure.
    let closed = conn.request("pickFile", json!({"kind": "keyfile"}));
    assert_eq!(closed["error"], "cancelled", "{closed}");
    assert_eq!(portal.next_call().title, "Choose key file");
}
