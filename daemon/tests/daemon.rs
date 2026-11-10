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
        let (bus, address) = start_bus(dir, "system-bus")?;
        let (ready, started) = mpsc::channel();
        let (taken, inhibitors) = mpsc::channel();
        let (announce, announcements) = tokio::sync::mpsc::unbounded_channel();
        let bus_address = address.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            // Also ends, with an error, when the bus goes away at the end of the test.
            if let Err(e) = runtime.block_on(serve_logind(&bus_address, ready, taken, announcements)) {
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
    ready: mpsc::Sender<()>,
    taken: mpsc::Sender<std::io::PipeReader>,
    mut announcements: tokio::sync::mpsc::UnboundedReceiver<bool>,
) -> zbus::Result<()> {
    let conn = zbus::connection::Builder::address(address).build().await?;
    let mut messages = zbus::MessageStream::from(&conn);
    conn.request_name("org.freedesktop.login1").await?;
    ready.send(()).unwrap();
    // `InhibitDelayMaxSec`: how long the real logind would wait for the inhibitor.
    let delay_max = || Variant::from(3_000_000u64);
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
