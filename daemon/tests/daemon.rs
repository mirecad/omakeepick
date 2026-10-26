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
        let id = self.next_id;
        self.next_id += 1;
        let mut req = args.as_object().cloned().unwrap_or_default();
        req.insert("id".into(), json!(id));
        req.insert("cmd".into(), json!(cmd));
        writeln!(self.writer, "{}", Value::Object(req)).unwrap();
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
        let config = dir.join("bus.conf");
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
                dir.join("bus").display()
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
