//! What becomes of the programs the daemon hands a secret to, against the stand-ins for `wtype`
//! and `wl-copy` in `tests/fixtures/bin`.
//!
//! This is the only test in this binary because it changes the environment of the whole
//! process.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use omakeepickd::autotype::{Typist, Wtype};
use omakeepickd::clipboard::Clipboard;
use omakeepickd::inflight::Tracker;
use zeroize::Zeroizing;

struct Fake(PathBuf);

impl Fake {
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.0.join(name)).unwrap_or_default()
    }

    fn reset(&self) {
        for entry in fs::read_dir(&self.0).unwrap().flatten() {
            fs::remove_file(entry.path()).unwrap();
        }
    }

    /// What is on the selection `which`: something only while the `wl-copy` that offered it
    /// is alive.
    fn selection(&self, which: &str) -> Option<String> {
        let pid: u32 = self.read(&format!("{which}.pid")).trim().parse().ok()?;
        Path::new(&format!("/proc/{pid}")).exists().then(|| self.read(which))
    }
}

fn set(name: &str, value: &str) {
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::set_var(name, value) };
}

fn unset(name: &str) {
    // SAFETY: as above.
    unsafe { std::env::remove_var(name) };
}

/// Everything a tool was started for is over once the tracker is back at zero: it was waited
/// for, and its scratch directory removed.
async fn settled(inflight: &Tracker) {
    tokio::time::timeout(Duration::from_secs(5), inflight.settled()).await.expect("a tool is still running");
}

#[tokio::test]
async fn tools_end_with_what_started_them() {
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake(dir.path().join("fake"));
    let runtime = dir.path().join("run");
    fs::create_dir(&fake.0).unwrap();
    let bin = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bin");
    set("PATH", &format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default()));
    set("FAKE_DIR", fake.0.to_str().unwrap());
    set("OMAKEEPICK_RUNTIME_DIR", runtime.to_str().unwrap());
    let inflight = Tracker::default();

    // Typing: all of the text arrives.
    let mut wtype = Wtype::new(&inflight);
    wtype.text("čšž-ľťň p@ss", 0).await.unwrap();
    assert_eq!(fake.read("typed"), "čšž-ľťň p@ss");
    assert_eq!(fake.read("wtype.log"), "-d 0 -\n");
    assert_eq!(inflight.count(), 0);

    // Dropped while it types (a lock): wtype is not killed, which could leave a key held down.
    // It types what it was given, which is why that is never much, and ends by itself.
    fake.reset();
    set("FAKE_KEY_SECONDS", "0.05");
    assert!(tokio::time::timeout(Duration::from_millis(80), wtype.text("0123", 0)).await.is_err());
    assert_eq!(inflight.count(), 1, "the wtype it left behind is not accounted for");
    assert_ne!(fake.read("typed"), "0123");
    settled(&inflight).await;
    assert_eq!(fake.read("typed"), "0123");

    // One that does not end is killed, once it has had the time its work should take.
    fake.reset();
    set("FAKE_KEY_SECONDS", "30");
    assert!(tokio::time::timeout(Duration::from_millis(100), wtype.text("0123", 0)).await.is_err());
    let dropped = Instant::now();
    settled(&inflight).await;
    assert!(dropped.elapsed() > Duration::from_millis(300), "killed while it may have had a key down");
    assert_eq!(fake.read("typed"), "0");

    // Or at once, when a suspend can wait no longer.
    fake.reset();
    assert!(tokio::time::timeout(Duration::from_millis(100), wtype.text("0123", 0)).await.is_err());
    let hurried = Instant::now();
    inflight.hurry();
    settled(&inflight).await;
    assert!(hurried.elapsed() < Duration::from_millis(300));
    unset("FAKE_KEY_SECONDS");

    // The clipboard: a value is on it for as long as its owner exists, and not after.
    fake.reset();
    let clipboard = Clipboard::new(inflight.clone());
    let owner = clipboard.offer("s3cret", false).await.unwrap();
    assert_eq!(fake.selection("clipboard").as_deref(), Some("s3cret"));
    assert_eq!(fake.read("wl-copy.log"), "offer --foreground --type text/plain;charset=utf-8 --sensitive\n");
    // wl-copy's buffer file is in a directory of the daemon's own, not in /tmp.
    let buffers = || -> Vec<PathBuf> {
        let Ok(dirs) = fs::read_dir(runtime.join("clip")) else { return vec![] };
        dirs.flatten().map(|d| d.path().join("buffer")).collect()
    };
    assert_eq!(buffers().len(), 1);
    assert_eq!(fs::read_to_string(&buffers()[0]).unwrap(), "s3cret");
    drop(owner);
    settled(&inflight).await;
    assert_eq!(fake.selection("clipboard"), None);
    assert!(buffers().is_empty(), "the buffer file outlived its wl-copy");

    // The primary selection, and a wl-copy from before 2.3, which has no --sensitive.
    fake.reset();
    set("FAKE_OLD_WL_COPY", "1");
    let old = Clipboard::new(inflight.clone());
    let owner = old.offer("s3cret", true).await.unwrap();
    assert_eq!(fake.selection("primary").as_deref(), Some("s3cret"));
    assert_eq!(fake.read("wl-copy.log"), "offer --foreground --type text/plain;charset=utf-8 --primary\n");
    drop(owner);
    settled(&inflight).await;
    unset("FAKE_OLD_WL_COPY");

    // A wl-copy that cannot reach the compositor.
    set("FAKE_WL_COPY", "fails");
    assert_eq!(clipboard.offer("s3cret", false).await.err().as_deref(), Some("wl-copy failed"));
    settled(&inflight).await;

    // One that never takes the value (the compositor does not answer): dropping the offer, as
    // a lock does, kills it with the value still in the pipe.
    set("FAKE_WL_COPY", "stalls");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), clipboard.offer("s3cret", false)).await.is_err()
    );
    let dropped = Instant::now();
    settled(&inflight).await;
    assert!(dropped.elapsed() < Duration::from_secs(1));
    assert!(buffers().is_empty());
    unset("FAKE_WL_COPY");

    // Copying: taken back by `forget` (a lock), with nothing run to do it.
    fake.reset();
    clipboard.copy(Zeroizing::new("first".into())).await.unwrap();
    assert_eq!(fake.selection("clipboard").as_deref(), Some("first"));
    clipboard.forget();
    settled(&inflight).await;
    assert_eq!(fake.selection("clipboard"), None);
    assert!(!fake.read("wl-copy.log").contains("clear"));

    // Taken back when its time is up, unless something was copied since.
    let first = clipboard.copy(Zeroizing::new("first".into())).await.unwrap();
    let second = clipboard.copy(Zeroizing::new("second".into())).await.unwrap();
    clipboard.clear_if_unchanged(first, Duration::from_millis(10)).await;
    assert_eq!(fake.selection("clipboard").as_deref(), Some("second"));
    clipboard.clear_if_unchanged(second, Duration::from_millis(10)).await;
    settled(&inflight).await;
    assert_eq!(fake.selection("clipboard"), None);

    // A clipboard manager that takes the selection over and keeps a copy: that copy is found
    // by its hash and cleared.
    fake.reset();
    set("FAKE_WL_COPY", "taken-over");
    clipboard.copy(Zeroizing::new("kept by a manager".into())).await.unwrap();
    assert_eq!(fake.read("kept"), "kept by a manager");
    clipboard.forget();
    settled(&inflight).await;
    assert!(fake.read("wl-copy.log").ends_with("clear clipboard\n"), "{}", fake.read("wl-copy.log"));
    // Unless the clipboard has something else by then, however much it looks like it.
    for other in ["kept by a manage", "kept by a manager!", "kept by a managex", ""] {
        fake.reset();
        clipboard.copy(Zeroizing::new("kept by a manager".into())).await.unwrap();
        fs::write(fake.0.join("kept"), other).unwrap();
        clipboard.forget();
        settled(&inflight).await;
        assert!(!fake.read("wl-copy.log").contains("clear"), "cleared {other:?}");
    }
}
