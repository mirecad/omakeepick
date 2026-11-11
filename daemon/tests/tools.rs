//! What becomes of the programs the daemon hands a secret to, against the stand-ins for `wtype`
//! and `wl-copy` in `tests/fixtures/bin`.
//!
//! This is the only test in this binary because it changes the environment of the whole
//! process.

use std::fs;
use std::io::Write;
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

    /// Whether the `wl-copy` that last took the selection `which` is still running. One that
    /// has ended and only waits to be reaped is not.
    fn owned(&self, which: &str) -> bool {
        let pid = self.read(&format!("{which}.pid"));
        let stat = fs::read_to_string(format!("/proc/{}/stat", pid.trim())).unwrap_or_default();
        stat.rfind(')').and_then(|at| stat[at..].chars().nth(2)).is_some_and(|state| state != 'Z')
    }

    /// What is on the selection `which`: something only while the `wl-copy` that offered it
    /// is alive.
    fn selection(&self, which: &str) -> Option<String> {
        self.owned(which).then(|| self.read(which))
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

/// Waits until `check` holds. What a stand-in records, it records a moment after the daemon's
/// side of the exchange is done.
async fn eventually(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Waits until only `left` holders are left: the owners that are meant to be there.
async fn settled_but_for(inflight: &Tracker, left: usize) {
    eventually("the tools that were dropped are gone", || inflight.count() <= left).await;
    assert_eq!(inflight.count(), left);
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

    // Typing: all of the text arrives. wtype takes no delay of 0, so none is passed then.
    let mut wtype = Wtype::new(&inflight);
    wtype.text("čšž-ľťň p@ss", 0).await.unwrap();
    wtype.text("!", 8).await.unwrap();
    assert_eq!(fake.read("typed"), "čšž-ľťň p@ss!");
    assert_eq!(fake.read("wtype.log"), "-\n-d 8 -\n");
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
    let offered = "offer --foreground --sensitive --type text/plain;charset=utf-8";
    let owner = clipboard.offer("s3cret", false).await.unwrap();
    eventually("clipboard has the value", || fake.selection("clipboard").as_deref() == Some("s3cret")).await;
    eventually("wl-copy has logged", || fake.read("wl-copy.log") == format!("{offered}\n")).await;
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

    // The primary selection.
    fake.reset();
    let owner = clipboard.offer("s3cret", true).await.unwrap();
    eventually("primary has the value", || fake.selection("primary").as_deref() == Some("s3cret")).await;
    eventually("wl-copy has logged", || fake.read("wl-copy.log") == format!("{offered} --primary\n")).await;
    drop(owner);
    settled(&inflight).await;

    // A wl-copy from before 2.3 is not used: killed, it would leave its buffer file in /tmp.
    fake.reset();
    set("FAKE_OLD_WL_COPY", "1");
    let old = Clipboard::new(inflight.clone());
    let refused = old.offer("s3cret", false).await.err();
    assert_eq!(refused.as_deref(), Some("tool_missing:wl-clipboard 2.3 or newer is needed"));
    assert_eq!(fake.read("wl-copy.log"), "");
    // Nothing of that answer is kept: with a newer one installed, it works.
    unset("FAKE_OLD_WL_COPY");
    drop(old.offer("s3cret", false).await.unwrap());
    settled(&inflight).await;

    // A wl-copy that cannot reach the compositor.
    set("FAKE_WL_COPY", "fails");
    assert_eq!(clipboard.offer("s3cret", false).await.err().as_deref(), Some("wl-copy failed"));
    // The same with more than a pipe holds: it is not waited for to read what it never will.
    let started = Instant::now();
    let large = "x".repeat(1 << 20);
    assert_eq!(clipboard.offer(large, false).await.err().as_deref(), Some("wl-copy failed"));
    assert!(started.elapsed() < Duration::from_secs(2));
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
    let copy = |value: &str| clipboard.copy(Zeroizing::new(value.into()));
    copy("first").await.unwrap();
    eventually("clipboard has the value", || fake.selection("clipboard").as_deref() == Some("first")).await;
    clipboard.forget();
    settled(&inflight).await;
    assert_eq!(fake.selection("clipboard"), None);
    assert!(!fake.read("wl-copy.log").contains("clear"));

    // Taken back when its time is up, unless something was copied since.
    let first = copy("first").await.unwrap();
    let second = copy("second").await.unwrap();
    clipboard.clear_if_unchanged(first, Duration::from_millis(10)).await;
    eventually("clipboard has the value", || fake.selection("clipboard").as_deref() == Some("second")).await;
    clipboard.clear_if_unchanged(second, Duration::from_millis(10)).await;
    settled(&inflight).await;
    assert_eq!(fake.selection("clipboard"), None);

    // The same value again: the first one's wl-copy has lost the selection, and nothing goes
    // looking for its value, which would find the second and clear it.
    copy("the same").await.unwrap();
    copy("the same").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    settled_but_for(&inflight, 1).await;
    assert_eq!(fake.selection("clipboard").as_deref(), Some("the same"));
    assert!(!fake.read("wl-copy.log").contains("clear"), "{}", fake.read("wl-copy.log"));
    clipboard.forget();
    settled(&inflight).await;

    // Two at once take their turns, and it is the later one that stays.
    let (a, b) = tokio::join!(copy("one"), copy("two"));
    let (a, b) = (a.unwrap(), b.unwrap());
    let later = if a > b { "one" } else { "two" };
    eventually("clipboard has the value", || fake.selection("clipboard").as_deref() == Some(later)).await;
    clipboard.forget();
    settled(&inflight).await;

    // The user copies something else, which ends our wl-copy: theirs is left alone.
    fake.reset();
    copy("ours").await.unwrap();
    let their_tmp = dir.path().join("theirs");
    fs::create_dir(&their_tmp).unwrap();
    let mut theirs = std::process::Command::new("wl-copy")
        .env("TMPDIR", &their_tmp)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    theirs.stdin.take().unwrap().write_all(b"theirs").unwrap();
    eventually("theirs is on the clipboard", || fake.selection("clipboard").as_deref() == Some("theirs"))
        .await;
    clipboard.forget();
    settled(&inflight).await;
    eventually("clipboard has the value", || fake.selection("clipboard").as_deref() == Some("theirs")).await;
    assert!(!fake.read("wl-copy.log").contains("clear"));
    theirs.kill().unwrap();
    theirs.wait().unwrap();

    // A clipboard manager that takes the selection over and keeps a copy: that copy is found
    // by its hash and cleared.
    let kept = |which: &str| fake.read(&format!("{which}.kept"));
    // The manager has its copy, and the wl-copy it took the selection from has ended.
    let taken_over = async |which: &str, value: &str| {
        eventually("the manager has taken the selection over", || kept(which) == value && !fake.owned(which))
            .await;
    };
    fake.reset();
    set("FAKE_WL_COPY", "taken-over");
    copy("kept by a manager").await.unwrap();
    taken_over("clipboard", "kept by a manager").await;
    clipboard.forget();
    settled(&inflight).await;
    assert!(fake.read("wl-copy.log").ends_with("clear clipboard\n"), "{}", fake.read("wl-copy.log"));
    // Unless the clipboard has something else by then, however much it looks like it.
    for other in ["kept by a manage", "kept by a manager!", "kept by a managex", ""] {
        fake.reset();
        copy("kept by a manager").await.unwrap();
        taken_over("clipboard", "kept by a manager").await;
        fs::write(fake.0.join("clipboard.kept"), other).unwrap();
        clipboard.forget();
        settled(&inflight).await;
        assert!(!fake.read("wl-copy.log").contains("clear"), "cleared {other:?}");
    }

    // The same for a piece that was only offered for a paste, on either selection.
    for (primary, which) in [(false, "clipboard"), (true, "primary")] {
        fake.reset();
        let owner = clipboard.offer("a pasted piece", primary).await.unwrap();
        taken_over(which, "a pasted piece").await;
        drop(owner);
        settled(&inflight).await;
        assert!(
            fake.read("wl-copy.log").ends_with(&format!("clear {which}\n")),
            "{}",
            fake.read("wl-copy.log")
        );
        assert_eq!(kept(which), "");
    }

    // A search that gets no answer is given up when a suspend can wait no longer, rather than
    // when its own patience ends.
    fake.reset();
    copy("kept by a manager").await.unwrap();
    taken_over("clipboard", "kept by a manager").await;
    set("FAKE_WL_PASTE", "stalls");
    clipboard.forget();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(inflight.count(), 1, "nothing is looking for the manager's copy");
    let hurried = Instant::now();
    inflight.hurry();
    settled(&inflight).await;
    assert!(hurried.elapsed() < Duration::from_millis(300));
    unset("FAKE_WL_PASTE");
}
