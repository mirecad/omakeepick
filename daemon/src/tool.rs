//! The programs the daemon hands a secret to: `wtype` types it, `wl-copy` holds it on the
//! clipboard.
//!
//! A [`Tool`] is such a program while it runs. Whatever becomes of the code that started it (it
//! finishes, fails, or is dropped mid-way by a lock), the tool is ended and waited for, and a
//! suspend is held back until it is gone. A [`Feed`] is the pipe to its stdin, which can tell
//! whether the tool has read what was written.

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::unix::pipe;
use tokio::process::{Child, ChildStderr, ChildStdin, Command};
use tokio::runtime::Handle;

use crate::inflight::{Guard, Tracker};

/// How a tool that is no longer wanted is ended.
#[derive(Clone, Copy)]
pub enum Stop {
    /// `SIGKILL`, at once. For `wl-copy`: the value it holds is gone with it.
    Kill,
    /// Left to end on its own, and killed only if it has not by then, or when a suspend can
    /// wait no longer. For `wtype`, which is given little enough at a time to be done at once:
    /// killed between a key press and its release, it would leave that key held down in the
    /// window it was typing into.
    Within(Duration),
}

pub struct Tool {
    /// Taken by `drop`.
    child: Option<Child>,
    stop: Stop,
    /// A directory made for this tool's temporary files. Removed when the tool is gone.
    scratch: Option<PathBuf>,
    guard: Option<Guard>,
    /// Resolves when a suspend can wait no longer. Listened for since the tool was started,
    /// so that the word cannot come before anyone listens.
    hurried: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

fn remove(scratch: Option<PathBuf>) {
    if let Some(dir) = scratch {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// `SIGKILL` to the tool and to whatever it started. `Child::id` is `None` once the tool has
/// been waited for, so a process ID that was given to someone else is never signalled.
fn kill(child: &Child) {
    if let Some(pid) = child.id() {
        unsafe { libc::killpg(pid as libc::pid_t, libc::SIGKILL) };
    }
}

impl Tool {
    /// Starts `command`. It holds a guard of `inflight` until it is gone.
    pub fn spawn(
        mut command: Command,
        stop: Stop,
        scratch: Option<PathBuf>,
        inflight: &Tracker,
    ) -> std::io::Result<Tool> {
        // A process group of its own, so that what it starts (`wl-copy` runs `cat`) ends with
        // it. `kill_on_drop` is the backstop for a runtime that is shutting down.
        command.process_group(0).kill_on_drop(true);
        if matches!(stop, Stop::Kill) {
            // Not outliving the daemon either. A tool that is left to end on its own does so
            // without this: the daemon's end of its stdin closes.
            unsafe {
                command.pre_exec(|| {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                    Ok(())
                });
            }
        }
        match command.spawn() {
            Ok(child) => {
                let guard = inflight.hold();
                let hurried: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(guard.hurried());
                Ok(Tool { child: Some(child), stop, scratch, guard: Some(guard), hurried: Some(hurried) })
            }
            Err(e) => {
                remove(scratch);
                Err(e)
            }
        }
    }

    fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("the child is only taken by drop")
    }

    pub fn stdin(&mut self) -> Option<ChildStdin> {
        self.child().stdin.take()
    }

    pub fn stderr(&mut self) -> Option<ChildStderr> {
        self.child().stderr.take()
    }

    /// Waits for the tool to end. Can be dropped and called again.
    pub async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child().wait().await
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.child().try_wait(), Ok(None))
    }
}

impl Drop for Tool {
    fn drop(&mut self) {
        let (Some(mut child), Some(guard), Some(hurried)) =
            (self.child.take(), self.guard.take(), self.hurried.take())
        else {
            return;
        };
        let scratch = self.scratch.take();
        if child.id().is_none() {
            // Waited for already.
            remove(scratch);
            return;
        }
        let grace = match self.stop {
            Stop::Kill => {
                kill(&child);
                None
            }
            Stop::Within(grace) => Some(grace),
        };
        let reap = async move {
            let ended = match grace {
                Some(grace) => tokio::select! {
                    _ = child.wait() => true,
                    () = tokio::time::sleep(grace) => false,
                    () = hurried => false,
                },
                None => false,
            };
            if !ended {
                kill(&child);
                let _ = child.wait().await;
            }
            remove(scratch);
            drop(guard);
        };
        // Outside a runtime (it is being torn down) the future is dropped right here, and the
        // child with it, which kills it.
        if let Ok(runtime) = Handle::try_current() {
            runtime.spawn(reap);
        }
    }
}

/// How often a [`Feed`] looks whether the tool has read what it was given.
const POLL: Duration = Duration::from_millis(1);

/// The tool ended without reading what it was given.
#[derive(Debug)]
pub struct Ended;

/// The writing end of a tool's stdin.
pub struct Feed {
    /// `None` after [`end`](Self::end).
    writer: Option<pipe::Sender>,
    /// Our own handle on the reading end. Nothing is read through it: it is only asked how much
    /// is still waiting in the pipe.
    watch: OwnedFd,
}

impl Feed {
    /// A new pipe: the feed, and the end to give the tool as its stdin.
    pub fn new() -> std::io::Result<(Feed, Stdio)> {
        let (reader, writer) = std::io::pipe()?;
        let watch = OwnedFd::from(reader.try_clone()?);
        let writer = pipe::Sender::from_owned_fd(OwnedFd::from(writer))?;
        Ok((Feed { writer: Some(writer), watch }, Stdio::from(reader)))
    }

    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        match &mut self.writer {
            Some(writer) => writer.write_all(data).await,
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }

    /// Closes the writing end: the tool reads what is left and then sees the end of its input.
    pub fn end(&mut self) {
        self.writer = None;
    }

    fn unread(&self) -> usize {
        let mut waiting: libc::c_int = 0;
        let rc = unsafe { libc::ioctl(self.watch.as_raw_fd(), libc::FIONREAD, &mut waiting) };
        if rc == 0 { usize::try_from(waiting).unwrap_or(0) } else { 0 }
    }

    /// Waits until `tool` has read everything written so far.
    pub async fn taken(&self, tool: &mut Tool) -> Result<(), Ended> {
        while self.unread() > 0 {
            tokio::select! {
                _ = tool.wait() => return Err(Ended),
                () = tokio::time::sleep(POLL) => {}
            }
        }
        Ok(())
    }
}
