//! `omakeepickd serve`: the Unix-socket server.

use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{broadcast, mpsc};

use crate::daemon::Daemon;
use crate::protocol::{ApiError, Header, SecretLines, encode_reply};
use crate::{harden, locker, paths};

/// Holds an exclusive `flock` on the runtime directory's lock file for the daemon's lifetime.
fn single_instance(dir: &std::path::Path) -> std::io::Result<Option<File>> {
    let file = OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("lock"))?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    Ok((rc == 0).then_some(file))
}

pub fn run(detach: bool) -> std::process::ExitCode {
    if detach {
        // Called by `attach`: fork so the caller can reap us immediately, then leave its session.
        match unsafe { libc::fork() } {
            -1 => {
                eprintln!("omakeepickd: fork failed");
                return std::process::ExitCode::FAILURE;
            }
            0 => unsafe {
                libc::setsid();
            },
            _ => unsafe { libc::_exit(0) },
        }
    }
    harden::harden_process();
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("omakeepickd: cannot start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("omakeepickd: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn serve() -> anyhow::Result<()> {
    let dir = paths::runtime_dir();
    paths::ensure_private_dir(&dir)?;
    let Some(_lock) = single_instance(&dir)? else {
        eprintln!("omakeepickd: already running");
        return Ok(());
    };
    let socket = paths::socket_path();
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    eprintln!("omakeepickd {} listening on {}", env!("CARGO_PKG_VERSION"), socket.display());

    let (daemon, mut reloads) = Daemon::new(&paths::state_dir());
    tokio::spawn(locker::idle_loop(daemon.clone()));
    if std::env::var_os("OMAKEEPICK_NO_LOGIND").is_none() {
        tokio::spawn(locker::logind_loop(daemon.clone()));
    }
    {
        let daemon = daemon.clone();
        tokio::spawn(async move {
            while reloads.recv().await.is_some() {
                // Debounce: writers emit several events per save.
                tokio::time::sleep(Duration::from_millis(500)).await;
                while reloads.try_recv().is_ok() {}
                daemon.reload().await;
            }
        });
    }

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let uid = unsafe { libc::getuid() };
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                match stream.peer_cred() {
                    Ok(cred) if cred.uid() == uid => {
                        tokio::spawn(client(daemon.clone(), stream));
                    }
                    _ => eprintln!("omakeepickd: rejected connection from another user"),
                }
            }
            _ = daemon.quit_requested() => break,
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = hangup.recv() => break,
        }
    }
    daemon.lock(crate::daemon::LockReason::Closed);
    let _ = fs::remove_file(&socket);
    // Give client writers a moment to flush the last replies (e.g. to `quit`).
    tokio::time::sleep(Duration::from_millis(100)).await;
    eprintln!("omakeepickd: exiting");
    Ok(())
}

async fn client(daemon: Arc<Daemon>, stream: UnixStream) {
    let (reader, mut writer) = stream.into_split();
    let (replies, mut queued) = mpsc::unbounded_channel::<String>();
    let mut events = daemon.subscribe();
    let first = daemon.state_line();
    let writer_task = tokio::spawn(async move {
        if writer.write_all(first.as_bytes()).await.is_err() {
            return;
        }
        loop {
            let line = tokio::select! {
                Some(line) = queued.recv() => line,
                event = events.recv() => match event {
                    Ok(line) => line,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            };
            if writer.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    let mut lines = SecretLines::new(reader);
    while let Ok(Some(line)) = lines.next_line().await {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let header: Header = match serde_json::from_slice(&line) {
            Ok(h) => h,
            Err(e) => {
                let _ = replies
                    .send(encode_reply(None, Err(ApiError::bad_request(format!("Invalid request: {e}")))));
                continue;
            }
        };
        if Daemon::is_async(&header.cmd) {
            let (daemon, replies) = (daemon.clone(), replies.clone());
            tokio::spawn(async move {
                let reply = daemon.handle_async(&header.cmd, &line).await;
                let _ = replies.send(encode_reply(header.id, reply));
            });
        } else {
            let reply = daemon.handle_sync(&header.cmd, &line);
            let _ = replies.send(encode_reply(header.id, reply));
        }
    }
    // Let in-flight replies drain briefly before closing.
    drop(replies);
    tokio::time::sleep(Duration::from_millis(50)).await;
    writer_task.abort();
}
