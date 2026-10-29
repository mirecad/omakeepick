//! Automatic locking: idle timeout, suspend/hibernate and logind session lock.
//!
//! Before sleep the database is locked and the quick-unlock key wiped while holding a logind
//! "delay" inhibitor, so nothing decrypted is left in RAM (or in the hibernation image).

use std::sync::Arc;

use futures_util::StreamExt;
use zbus::{Connection, OwnedFd, OwnedObjectPath, proxy};

use crate::daemon::{Daemon, LockReason};

pub async fn idle_loop(daemon: Arc<Daemon>) {
    loop {
        match daemon.idle_deadline() {
            Some(deadline) => {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline.into()) => {
                        if daemon.idle_deadline().is_some_and(|d| d <= std::time::Instant::now()) {
                            daemon.lock(LockReason::Idle);
                        }
                    }
                    _ = daemon.idle_changed() => {}
                }
            }
            None => daemon.idle_changed().await,
        }
    }
}

#[proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Manager {
    fn inhibit(&self, what: &str, who: &str, why: &str, mode: &str) -> zbus::Result<OwnedFd>;
    fn get_session(&self, session_id: &str) -> zbus::Result<OwnedObjectPath>;
    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
}

#[proxy(interface = "org.freedesktop.login1.Session", default_service = "org.freedesktop.login1")]
trait Session {
    #[zbus(signal)]
    fn lock(&self) -> zbus::Result<()>;
}

async fn inhibit(manager: &ManagerProxy<'_>) -> Option<OwnedFd> {
    manager
        .inhibit("sleep", "OmaKeePick", "Lock the KeePass database before sleep", "delay")
        .await
        .map_err(|e| eprintln!("omakeepickd: no sleep inhibitor: {e}"))
        .ok()
}

pub async fn logind_loop(daemon: Arc<Daemon>) {
    if let Err(e) = watch_logind(daemon).await {
        eprintln!("omakeepickd: logind unavailable, not locking on suspend: {e}");
    }
}

async fn watch_logind(daemon: Arc<Daemon>) -> zbus::Result<()> {
    let conn = Connection::system().await?;
    let manager = ManagerProxy::new(&conn).await?;
    let mut sleeps = manager.receive_prepare_for_sleep().await?;

    let session_locks = {
        let daemon = daemon.clone();
        let conn = conn.clone();
        let manager = manager.clone();
        async move {
            // Not by PID: under uwsm the shell, and so this daemon, runs in a user service
            // outside the login session's scope. `auto` is the caller's session if it has one,
            // else the user's graphical session.
            let path = manager.get_session("auto").await?;
            let session = SessionProxy::builder(&conn).path(path).build().await?;
            let mut locks = session.receive_lock().await?;
            while locks.next().await.is_some() {
                daemon.lock(LockReason::Screen);
            }
            zbus::Result::Ok(())
        }
    };
    tokio::spawn(async move {
        // A user without a graphical session (e.g. only logged in over SSH) has none; that's fine.
        if let Err(e) = session_locks.await {
            eprintln!("omakeepickd: not watching logind session lock: {e}");
        }
    });

    let mut inhibitor = inhibit(&manager).await;
    while let Some(signal) = sleeps.next().await {
        let Ok(args) = signal.args() else { continue };
        if args.start {
            daemon.lock(LockReason::Sleep);
            // Releasing the inhibitor lets the system go to sleep.
            inhibitor = None;
        } else if inhibitor.is_none() {
            inhibitor = inhibit(&manager).await;
        }
    }
    drop(inhibitor);
    Ok(())
}
