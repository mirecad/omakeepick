//! Counting what still has secrets in hand outside the daemon's core.
//!
//! A lock wipes the core at once. What it cannot reach directly is counted here: a request
//! that is still unwinding, a helper or a tool that was told to stop and is not gone yet. A
//! suspend is held back until the count is zero (see `Daemon::lock_and_settle`).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{Notify, watch};

struct Shared {
    count: AtomicUsize,
    settled: Notify,
    /// Counts the calls of [`Tracker::hurry`].
    hurries: watch::Sender<u64>,
}

/// Hands out guards and knows when the last one is gone.
#[derive(Clone)]
pub struct Tracker(Arc<Shared>);

impl Default for Tracker {
    fn default() -> Self {
        Tracker(Arc::new(Shared {
            count: AtomicUsize::new(0),
            settled: Notify::new(),
            hurries: watch::Sender::new(0),
        }))
    }
}

/// Counts one holder for as long as it exists.
pub struct Guard(Arc<Shared>);

impl Tracker {
    pub fn hold(&self) -> Guard {
        self.0.count.fetch_add(1, Ordering::SeqCst);
        Guard(self.0.clone())
    }

    pub fn count(&self) -> usize {
        self.0.count.load(Ordering::SeqCst)
    }

    /// Says that time is up: whatever was being given a moment to end by itself (see
    /// [`Guard::hurried`]) is to be ended now.
    pub fn hurry(&self) {
        self.0.hurries.send_modify(|hurries| *hurries += 1);
    }

    /// Resolves once nothing is held.
    pub async fn settled(&self) {
        loop {
            let waiting = self.0.settled.notified();
            if self.count() == 0 {
                return;
            }
            waiting.await;
        }
    }
}

impl Guard {
    /// Resolves at the next [`Tracker::hurry`].
    pub fn hurried(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut hurries = self.0.hurries.subscribe();
        async move {
            let _ = hurries.changed().await;
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.settled.notify_waiters();
        }
    }
}
