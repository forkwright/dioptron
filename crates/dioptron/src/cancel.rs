//! Cancellation signal shared by the server, the lifecycle, and producers.

use tokio::sync::watch;

/// Creates a linked cancel handle and signal.
///
/// The signal fires when [`CancelHandle::cancel`] is called or when the
/// handle is dropped: a request whose owner is gone (its connection closed,
/// the daemon is shutting down) is cancelled.
///
/// # Examples
///
/// ```
/// let (handle, signal) = dioptron::cancel_pair();
/// assert!(!signal.is_cancelled());
/// handle.cancel();
/// assert!(signal.is_cancelled());
/// ```
#[must_use]
pub fn cancel_pair() -> (CancelHandle, CancelSignal) {
    let (tx, rx) = watch::channel(false);
    (CancelHandle { tx }, CancelSignal { rx })
}

/// The owner's side of a cancellation: fires the linked [`CancelSignal`].
#[derive(Debug)]
pub struct CancelHandle {
    tx: watch::Sender<bool>,
}

impl CancelHandle {
    /// Fires the signal. Idempotent.
    pub fn cancel(&self) {
        self.tx.send_replace(true);
    }
}

/// The worker's side of a cancellation. Cheap to clone; every clone
/// observes the same signal.
#[derive(Clone, Debug)]
pub struct CancelSignal {
    rx: watch::Receiver<bool>,
}

impl CancelSignal {
    /// Whether the signal has fired, or its handle is gone.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow() || self.rx.has_changed().is_err()
    }

    /// Completes when the signal fires or its handle is dropped.
    /// Cancel-safe: dropping this future and calling it again loses
    /// nothing.
    pub async fn cancelled(&self) {
        let mut rx = self.rx.clone();
        // WHY the result is ignored: Ok means the flag was set and Err means
        // the handle was dropped; both are cancellation.
        let _fired = rx.wait_for(|cancelled| *cancelled).await.is_ok();
    }
}

#[cfg(test)]
mod tests;
