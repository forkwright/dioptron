//! Tests for the cancellation signal.

use super::*;

#[tokio::test]
async fn cancelled_completes_after_cancel() {
    let (handle, signal) = cancel_pair();
    assert!(!signal.is_cancelled(), "a fresh signal has not fired");
    handle.cancel();
    signal.cancelled().await;
    assert!(signal.is_cancelled(), "cancel fires the signal");
    handle.cancel();
    assert!(signal.is_cancelled(), "a second cancel keeps it fired");
}

#[tokio::test]
async fn dropping_the_handle_fires_every_clone() {
    let (handle, signal) = cancel_pair();
    let clone = signal.clone();
    drop(handle);
    clone.cancelled().await;
    assert!(signal.is_cancelled(), "a dropped handle cancels");
    assert!(clone.is_cancelled(), "clones observe the same signal");
}
