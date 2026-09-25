#![expect(clippy::expect_used, reason = "test assertions must fail loudly")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use syntheke::{CaptureLimits, ExtractionClass, InvocationId, TransferClass};
use tokio::time::Instant;

use super::{FixtureProducer, Script, call_log_for};
use crate::Error;
use crate::cancel::cancel_pair;
use crate::producer::{AcquireRequest, Producer as _, ProducerError};

const SCRIPT: &str = "# fixture script
https://example.com/ok\tdeliver\tenvelope.bin\tzetesis.evidence.v1\tfixture-1\tfp-ok\ttext.txt
https://example.com/late\tdeliver-on-cancel\tenvelope.bin\tzetesis.evidence.v1\tfixture-1\tfp-late\t-
https://example.com/down\tunavailable\tfalse
https://example.com/reset\ttransfer\tReset
https://example.com/bad\textraction\tMalformed
https://example.com/stall\tstall\ttrue
";

/// Writes the script and its files into a fresh directory.
fn scripted(dir: &Path, script: &str) -> PathBuf {
    std::fs::write(dir.join("envelope.bin"), b"<html>fixture envelope</html>").expect("write");
    std::fs::write(dir.join("text.txt"), "fixture text").expect("write");
    let path = dir.join("script.tsv");
    std::fs::write(&path, script).expect("write");
    path
}

fn request(target: &str, limits: CaptureLimits) -> AcquireRequest {
    AcquireRequest::new(InvocationId::from_bytes([7; 16]), target, limits)
}

fn soon() -> Instant {
    Instant::now()
        .checked_add(Duration::from_secs(30))
        .expect("deadline")
}

#[tokio::test]
async fn load_replays_each_scripted_outcome() {
    let dir = tempfile::tempdir().expect("tempdir");
    let producer = FixtureProducer::load(&scripted(dir.path(), SCRIPT)).expect("load");
    let (_handle, signal) = cancel_pair();
    let limits = CaptureLimits::default();

    let ok = producer
        .acquire(
            request("https://example.com/ok", limits),
            signal.clone(),
            soon(),
        )
        .await
        .expect("deliver");
    let down = producer
        .acquire(
            request("https://example.com/down", limits),
            signal.clone(),
            soon(),
        )
        .await;
    let reset = producer
        .acquire(
            request("https://example.com/reset", limits),
            signal.clone(),
            soon(),
        )
        .await;
    let bad = producer
        .acquire(
            request("https://example.com/bad", limits),
            signal.clone(),
            soon(),
        )
        .await;
    let unscripted = producer
        .acquire(request("https://example.com/none", limits), signal, soon())
        .await;

    assert_eq!(
        ok.envelope, b"<html>fixture envelope</html>",
        "verbatim envelope"
    );
    assert_eq!(ok.fingerprint, "fp-ok", "fingerprint from the script");
    assert_eq!(ok.text_view.as_deref(), Some("fixture text"), "text view");
    assert_eq!(
        down,
        Err(ProducerError::Unavailable { contacted: false }),
        "down"
    );
    assert_eq!(
        reset,
        Err(ProducerError::Transfer {
            class: TransferClass::Reset
        }),
        "transfer class"
    );
    assert_eq!(
        bad,
        Err(ProducerError::Extraction {
            class: ExtractionClass::Malformed
        }),
        "extraction class"
    );
    assert_eq!(
        unscripted,
        Err(ProducerError::Unavailable { contacted: false }),
        "an unscripted target is unavailable"
    );
    assert_eq!(producer.calls(), 5, "every call is counted");
}

#[tokio::test]
async fn stall_and_deliver_on_cancel_wait_for_the_signal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let producer = FixtureProducer::load(&scripted(dir.path(), SCRIPT)).expect("load");
    let limits = CaptureLimits::default();
    let (handle, signal) = cancel_pair();
    handle.cancel();

    let stall = producer
        .acquire(
            request("https://example.com/stall", limits),
            signal.clone(),
            soon(),
        )
        .await;
    let late = producer
        .acquire(request("https://example.com/late", limits), signal, soon())
        .await
        .expect("deliver after cancel");

    assert_eq!(
        stall,
        Err(ProducerError::Cancelled {
            effect_started: true
        }),
        "a stall reports the scripted effect"
    );
    assert_eq!(late.fingerprint, "fp-late", "the late output arrives");
}

#[tokio::test]
async fn stall_ends_at_the_deadline() {
    let producer = FixtureProducer::new().with(
        "https://example.com/stall",
        Script::Stall {
            effect_started: false,
        },
    );
    let (_handle, signal) = cancel_pair();

    let result = producer
        .acquire(
            request("https://example.com/stall", CaptureLimits::default()),
            signal,
            Instant::now(),
        )
        .await;

    assert_eq!(
        result,
        Err(ProducerError::Cancelled {
            effect_started: false
        }),
        "a passed deadline stops the stall"
    );
}

#[tokio::test]
async fn envelope_over_the_transfer_limit_is_too_large() {
    let dir = tempfile::tempdir().expect("tempdir");
    let producer = FixtureProducer::load(&scripted(dir.path(), SCRIPT)).expect("load");
    let (_handle, signal) = cancel_pair();
    let limits = CaptureLimits {
        max_output_bytes: None,
        max_transfer_bytes: Some(4),
    };

    let result = producer
        .acquire(request("https://example.com/ok", limits), signal, soon())
        .await;

    assert_eq!(
        result,
        Err(ProducerError::Transfer {
            class: TransferClass::TooLarge
        }),
        "the producer stops at the caller's transfer bound"
    );
}

#[tokio::test]
async fn call_log_gets_one_line_per_call() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("calls");
    let producer = FixtureProducer::new().with_call_log(&log);
    let (_handle, signal) = cancel_pair();
    let limits = CaptureLimits::default();

    for _ in 0..3 {
        let _result = producer
            .acquire(
                request("https://example.com/x", limits),
                signal.clone(),
                soon(),
            )
            .await;
    }

    let text = std::fs::read_to_string(&log).expect("log");
    assert_eq!(text.lines().count(), 3, "three calls, three lines");
}

#[test]
fn load_rejects_malformed_lines() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases = [
        "https://example.com/a\n",
        "https://example.com/a\tfetch\tx\n",
        "https://example.com/a\tunavailable\tmaybe\n",
        "https://example.com/a\ttransfer\tSlow\n",
        "https://example.com/a\textraction\tSlow\n",
        "https://example.com/a\tdeliver\tmissing.bin\ts\tr\tf\t-\n",
        "https://example.com/a\tdeliver\tenvelope.bin\ts\tr\n",
        "https://example.com/a\tstall\n",
    ];

    for case in cases {
        let path = scripted(dir.path(), case);
        let error = FixtureProducer::load(&path).expect_err("malformed");
        assert!(
            matches!(error, Error::FixtureSyntax { line: 1, .. }),
            "{case:?} is a syntax error on line 1: {error:?}"
        );
    }
}

#[test]
fn load_reports_a_missing_script() {
    let dir = tempfile::tempdir().expect("tempdir");

    let error = FixtureProducer::load(&dir.path().join("absent.tsv")).expect_err("missing");

    assert!(
        matches!(error, Error::FixtureIo { .. }),
        "a missing script is an I/O error: {error:?}"
    );
}

#[test]
fn call_log_sits_next_to_the_script() {
    let log = call_log_for(Path::new("/srv/fixtures/script.tsv")).expect("path");
    let error = call_log_for(Path::new("/")).expect_err("no file name");

    assert_eq!(log, Path::new("/srv/fixtures/script.tsv.calls"), "suffix");
    assert!(
        matches!(error, Error::FixtureSyntax { line: 0, .. }),
        "a path with no file is refused: {error:?}"
    );
}
