use syntheke::{CaptureLimits, ExtractionClass, InvocationId, SourceRef, TransferClass};
use tokio::time::Instant;

use super::{AcquireRequest, Producer as _, ProducerError, ProducerOutput, UnavailableProducer};
use crate::cancel::cancel_pair;

fn source() -> SourceRef {
    SourceRef {
        fingerprint: "fp-1".to_owned(),
        schema_id: "zetesis.evidence.v1".to_owned(),
        producer_revision: "fixture-1".to_owned(),
    }
}

#[tokio::test]
async fn unavailable_producer_reports_never_contacted() {
    let (_handle, signal) = cancel_pair();
    let request = AcquireRequest::new(
        InvocationId::from_bytes([1; 16]),
        "https://example.com/",
        CaptureLimits::default(),
    );

    let result = UnavailableProducer
        .acquire(request, signal, Instant::now())
        .await;

    assert_eq!(
        result,
        Err(ProducerError::Unavailable { contacted: false }),
        "the default producer never reaches anything"
    );
}

#[test]
fn effect_started_follows_each_variant() {
    let cases = [
        (ProducerError::Unavailable { contacted: false }, false),
        (ProducerError::Unavailable { contacted: true }, true),
        (
            ProducerError::Transfer {
                class: TransferClass::Reset,
            },
            true,
        ),
        (
            ProducerError::Extraction {
                class: ExtractionClass::Malformed,
            },
            true,
        ),
        (
            ProducerError::Cancelled {
                effect_started: false,
            },
            false,
        ),
        (
            ProducerError::Cancelled {
                effect_started: true,
            },
            true,
        ),
    ];

    for (error, started) in cases {
        assert_eq!(error.effect_started(), started, "effect of {error:?}");
        assert!(!error.to_string().is_empty(), "{error:?} displays");
    }
}

#[test]
fn output_source_round_trips_the_evidence_identity() {
    let output = ProducerOutput::new(b"envelope".to_vec(), source(), Some("text".to_owned()));

    assert_eq!(output.source(), source(), "the evidence identity is kept");
    assert_eq!(output.envelope, b"envelope", "the envelope is verbatim");
}
