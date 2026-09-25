//! Admitted requests: ordering, cancellation, deadlines, in-flight bounds,
//! duplicate ids, idle timeout, and dispatcher failures.

use std::time::Duration;

use syntheke::{Failure, Request, ResponseBody};
use tokio::time::{Instant, sleep};

use super::super::test_support::{
    Behavior, Event, Harness, SHORT, SLACK, TENANT, TestResult, assert_fired, immediate, limits,
    own_uid, request, until_cancel,
};

/// Requests with an even id answer at once; odd ids wait for cancel.
fn odd_waits(request: &Request) -> Behavior {
    if request.request_id.is_multiple_of(2) {
        Behavior::Immediate
    } else {
        Behavior::UntilCancel
    }
}

fn hang(_: &Request) -> Behavior {
    Behavior::Hang
}

fn panics(request: &Request) -> Behavior {
    if request.request_id == 1 {
        Behavior::Panic
    } else {
        Behavior::Immediate
    }
}

fn oversize(_: &Request) -> Behavior {
    Behavior::Oversize
}

#[tokio::test]
async fn dispatcher_receives_the_connection_identity() -> TestResult {
    let mut harness = Harness::start(limits(), immediate)?;
    let mut client = harness.admitted().await?;
    client.request(&request(2, 1_000)).await?;
    let Event::Started { conn, .. } = harness.event().await? else {
        return Err("expected a start".into());
    };
    assert_eq!(conn.tenant, TENANT, "the authenticated tenant");
    assert_eq!(conn.uid, own_uid()?, "the peer uid from the socket");
    assert_eq!(
        conn.pid,
        Some(std::process::id().try_into()?),
        "the peer pid"
    );
    assert_eq!(conn.version, 1, "the negotiated version");
    assert_eq!(conn.max_frame, 1024 * 1024, "the negotiated bound");
    Ok(())
}

#[tokio::test]
async fn responses_arrive_in_completion_order() -> TestResult {
    let mut harness = Harness::start(limits(), odd_waits)?;
    let mut client = harness.admitted().await?;
    client.request(&request(1, 10_000)).await?;
    client.request(&request(2, 10_000)).await?;
    assert_eq!(
        client.response().await?.request_id,
        2,
        "the fast request first"
    );
    client.cancel(1).await?;
    let response = client.response().await?;
    assert_eq!(response.request_id, 1, "then the cancelled one");
    assert_eq!(
        response.body,
        ResponseBody::Failed(Failure::Cancelled),
        "answered by the dispatcher"
    );
    assert!(
        harness
            .events
            .try_recv()
            .is_ok_and(|event| matches!(event, Event::Started { request_id: 1, .. })),
        "request 1 started first"
    );
    Ok(())
}

#[tokio::test]
async fn cancel_frame_fires_the_dispatchers_signal() -> TestResult {
    let mut harness = Harness::start(limits(), until_cancel)?;
    let mut client = harness.admitted().await?;
    client.request(&request(5, 10_000)).await?;
    assert!(
        matches!(harness.event().await?, Event::Started { request_id: 5, .. }),
        "dispatch started"
    );
    client.cancel(5).await?;
    assert_eq!(
        harness.event().await?,
        Event::Cancelled { request_id: 5 },
        "the dispatcher observed the signal"
    );
    let response = client.response().await?;
    assert_eq!(
        response.body,
        ResponseBody::Failed(Failure::Cancelled),
        "cancelled"
    );
    Ok(())
}

#[tokio::test]
async fn cancel_for_an_unknown_id_is_ignored() -> TestResult {
    let harness = Harness::start(limits(), immediate)?;
    let mut client = harness.admitted().await?;
    client.cancel(99).await?;
    client.request(&request(4, 1_000)).await?;
    assert_eq!(
        client.response().await?.request_id,
        4,
        "the connection lives"
    );
    Ok(())
}

#[tokio::test]
async fn hung_dispatcher_is_answered_deadline_exceeded_after_the_grace() -> TestResult {
    let mut short = limits();
    short.dispatch_grace = SHORT;
    let harness = Harness::start(short, hang)?;
    let mut client = harness.admitted().await?;
    let start = Instant::now();
    client.request(&request(3, 200)).await?;
    let response = client.response().await?;
    assert_eq!(response.request_id, 3, "the hung request");
    assert_eq!(
        response.body,
        ResponseBody::Failed(Failure::DeadlineExceeded),
        "deadline exceeded"
    );
    assert_eq!(response.invocation, None, "the server names no invocation");
    assert_fired(
        start.elapsed(),
        SHORT.saturating_add(Duration::from_millis(200)),
        "the deadline plus the dispatch grace",
    );
    Ok(())
}

#[tokio::test]
async fn deadline_is_clamped_to_the_server_maximum() -> TestResult {
    let mut harness = Harness::start(limits(), immediate)?;
    let mut client = harness.admitted().await?;
    for (request_id, deadline_ms, expected) in [
        (2, u32::MAX, Duration::from_secs(30)),
        (4, 1_500, Duration::from_millis(1_500)),
        (6, 0, Duration::ZERO),
    ] {
        client.request(&request(request_id, deadline_ms)).await?;
        let Event::Started { remaining, .. } = harness.event().await? else {
            return Err("expected a start".into());
        };
        // The dispatcher measures a moment after the server set the
        // deadline, so it sees at most `expected` and not much less.
        assert!(
            remaining <= expected,
            "deadline for {deadline_ms} ms not above {expected:?}"
        );
        assert!(
            remaining.saturating_add(SLACK) >= expected,
            "deadline for {deadline_ms} ms near {expected:?}, got {remaining:?}"
        );
        client.response().await?;
    }
    Ok(())
}

#[tokio::test]
async fn duplicate_in_flight_request_id_is_a_protocol_error() -> TestResult {
    let mut harness = Harness::start(limits(), until_cancel)?;
    let mut client = harness.admitted().await?;
    client.request(&request(1, 10_000)).await?;
    client.request(&request(1, 10_000)).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "duplicate id");
    assert!(
        matches!(harness.event().await?, Event::Started { request_id: 1, .. }),
        "the first started"
    );
    assert_eq!(
        harness.event().await?,
        Event::Cancelled { request_id: 1 },
        "closing the connection cancels it"
    );
    Ok(())
}

#[tokio::test]
async fn request_id_is_reusable_after_its_response() -> TestResult {
    let harness = Harness::start(limits(), immediate)?;
    let mut client = harness.admitted().await?;
    for _ in 0..3 {
        client.request(&request(8, 1_000)).await?;
        assert_eq!(client.response().await?.request_id, 8, "answered");
    }
    Ok(())
}

#[tokio::test]
async fn exceeding_the_in_flight_bound_is_a_protocol_error() -> TestResult {
    let mut bounded = limits();
    bounded.max_in_flight = 2;
    let mut harness = Harness::start(bounded, until_cancel)?;
    let mut client = harness.admitted().await?;
    for request_id in 1..=3 {
        client.request(&request(request_id, 10_000)).await?;
    }
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(
        failure,
        Failure::ProtocolError,
        "third request over the bound"
    );
    let mut started = Vec::new();
    let mut cancelled = Vec::new();
    for _ in 0..4 {
        match harness.event().await? {
            Event::Started { request_id, .. } => started.push(request_id),
            Event::Cancelled { request_id } => cancelled.push(request_id),
        }
    }
    started.sort_unstable();
    cancelled.sort_unstable();
    assert_eq!(started, [1, 2], "only two dispatches started");
    assert_eq!(cancelled, [1, 2], "both were cancelled at close");
    Ok(())
}

#[tokio::test]
async fn idle_connection_is_closed_without_a_fault() -> TestResult {
    let mut short = limits();
    short.idle_timeout = SHORT;
    let harness = Harness::start(short, immediate)?;
    let mut client = harness.admitted().await?;
    let start = Instant::now();
    client.expect_closed().await?;
    assert_fired(start.elapsed(), SHORT, "the idle bound");
    Ok(())
}

#[tokio::test]
async fn in_flight_request_holds_off_the_idle_timeout() -> TestResult {
    let mut short = limits();
    short.idle_timeout = SHORT;
    let harness = Harness::start(short, until_cancel)?;
    let mut client = harness.admitted().await?;
    client.request(&request(1, 20_000)).await?;
    sleep(SHORT.saturating_mul(3)).await;
    client.cancel(1).await?;
    let response = client.response().await?;
    assert_eq!(
        response.body,
        ResponseBody::Failed(Failure::Cancelled),
        "the connection outlived twice the idle bound"
    );
    Ok(())
}

#[tokio::test]
async fn panicking_dispatcher_is_answered_unknown_effect() -> TestResult {
    let harness = Harness::start(limits(), panics)?;
    let mut client = harness.admitted().await?;
    client.request(&request(1, 1_000)).await?;
    let response = client.response().await?;
    assert_eq!(
        response.body,
        ResponseBody::Failed(Failure::UnknownEffect),
        "an effect cannot be ruled out"
    );
    client.request(&request(2, 1_000)).await?;
    assert_eq!(
        client.response().await?.request_id,
        2,
        "the connection lives"
    );
    Ok(())
}

#[tokio::test]
async fn response_over_the_negotiated_bound_closes_with_a_fault() -> TestResult {
    let mut small = limits();
    small.max_frame = 4096;
    let harness = Harness::start(small, oversize)?;
    let mut client = harness.admitted().await?;
    client.request(&request(1, 1_000)).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(
        failure,
        Failure::ProtocolError,
        "the server never sends over the bound"
    );
    Ok(())
}

#[tokio::test]
async fn fault_close_does_not_wait_for_hung_work() -> TestResult {
    let mut patient = limits();
    patient.dispatch_grace = Duration::from_secs(30);
    let harness = Harness::start(patient, hang)?;
    let mut client = harness.admitted().await?;
    client.request(&request(1, 20_000)).await?;
    let start = Instant::now();
    client.request(&request(1, 20_000)).await?;
    let (_, failure) = client.fault_then_close().await?;
    assert_eq!(failure, Failure::ProtocolError, "duplicate id");
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "end of stream follows the fault, not the 30 s drain"
    );
    Ok(())
}
