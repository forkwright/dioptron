//! Socket binding, the connection bound, limits, and shutdown.

use std::fs;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::os::unix::net::UnixListener as StdListener;
use std::path::Path;
use std::time::Duration;

use rustix::process::{Signal, getpid, kill_process};
use syntheke::{Failure, ResponseBody};
use tokio::signal::unix::SignalKind;
use tokio::time::sleep;

use super::super::test_support::{
    Behavior, Event, Harness, SHORT, StaticDirectory, TestDispatcher, TestResult, assert_fired,
    directory, immediate, limits, request, until_cancel,
};
use super::super::{Limits, Server, listen, shutdown_signal};
use crate::Error;

/// Binds a server at `path` with a dispatcher nobody observes. The outer
/// result is the harness; the inner one is the bind under test.
fn bind(path: &Path) -> TestResult<Result<Server<StaticDirectory, TestDispatcher>, Error>> {
    let (events, _unobserved) = tokio::sync::mpsc::unbounded_channel();
    Ok(Server::bind(
        path,
        limits(),
        directory()?,
        TestDispatcher::new(events, immediate),
    ))
}

/// A private directory with mode 0700.
fn private_dir() -> TestResult<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

#[tokio::test]
async fn socket_is_mode_0600_in_a_created_0700_directory() -> TestResult {
    let harness = Harness::start(limits(), immediate)?;
    let socket = fs::symlink_metadata(&harness.path)?.permissions().mode();
    assert_eq!(socket & 0o777, 0o600, "socket mode");
    let dir = harness.path.parent().ok_or("socket has a parent")?;
    let dir_mode = fs::symlink_metadata(dir)?.permissions().mode();
    assert_eq!(dir_mode & 0o777, 0o700, "created directory mode");
    Ok(())
}

#[tokio::test]
async fn bind_refuses_a_path_without_a_parent() -> TestResult {
    for path in ["dioptron.sock", "/"] {
        let result = bind(Path::new(path))?;
        assert!(
            matches!(result, Err(Error::NoSocketParent { .. })),
            "{path} names no parent"
        );
    }
    Ok(())
}

#[tokio::test]
async fn bind_reports_a_directory_it_cannot_create() -> TestResult {
    let dir = private_dir()?;
    let path = dir.path().join("missing").join("run").join("s.sock");
    assert!(
        matches!(bind(&path)?, Err(Error::SocketDir { .. })),
        "the grandparent does not exist"
    );
    Ok(())
}

#[tokio::test]
async fn bind_refuses_an_open_or_non_directory_parent() -> TestResult {
    let dir = private_dir()?;
    let open = dir.path().join("open");
    fs::DirBuilder::new().mode(0o755).create(&open)?;
    fs::set_permissions(&open, fs::Permissions::from_mode(0o755))?;
    assert!(
        matches!(
            bind(&open.join("s.sock"))?,
            Err(Error::InsecureSocketDir { mode, .. }) if mode & 0o777 == 0o755
        ),
        "group and other bits refused"
    );

    let file = dir.path().join("file");
    fs::write(&file, b"")?;
    assert!(
        matches!(
            bind(&file.join("s.sock"))?,
            Err(Error::InsecureSocketDir { .. })
        ),
        "a regular file is not a directory"
    );

    let link = dir.path().join("link");
    let target = dir.path().join("target");
    fs::DirBuilder::new().mode(0o700).create(&target)?;
    std::os::unix::fs::symlink(&target, &link)?;
    assert!(
        matches!(
            bind(&link.join("s.sock"))?,
            Err(Error::InsecureSocketDir { .. })
        ),
        "a symlinked directory is refused"
    );
    Ok(())
}

#[tokio::test]
async fn bind_refuses_a_path_occupied_by_a_non_socket() -> TestResult {
    let dir = private_dir()?;
    let path = dir.path().join("s.sock");
    fs::write(&path, b"not a socket")?;
    assert!(
        matches!(bind(&path)?, Err(Error::SocketPathOccupied { .. })),
        "a regular file"
    );
    assert_eq!(fs::read(&path)?, b"not a socket", "left untouched");
    Ok(())
}

#[tokio::test]
async fn bind_refuses_a_socket_with_a_live_listener() -> TestResult {
    let dir = private_dir()?;
    let path = dir.path().join("s.sock");
    let _live = StdListener::bind(&path)?;
    assert!(
        matches!(bind(&path)?, Err(Error::SocketInUse { .. })),
        "another daemon is listening"
    );
    Ok(())
}

#[tokio::test]
async fn bind_replaces_a_provably_stale_socket() -> TestResult {
    let dir = private_dir()?;
    let path = dir.path().join("s.sock");
    drop(StdListener::bind(&path)?);
    assert!(path.exists(), "the stale socket file remains");
    let server = bind(&path)??;
    assert_eq!(server.path(), path, "bound at the same path");
    let mode = fs::symlink_metadata(&path)?.permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "the new socket is restricted");
    Ok(())
}

#[tokio::test]
async fn bind_reports_a_path_it_cannot_inspect() -> TestResult {
    let dir = private_dir()?;
    let path = dir.path().join("x".repeat(300));
    assert!(
        matches!(bind(&path)?, Err(Error::InspectSocket { .. })),
        "a file name over the filesystem limit"
    );
    Ok(())
}

#[tokio::test]
async fn bind_reports_a_socket_path_too_long_to_bind() -> TestResult {
    let dir = private_dir()?;
    let nested = dir.path().join("d".repeat(100));
    fs::DirBuilder::new().mode(0o700).create(&nested)?;
    let path = nested.join("s.sock");
    assert!(
        matches!(bind(&path)?, Err(Error::Bind { .. })),
        "longer than a socket address holds"
    );
    Ok(())
}

#[tokio::test]
async fn forbidden_signal_reports_a_signal_error() {
    assert!(
        matches!(listen(SignalKind::from_raw(9)), Err(Error::Signal { .. })),
        "SIGKILL cannot be handled"
    );
}

#[tokio::test]
async fn shutdown_signal_completes_on_sigterm() -> TestResult {
    // WHY install first: once a handler is registered, SIGTERM no longer
    // terminates the test process, whatever the task below has reached.
    let _guard = listen(SignalKind::terminate())?;
    let waiter = tokio::spawn(shutdown_signal());
    tokio::task::yield_now().await;
    kill_process(getpid(), Signal::TERM)?;
    tokio::time::timeout(Duration::from_secs(30), waiter).await???;
    Ok(())
}

#[test]
fn default_limits_stay_within_the_memory_budget() {
    // 16 connections × (10 in flight + 6 per-connection frames) × 1 MiB,
    // computed independently of the helper.
    let expected: u64 = 16 * (10 + 6) * 1024 * 1024;
    assert_eq!(Limits::default().worst_case_bytes(), expected, "formula");
    assert_eq!(expected, 256 * 1024 * 1024, "exactly the budget");
    assert!(
        Limits::default().worst_case_bytes() <= Limits::DEFAULT_MEMORY_BUDGET,
        "defaults within the documented budget"
    );
    assert_eq!(
        Limits::default().max_frame,
        1024 * 1024,
        "the contract's default negotiated bound is kept"
    );
}

#[test]
fn worst_case_bytes_uses_clamped_limits_and_saturates() {
    let huge = Limits {
        max_connections: usize::MAX,
        max_in_flight: usize::MAX,
        max_frame: u32::MAX,
        ..Limits::default()
    };
    assert_eq!(huge.worst_case_bytes(), u64::MAX, "saturates, never wraps");
    let zero = Limits {
        max_connections: 0,
        max_in_flight: 0,
        max_frame: 0,
        ..Limits::default()
    };
    assert_eq!(
        zero.worst_case_bytes(),
        (1 + 6) * 4096,
        "one connection, one request, the 4 KiB floor"
    );
}

#[tokio::test]
async fn bind_refuses_a_directory_another_server_holds() -> TestResult {
    let dir = private_dir()?;
    let first = bind(&dir.path().join("a.sock"))??;
    for name in ["a.sock", "b.sock"] {
        assert!(
            matches!(
                bind(&dir.path().join(name))?,
                Err(Error::SocketInUse { .. })
            ),
            "{name}: the directory lock is held"
        );
    }
    assert!(
        dir.path().join("a.sock").exists(),
        "the holder's socket is untouched"
    );
    drop(first);
    fs::remove_file(dir.path().join("a.sock"))?;
    let second = bind(&dir.path().join("b.sock"))??;
    assert_eq!(second.path(), dir.path().join("b.sock"), "lock released");
    Ok(())
}

#[test]
fn limits_are_clamped_into_their_ranges() {
    let mut wild = Limits {
        max_connections: 0,
        max_in_flight: 0,
        handshake_timeout: Duration::from_mins(1),
        idle_timeout: Duration::MAX,
        max_frame: 0,
        ..Limits::default()
    };
    let clamped = wild.clamped();
    assert_eq!(clamped.max_connections, 1, "at least one connection");
    assert_eq!(clamped.max_in_flight, 1, "at least one request");
    assert_eq!(
        clamped.handshake_timeout,
        Duration::from_secs(5),
        "contract bound"
    );
    assert_eq!(
        clamped.idle_timeout,
        Duration::from_hours(24),
        "overflow guard"
    );
    assert_eq!(clamped.max_frame, 4096, "at least the pre-auth bound");
    wild.max_frame = u32::MAX;
    assert_eq!(
        wild.clamped().max_frame,
        4 * 1024 * 1024,
        "the hard maximum"
    );
    assert_eq!(
        Limits::default().clamped(),
        Limits::default(),
        "defaults are valid"
    );
}

#[tokio::test]
async fn connections_over_the_bound_are_closed_at_once() -> TestResult {
    let mut one = limits();
    one.max_connections = 1;
    let harness = Harness::start(one, immediate)?;
    let first = harness.admitted().await?;
    let mut refused = harness.connect().await?;
    refused.expect_closed().await?;

    drop(first);
    // WHY retry: the first connection's task releases its permit after it
    // reads end of stream, which races this reconnect. Until then the
    // server closes new connections at once, as asserted above. The bound
    // on retries is generous so a loaded machine does not fail the test.
    let give_up = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or("clock overflow")?;
    let mut next = loop {
        if let Ok(client) = harness.admitted().await {
            break client;
        }
        if tokio::time::Instant::now() >= give_up {
            return Err("the permit never came back".into());
        }
        sleep(Duration::from_millis(10)).await;
    };
    next.request(&request(2, 1_000)).await?;
    assert_eq!(next.response().await?.request_id, 2, "the permit came back");
    Ok(())
}

#[tokio::test]
async fn shutdown_cancels_in_flight_work_and_removes_the_socket() -> TestResult {
    let mut harness = Harness::start(limits(), until_cancel)?;
    let mut client = harness.admitted().await?;
    client.request(&request(1, 10_000)).await?;
    assert!(
        matches!(harness.event().await?, Event::Started { request_id: 1, .. }),
        "dispatch started"
    );
    harness.shutdown().await?;
    assert_eq!(
        harness.event().await?,
        Event::Cancelled { request_id: 1 },
        "shutdown fired the signal"
    );
    let response = client.response().await?;
    assert_eq!(
        response.body,
        ResponseBody::Failed(Failure::Cancelled),
        "the cancelled response is still delivered"
    );
    client.expect_closed().await?;
    assert!(!harness.path.exists(), "the socket file is removed");
    Ok(())
}

#[tokio::test]
async fn shutdown_is_bounded_when_a_dispatcher_hangs() -> TestResult {
    let mut short = limits();
    short.dispatch_grace = SHORT;
    let mut harness = Harness::start(short, |_| Behavior::Hang)?;
    let mut client = harness.admitted().await?;
    client.request(&request(1, 20_000)).await?;
    harness.event().await?;
    let start = tokio::time::Instant::now();
    harness.shutdown().await?;
    assert_fired(
        start.elapsed(),
        SHORT,
        "the connection waits one dispatch grace, then aborts",
    );
    client.expect_closed().await
}
