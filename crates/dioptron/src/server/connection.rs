//! One connection: handshake, then the admitted request loop.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use syntheke::{
    Cancel, Failure, FrameKind, Request, Response, ResponseBody, decode_frame, encode_frame,
};
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, watch};
use tokio::task::{Id, JoinError, JoinSet};
use tokio::time::{Instant, sleep_until, timeout, timeout_at};
use tracing::{Instrument as _, debug, field, info_span, warn};

use super::frame::{after, fault_frame, read_frame, write_frame};
use super::handshake::{Admission, handshake};
use super::{Close, ConnIdentity, Dispatcher, Shared, TenantDirectory};
use crate::cancel::{CancelHandle, cancel_pair};

/// A frame an admitted client may send.
enum Inbound {
    Request(Box<Request>),
    Cancel(Cancel),
}

/// Serves one accepted connection to completion.
pub(super) async fn serve<T, D>(
    stream: UnixStream,
    shared: Arc<Shared<T, D>>,
    shutdown: watch::Receiver<bool>,
) where
    T: TenantDirectory,
    D: Dispatcher,
{
    let credentials = match stream.peer_cred() {
        Ok(credentials) => credentials,
        Err(error) => {
            warn!(%error, "peer credentials unavailable; closing");
            return;
        }
    };
    let uid = credentials.uid();
    let pid = credentials.pid();
    let span = info_span!("connection", uid, pid, tenant = field::Empty);
    run(stream, uid, pid, shared, shutdown)
        .instrument(span)
        .await;
}

async fn run<T, D>(
    mut stream: UnixStream,
    uid: u32,
    pid: Option<i32>,
    shared: Arc<Shared<T, D>>,
    mut shutdown: watch::Receiver<bool>,
) where
    T: TenantDirectory,
    D: Dispatcher,
{
    let limits = shared.limits;
    let outcome = tokio::select! {
        result = timeout(
            limits.handshake_timeout,
            handshake(
                &mut stream,
                uid,
                &limits,
                &shared.directory,
                &shared.authenticator,
            ),
        ) => result,
        () = stopped(&mut shutdown) => return,
    };
    let admission = match outcome {
        Ok(Ok(admission)) => admission,
        Ok(Err(close)) => return close_handshake(stream, &close, limits.frame_timeout).await,
        Err(_elapsed) => {
            let close = Close::Fault(Failure::ProtocolError, "handshake timed out");
            return close_handshake(stream, &close, limits.frame_timeout).await;
        }
    };
    tracing::Span::current().record("tenant", field::display(admission.tenant));
    debug!(version = admission.version, "admitted");
    let identity = identity(admission, uid, pid, limits.max_frame);
    Admitted::new(identity, shared).run(stream, shutdown).await;
}

fn identity(admission: Admission, uid: u32, pid: Option<i32>, max_frame: u32) -> ConnIdentity {
    ConnIdentity {
        tenant: admission.tenant,
        uid,
        pid,
        version: admission.version,
        max_frame,
    }
}

/// Logs why a handshake ended and sends its single fault frame, if any.
async fn close_handshake(mut stream: UnixStream, close: &Close, write_timeout: Duration) {
    close.log();
    if let Some(bytes) = close.fault().and_then(fault_frame) {
        // WHY ignored: the connection closes either way; a peer that
        // stopped reading loses only its own fault frame.
        let _sent = write_frame(&mut stream, &bytes, write_timeout).await;
    }
}

/// State of an admitted connection. Owned by one task; dispatch tasks
/// report back only through the join set.
struct Admitted<T, D> {
    identity: ConnIdentity,
    shared: Arc<Shared<T, D>>,
    in_flight: HashMap<u64, CancelHandle>,
    task_ids: HashMap<Id, u64>,
    tasks: JoinSet<Response>,
    last_activity: Instant,
}

impl<T, D> Admitted<T, D>
where
    T: TenantDirectory,
    D: Dispatcher,
{
    fn new(identity: ConnIdentity, shared: Arc<Shared<T, D>>) -> Self {
        Self {
            identity,
            shared,
            in_flight: HashMap::new(),
            task_ids: HashMap::new(),
            tasks: JoinSet::new(),
            last_activity: Instant::now(),
        }
    }

    async fn run(mut self, stream: UnixStream, mut shutdown: watch::Receiver<bool>) {
        let limits = self.shared.limits;
        let (reader, mut writer) = stream.into_split();
        // WHY capacity 1: the reader holds at most one decoded frame ahead
        // of this loop, so a fast sender cannot queue unbounded work.
        let (inbound_tx, mut inbound) = mpsc::channel(1);
        // WHY a join set: dropping it aborts the reader, so the reader
        // cannot outlive this task even when the server aborts it.
        let mut reader_task = JoinSet::new();
        reader_task.spawn(
            read_loop(reader, limits.max_frame, limits.frame_timeout, inbound_tx).in_current_span(),
        );
        let close = loop {
            let idle_at = self
                .in_flight
                .is_empty()
                .then(|| self.last_activity.checked_add(limits.idle_timeout))
                .flatten();
            tokio::select! {
                biased;
                () = stopped(&mut shutdown) => break Close::Shutdown,
                Some(joined) = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => {
                    if let Err(close) = self.complete(joined, &mut writer).await {
                        break close;
                    }
                }
                item = inbound.recv() => match item {
                    Some(Ok(frame)) => {
                        self.last_activity = Instant::now();
                        if let Err(close) = self.accept(frame) {
                            break close;
                        }
                    }
                    Some(Err(close)) => break close,
                    None => break Close::PeerClosed,
                },
                () = sleep_until(idle_at.unwrap_or(self.last_activity)), if idle_at.is_some() => {
                    break Close::Idle;
                }
            }
        };
        reader_task.abort_all();
        close.log();
        self.finish(&close, &mut writer).await;
    }

    /// Admits one inbound frame.
    fn accept(&mut self, inbound: Inbound) -> Result<(), Close> {
        match inbound {
            Inbound::Request(request) => self.start(*request),
            Inbound::Cancel(Cancel { request_id }) => {
                // NOTE: a cancel for an id that is not in flight is benign:
                // the request may have completed while the cancel was in
                // transit.
                if let Some(handle) = self.in_flight.get(&request_id) {
                    handle.cancel();
                }
                Ok(())
            }
        }
    }

    /// Spawns the dispatch of one request.
    fn start(&mut self, request: Request) -> Result<(), Close> {
        let limits = self.shared.limits;
        let request_id = request.request_id;
        if self.in_flight.contains_key(&request_id) {
            return Err(Close::Fault(
                Failure::ProtocolError,
                "duplicate in-flight request id",
            ));
        }
        if self.in_flight.len() >= limits.max_in_flight {
            return Err(Close::Fault(
                Failure::ProtocolError,
                "in-flight request bound exceeded",
            ));
        }
        let requested = Duration::from_millis(u64::from(request.deadline_ms));
        let deadline = after(requested.min(limits.max_deadline));
        let backstop = deadline
            .checked_add(limits.dispatch_grace)
            .unwrap_or(deadline);
        let (handle, signal) = cancel_pair();
        let dispatcher = Arc::clone(&self.shared.dispatcher);
        let identity = self.identity;
        let span = info_span!(
            "request",
            request_id,
            capability = %request.body.capability()
        );
        let task = self.tasks.spawn(
            async move {
                let dispatch = dispatcher.dispatch(identity, request, signal, deadline);
                match timeout_at(backstop, dispatch).await {
                    Ok(response) => tag(response, request_id),
                    Err(_elapsed) => {
                        warn!("dispatcher missed its deadline; answering DeadlineExceeded");
                        failed(request_id, Failure::DeadlineExceeded)
                    }
                }
            }
            .instrument(span),
        );
        self.task_ids.insert(task.id(), request_id);
        self.in_flight.insert(request_id, handle);
        Ok(())
    }

    /// Retires a finished dispatch and writes its response.
    async fn complete(
        &mut self,
        joined: Result<(Id, Response), JoinError>,
        writer: &mut OwnedWriteHalf,
    ) -> Result<(), Close> {
        let Some(response) = self.retire(joined) else {
            return Ok(());
        };
        let bytes = encode_frame(&response, self.identity.max_frame).map_err(|_too_large| {
            Close::Fault(
                Failure::ProtocolError,
                "response does not fit the negotiated frame bound",
            )
        })?;
        write_frame(writer, &bytes, self.shared.limits.frame_timeout)
            .await
            .map_err(Close::Io)?;
        self.last_activity = Instant::now();
        Ok(())
    }

    /// Removes a finished task from the in-flight set and returns the
    /// response to send, if the task belonged to a tracked request.
    fn retire(&mut self, joined: Result<(Id, Response), JoinError>) -> Option<Response> {
        let (task, outcome) = match joined {
            Ok((task, response)) => (task, Ok(response)),
            Err(error) => (error.id(), Err(error)),
        };
        let request_id = self.task_ids.remove(&task)?;
        self.in_flight.remove(&request_id);
        Some(match outcome {
            Ok(response) => response,
            Err(error) => {
                // WHY UnknownEffect: a dispatcher that panicked may have
                // reached any lifecycle boundary; the contract's outcome for
                // an effect that cannot be proven either way is UnknownEffect.
                warn!(panicked = error.is_panic(), "dispatch task failed");
                failed(request_id, Failure::UnknownEffect)
            }
        })
    }

    /// Cancels in-flight work and closes the connection.
    ///
    /// On shutdown, responses that complete within the dispatch grace are
    /// still delivered. On a fault, the single fault frame is the last
    /// thing written. Tasks still running after the grace are aborted, and
    /// only then does the connection release its connection permit, so a
    /// peer cannot pile up dispatch work by reconnecting.
    async fn finish(mut self, close: &Close, writer: &mut OwnedWriteHalf) {
        let limits = self.shared.limits;
        for handle in self.in_flight.values() {
            handle.cancel();
        }
        let deliver = matches!(close, Close::Shutdown);
        if !deliver {
            if let Some(bytes) = close.fault().and_then(fault_frame) {
                // WHY ignored: the connection closes either way.
                let _sent = write_frame(writer, &bytes, limits.frame_timeout).await;
            }
            // WHY shut down now: the peer sees end of stream right after
            // the fault, not after the cancelled work drains.
            let _shut = timeout(limits.frame_timeout, writer.shutdown()).await;
        }
        let grace = after(limits.dispatch_grace);
        while !self.tasks.is_empty() {
            let Ok(Some(joined)) = timeout_at(grace, self.tasks.join_next_with_id()).await else {
                break;
            };
            if deliver && self.complete(joined, writer).await.is_err() {
                break;
            }
        }
        self.tasks.shutdown().await;
    }
}

/// Reads frames for an admitted connection and forwards them decoded.
/// Ends after forwarding the first failure.
async fn read_loop(
    mut reader: OwnedReadHalf,
    cap: u32,
    frame_timeout: Duration,
    forward: mpsc::Sender<Result<Inbound, Close>>,
) {
    loop {
        let item = match read_frame(&mut reader, cap, frame_timeout).await {
            Ok(frame) => match frame.header.kind() {
                FrameKind::Request => decode_frame(&frame.header, &frame.body, cap)
                    .map(|request| Inbound::Request(Box::new(request)))
                    .map_err(|_invalid| Close::Fault(Failure::ProtocolError, "invalid request")),
                FrameKind::Cancel => decode_frame(&frame.header, &frame.body, cap)
                    .map(Inbound::Cancel)
                    .map_err(|_invalid| Close::Fault(Failure::ProtocolError, "invalid cancel")),
                _ => Err(Close::Fault(
                    Failure::ProtocolError,
                    "frame kind not valid after admission",
                )),
            },
            Err(fail) => Err(fail.into_close()),
        };
        let stop = item.is_err();
        if forward.send(item).await.is_err() || stop {
            return;
        }
    }
}

/// Completes when the server signals shutdown (or is gone).
async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    // WHY the result is ignored: Ok means the flag was set and Err means the
    // server dropped its sender; both mean stop.
    let _stop = shutdown.wait_for(|stop| *stop).await.is_ok();
}

/// Forces a dispatcher's response onto the request it answers.
fn tag(mut response: Response, request_id: u64) -> Response {
    if response.request_id != request_id {
        warn!("dispatcher answered with another request id; retagging");
        response.request_id = request_id;
    }
    response
}

/// A failure response for `request_id` that persisted nothing the server
/// knows of.
fn failed(request_id: u64, failure: Failure) -> Response {
    Response {
        request_id,
        invocation: None,
        body: ResponseBody::Failed(failure),
    }
}
