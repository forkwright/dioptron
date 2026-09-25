//! The invocation orchestrator: the server's [`Dispatcher`] over the
//! custody store (contract § Invocation lifecycle).
//!
//! Every admitted request runs as a task the orchestrator owns, so work
//! that must finish (settling or releasing a reservation) completes even
//! when the server drops the dispatch future at its deadline backstop or
//! at shutdown. [`Drain::wait`] lets the daemon wait for those tasks.
//!
//! - `DryRun` of any capability plans over a store snapshot and writes
//!   nothing, including no audit entry (`plan.rs`).
//! - `Capture` runs the lifecycle B1 to B5 around one producer call
//!   (`capture.rs`).
//! - Session and grant calls authorize under the designated grant, bind
//!   their idempotency key, and write through the store (`directory.rs`).
//! - `Read`, `Query`, and `AuditQuery` authorize the session they touch
//!   and answer within the connection's frame bound; `Ingest` is refused
//!   as `NotSupported` at authorization (`reads.rs`).
//! - A capture's declared limits come from `limits.rs`.
//!
//! Every `Execute` refusal commits a `Denied` audit entry and answers with
//! no invocation id, so a refusal's bytes depend only on the failure: a
//! missing resource and a foreign one read the same.

mod capture;
mod directory;
mod limits;
mod plan;
mod reads;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use epitrope::{AuthzRequest, Clock, GrantView as _, check_chain, designated_chain};
use phylake::Store;
use phylake::store::{AuditNote, AuditOutcome};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;
use syntheke::{
    Capability, Cost, DenyCode, Failure, GrantId, IdempotencyKey, InvocationId, Mode, Plan,
    Request, RequestBody, Response, ResponseBody, SessionId, TenantId,
};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::warn;

use crate::cancel::{CancelHandle, CancelSignal};
use crate::error::{AuthzSnafu, EncodeSnafu, Error, RandomSourceSnafu, StoreSnafu, ViewSnafu};
use crate::producer::Producer;
use crate::server::{ConnIdentity, Dispatcher};

/// The longest deadline a request may declare, in milliseconds; matches
/// the server's default maximum.
const MAX_DEADLINE_MS: u32 = 120_000;

/// Bytes reserved in a response frame for everything but its variable
/// payload.
const FRAME_OVERHEAD: u32 = 1_024;

/// Waits for the orchestrator's tasks after the server has stopped.
#[derive(Debug)]
pub struct Drain(mpsc::Receiver<()>);

impl Drain {
    /// Completes when the orchestrator and every task it spawned are gone.
    pub async fn wait(mut self) {
        // WHY: no value is ever sent; `recv` returns `None` once every
        // sender (the orchestrator's and one per task) is dropped.
        while self.0.recv().await.is_some() {}
    }
}

/// The server's [`Dispatcher`]: runs admitted requests against the store
/// and the producer.
#[derive(Debug)]
pub struct Orchestrator<P> {
    inner: Arc<Inner<P>>,
    tracker: mpsc::Sender<()>,
}

impl<P: Producer> Orchestrator<P> {
    /// An orchestrator over `store` that captures through `producer` and
    /// reads time from `clock`, and the [`Drain`] for its tasks.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        producer: P,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> (Self, Drain) {
        let (tracker, drain) = mpsc::channel(1);
        let inner = Arc::new(Inner {
            store,
            producer: Arc::new(producer),
            clock,
            running: Mutex::new(HashMap::new()),
        });
        (Self { inner, tracker }, Drain(drain))
    }
}

impl<P: Producer> Dispatcher for Orchestrator<P> {
    fn dispatch(
        &self,
        conn: ConnIdentity,
        request: Request,
        cancel: CancelSignal,
        deadline: Instant,
    ) -> impl Future<Output = Response> + Send {
        let request_id = request.request_id;
        let inner = Arc::clone(&self.inner);
        let guard = self.tracker.clone();
        // WHY spawn: the server may drop this future at its backstop; the
        // task keeps running and settles what it started.
        let task = tokio::spawn(async move {
            let _guard = guard;
            inner.handle(conn, request, cancel, deadline).await
        });
        async move {
            let reply = task.await.unwrap_or_else(|error| {
                warn!(panicked = error.is_panic(), "request task failed");
                Reply::failed(Failure::UnknownEffect)
            });
            Response {
                request_id,
                invocation: reply.invocation,
                body: reply.body,
            }
        }
    }
}

/// A response without its request id.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Reply {
    invocation: Option<InvocationId>,
    body: ResponseBody,
}

impl Reply {
    /// A failure that names no invocation.
    const fn failed(failure: Failure) -> Self {
        Self {
            invocation: None,
            body: ResponseBody::Failed(failure),
        }
    }

    /// A reply for the persisted invocation `invocation`.
    const fn of(invocation: InvocationId, body: ResponseBody) -> Self {
        Self {
            invocation: Some(invocation),
            body,
        }
    }

    /// A dry-run plan.
    const fn plan(plan: Plan) -> Self {
        Self {
            invocation: None,
            body: ResponseBody::Plan(plan),
        }
    }
}

/// The request facts every handler uses.
#[derive(Clone, Debug)]
struct Call {
    tenant: TenantId,
    grant: GrantId,
    key: Option<IdempotencyKey>,
    digest: [u8; 32],
    deadline_ms: u32,
    max_frame: u32,
}

impl Call {
    /// The facts of `request` on `conn`, with the request digest.
    fn new(conn: &ConnIdentity, request: &Request) -> Result<Self, Error> {
        Ok(Self {
            tenant: conn.tenant,
            grant: request.grant,
            key: request.idempotency_key.clone(),
            digest: request_digest(request)?,
            deadline_ms: request.deadline_ms.min(MAX_DEADLINE_MS),
            max_frame: conn.max_frame,
        })
    }

    /// The payload bytes a response may carry beyond its fixed fields.
    const fn payload_budget(&self) -> u32 {
        self.max_frame.saturating_sub(FRAME_OVERHEAD)
    }
}

/// SHA-256 over the canonical encoding of what makes two requests the
/// same call: the designated grant, the idempotency key, the mode, and
/// the body. The request id and the deadline do not count.
fn request_digest(request: &Request) -> Result<[u8; 32], Error> {
    let normalized = Request {
        request_id: 0,
        grant: request.grant,
        idempotency_key: request.idempotency_key.clone(),
        mode: request.mode,
        deadline_ms: 0,
        body: request.body.clone(),
    };
    let encoded = syntheke::encode(&normalized).context(EncodeSnafu)?;
    Ok(Sha256::new()
        .chain_update(b"dioptron-request-v1")
        .chain_update(&encoded)
        .finalize()
        .into())
}

/// An invocation in flight between B1 and its terminal state.
#[derive(Debug)]
struct Running {
    /// Its authorizing chain, leaf first.
    chain: Vec<GrantId>,
    /// Fires the producer's cancel signal.
    cancel: Arc<CancelHandle>,
}

/// State shared by every request task.
struct Inner<P> {
    store: Arc<Store>,
    producer: Arc<P>,
    clock: Arc<dyn Clock + Send + Sync>,
    running: Mutex<HashMap<InvocationId, Running>>,
}

impl<P> std::fmt::Debug for Inner<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner").finish_non_exhaustive()
    }
}

impl<P: Producer> Inner<P> {
    /// Runs one request to its reply.
    async fn handle(
        self: Arc<Self>,
        conn: ConnIdentity,
        request: Request,
        cancel: CancelSignal,
        deadline: Instant,
    ) -> Reply {
        let call = match Call::new(&conn, &request) {
            Ok(call) => call,
            Err(error) => return internal(&error),
        };
        let Request { mode, body, .. } = request;
        if mode == Mode::DryRun {
            return self.run_blocking(move |this| this.plan(&call, &body)).await;
        }
        match body {
            RequestBody::Capture(capture) => self.capture(call, capture, cancel, deadline).await,
            other => {
                self.run_blocking(move |this| this.execute(&call, other))
                    .await
            }
        }
    }

    /// Runs store work on the blocking pool.
    async fn run_blocking<F>(self: &Arc<Self>, work: F) -> Reply
    where
        F: FnOnce(&Self) -> Result<Reply, Error> + Send + 'static,
    {
        let this = Arc::clone(self);
        match tokio::task::spawn_blocking(move || work(&this)).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(error)) => internal(&error),
            Err(error) => {
                warn!(panicked = error.is_panic(), "store task failed");
                Reply::failed(Failure::UnknownEffect)
            }
        }
    }

    /// Runs an executed call other than `Capture`.
    fn execute(&self, call: &Call, body: RequestBody) -> Result<Reply, Error> {
        match body {
            RequestBody::SessionCreate => self.session_create(call),
            RequestBody::SessionFork(fork) => self.session_fork(call, fork.parent_session),
            RequestBody::GrantIssue(issue) => self.grant_issue(call, &issue),
            RequestBody::GrantRevoke(revoke) => self.grant_revoke(call, revoke.target_grant),
            RequestBody::Read(read) => self.read(call, &read),
            RequestBody::Query(query) => self.query(call, &query),
            RequestBody::AuditQuery(query) => self.audit_query(call, &query),
            RequestBody::Ingest(_) => self.ingest(call),
            // WHY: a capture never reaches here; a body a later contract
            // version adds has no handler, and refusing it is the closed
            // side.
            _ => Ok(Reply::failed(Failure::ProtocolError)),
        }
    }

    /// The authorization request of `call` for `capability`.
    fn authz<'a>(
        call: &Call,
        capability: Capability,
        target: Option<&'a str>,
        session: Option<SessionId>,
        declared: Cost,
    ) -> AuthzRequest<'a> {
        AuthzRequest {
            tenant: call.tenant,
            grant: call.grant,
            capability,
            target,
            session,
            declared,
        }
    }

    /// The dry-run decision for `authz` over a fresh snapshot.
    fn decide(&self, authz: &AuthzRequest<'_>) -> Result<Plan, Error> {
        self.store.plan(authz).context(StoreSnafu)
    }

    /// Commits the `Denied` audit entry of a refused call and answers it.
    fn deny(
        &self,
        call: &Call,
        capability: Capability,
        session: Option<SessionId>,
        failure: Failure,
    ) -> Result<Reply, Error> {
        let mut note = AuditNote::new(
            call.tenant,
            self.fresh_invocation()?,
            capability,
            AuditOutcome::Refused(failure),
        );
        note.session = session;
        note.grant = Some(call.grant);
        self.store.record_audit(&note).context(StoreSnafu)?;
        Ok(Reply::failed(failure))
    }

    /// The refusal a replay of `call` gets, or `None` when its designated
    /// chain still authorizes `capability` (contract § Idempotency).
    ///
    /// A replay re-runs the designated-grant checks (the grant, the
    /// validity of its whole chain, and the capability on every link)
    /// before it answers anything, so stored content is never returned
    /// under a chain that has since been revoked or has expired.
    fn replay_refusal(
        &self,
        call: &Call,
        capability: Capability,
    ) -> Result<Option<Failure>, Error> {
        let snapshot = self.store.snapshot();
        let decided =
            designated_chain(&snapshot, call.tenant, call.grant, capability, &*self.clock)
                .context(AuthzSnafu)?;
        Ok(match decided {
            Ok(_) => None,
            Err(refusal) => Some(refusal.refusal().unwrap_or(Failure::NotFoundOrDenied)),
        })
    }

    /// A new invocation id: ULID layout, the clock's milliseconds then 80
    /// random bits.
    fn fresh_invocation(&self) -> Result<InvocationId, Error> {
        fresh_id(self.clock.now()).map(InvocationId::from_bytes)
    }

    /// Why the chain of `grant` is not usable now, or `None` when it is.
    fn chain_refusal(&self, grant: GrantId) -> Result<Option<DenyCode>, Error> {
        let snapshot = self.store.snapshot();
        let Some(leaf) = snapshot.grant(grant).context(ViewSnafu)? else {
            return Ok(Some(DenyCode::GrantRevoked));
        };
        Ok(
            match check_chain(&snapshot, leaf, self.clock.now()).context(AuthzSnafu)? {
                epitrope::ChainStatus::Valid(_) => None,
                epitrope::ChainStatus::Invalid { code, .. } => Some(code),
                // WHY: a status a later epitrope adds is not proven valid.
                _ => Some(DenyCode::GrantRevoked),
            },
        )
    }

    /// Registers a running invocation so a revocation can reach it.
    fn register(&self, invocation: InvocationId, chain: Vec<GrantId>) -> Registration {
        let (handle, signal) = crate::cancel::cancel_pair();
        let cancel = Arc::new(handle);
        self.running_map().insert(
            invocation,
            Running {
                chain,
                cancel: Arc::clone(&cancel),
            },
        );
        Registration { cancel, signal }
    }

    /// Removes a finished invocation from the running set.
    fn deregister(&self, invocation: InvocationId) {
        self.running_map().remove(&invocation);
    }

    /// Cancels every running invocation whose chain contains `revoked`: the
    /// grant itself and, through chain validity, its descendants.
    fn cancel_revoked(&self, revoked: GrantId) {
        for running in self.running_map().values() {
            if running.chain.contains(&revoked) {
                running.cancel.cancel();
            }
        }
    }

    fn running_map(&self) -> std::sync::MutexGuard<'_, HashMap<InvocationId, Running>> {
        // WHY recover: the map holds no invariant a panic could break
        // halfway; each entry is inserted and removed whole.
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What [`Inner::register`] hands the lifecycle.
struct Registration {
    /// Fires `signal`.
    cancel: Arc<CancelHandle>,
    /// The producer's cancel signal.
    signal: CancelSignal,
}

/// Sixteen id bytes: 48 bits of milliseconds since the epoch (clamped at
/// zero), then 80 random bits.
pub(crate) fn fresh_id(now: syntheke::Timestamp) -> Result<[u8; 16], Error> {
    let millis = u64::try_from(now.unix_millis()).unwrap_or(0);
    let [_, _, t0, t1, t2, t3, t4, t5] = millis.to_be_bytes();
    let mut random = [0_u8; 10];
    getrandom::fill(&mut random).context(RandomSourceSnafu)?;
    let [r0, r1, r2, r3, r4, r5, r6, r7, r8, r9] = random;
    Ok([
        t0, t1, t2, t3, t4, t5, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9,
    ])
}

/// The reply for a failure inside the daemon. Logged without payload.
///
/// WHY `UnknownEffect`: the daemon cannot prove which store writes landed
/// before the failure, and the contract's outcome for an effect that can
/// be neither proven nor ruled out is `UnknownEffect`.
fn internal(error: &Error) -> Reply {
    warn!(%error, "request failed inside the daemon");
    Reply::failed(Failure::UnknownEffect)
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
