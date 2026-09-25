//! The capture lifecycle: B1 intent, B2 dispatch, the producer call, B3
//! transfer, B4 publish, B5 settle; or release or `UnknownEffect` on each
//! failure path (contract § Invocation lifecycle, § Revocation of queued
//! and running calls, § Cancellation and deadline).

use std::sync::Arc;
use std::time::Duration;

use phylake::store::{
    Begin, Intent, InvocationStatus, SettleOutcome, Terminal, Transfer, artifact_ref,
};
use snafu::ResultExt as _;
use syntheke::{
    Capability, CaptureLimits, CaptureOutcome, CaptureRequest, Cost, DenyCode, Failure, GrantId,
    InvocationId, InvocationState, ReleaseReason, ResponseBody, TransferClass,
};
use tokio::time::{Instant, sleep, sleep_until};

use super::limits::capture_cost;
use super::{Call, Inner, Registration, Reply, internal};
use crate::cancel::CancelSignal;
use crate::error::{Error, StoreSnafu};
use crate::producer::{AcquireRequest, Producer, ProducerError, ProducerOutput};

/// How long past its deadline a producer may take to report how it
/// stopped before the call is resolved as `UnknownEffect`. Shorter than
/// the server's dispatch grace, so the reply still reaches the caller.
const PRODUCER_GRACE: Duration = Duration::from_secs(1);

/// How often a running capture re-checks its chain, so a link that
/// expires, or is revoked by any path, stops the producer. Polling reads
/// the injected clock, so a test clock moves it too.
const CHAIN_POLL: Duration = Duration::from_millis(100);

/// One invocation's signals and timing while it runs.
#[derive(Clone, Copy)]
struct Flight<'a> {
    /// The server's cancel signal for the request.
    cancel: &'a CancelSignal,
    /// The request deadline on the monotonic clock.
    deadline: Instant,
    /// The running-set entry: the producer's cancel signal and handle.
    registration: &'a Registration,
    /// When the call started, for the wall-time actual.
    started: Instant,
}

/// How a producer call ended, as the lifecycle sees it.
enum Produced {
    /// The producer returned its output.
    Output(ProducerOutput),
    /// The producer returned a failure.
    Error(ProducerError),
    /// The producer did not return within its grace.
    Abandoned,
}

/// What B1 answered.
enum Started {
    /// B1 committed under these limits.
    Persisted(InvocationStatus, CaptureLimits),
    /// The reply is final without running anything.
    Answered(Reply),
}

impl<P: Producer> Inner<P> {
    /// Runs one executed capture to its reply.
    pub(super) async fn capture(
        self: Arc<Self>,
        call: Call,
        capture: CaptureRequest,
        cancel: CancelSignal,
        deadline: Instant,
    ) -> Reply {
        let started = Instant::now();
        let begin = {
            let call = call.clone();
            let capture = capture.clone();
            self.run_step(move |this| this.begin_capture(&call, &capture))
                .await
        };
        let (status, limits) = match begin {
            Ok(Started::Persisted(status, limits)) => (status, limits),
            Ok(Started::Answered(reply)) => return reply,
            Err(error) => return internal(&error),
        };
        let id = status.id;
        let registration = self.register(id, status.grant_chain.clone());
        let flight = Flight {
            cancel: &cancel,
            deadline,
            registration: &registration,
            started,
        };
        let reply = self
            .run_invocation(&call, &capture, limits, id, &flight)
            .await;
        self.deregister(id);
        match reply {
            Ok(reply) => reply,
            Err(error) => {
                warn_internal(&error);
                // WHY: the lifecycle owns its reservation; a failed step
                // must not leave it held until the next restart.
                self.run_step(move |this| this.after_error(id))
                    .await
                    .unwrap_or_else(|error| internal(&error))
            }
        }
    }

    /// B1: authorizes and persists the intent, or answers a replay, a
    /// conflict, or a refusal.
    fn begin_capture(&self, call: &Call, capture: &CaptureRequest) -> Result<Started, Error> {
        let Some(key) = &call.key else {
            // WHY: the wire refuses an executed capture without a key;
            // reaching here is a protocol fault, never a conflict.
            return Ok(Started::Answered(Reply::failed(Failure::ProtocolError)));
        };
        let limits = self.capture_limits(call, capture.limits)?;
        let declared = capture_cost(&limits, call.deadline_ms);
        let authz = Self::authz(
            call,
            Capability::Capture,
            Some(&capture.target),
            Some(capture.session),
            declared,
        );
        let intent = Intent::new(self.fresh_invocation()?, authz, key, call.digest);
        Ok(match self.store.begin(&intent).context(StoreSnafu)? {
            Begin::Persisted(status) => Started::Persisted(status, limits),
            Begin::Replayed(status) => Started::Answered(self.replay_capture(call, &status)?),
            Begin::Conflict => Started::Answered(Reply::failed(Failure::IdempotencyConflict)),
            Begin::Refused { failure, .. } => Started::Answered(Reply::failed(failure)),
            _ => Started::Answered(Reply::failed(Failure::UnknownEffect)),
        })
    }

    /// B1 committed: re-check, dispatch, call the producer, and finish.
    async fn run_invocation(
        self: &Arc<Self>,
        call: &Call,
        capture: &CaptureRequest,
        limits: CaptureLimits,
        id: InvocationId,
        flight: &Flight<'_>,
    ) -> Result<Reply, Error> {
        let grant = call.grant;
        let deadline = flight.deadline;
        let stop = {
            let cancelled = flight.cancel.is_cancelled();
            self.run_step(move |this| this.pre_dispatch(grant, cancelled, deadline))
                .await?
        };
        if let Some(reason) = stop {
            return self.release(id, reason).await;
        }
        self.run_step(move |this| this.store.dispatch(id).context(StoreSnafu))
            .await?;
        let request = AcquireRequest {
            invocation: id,
            target: capture.target.clone(),
            limits,
            egress_policy: capture.egress_policy.clone(),
        };
        let produced = self.produce(request, grant, flight).await;
        let elapsed = elapsed_ms(flight.started);
        match produced {
            Produced::Output(output) => self.finish(call, limits, id, output, elapsed).await,
            Produced::Error(error) => self.fail(grant, id, error, deadline, elapsed).await,
            Produced::Abandoned => {
                self.run_step(move |this| this.store.mark_unknown_effect(id).context(StoreSnafu))
                    .await?;
                Ok(Reply::of(id, ResponseBody::Failed(Failure::UnknownEffect)))
            }
        }
    }

    /// The release reason when the call must stop before dispatch: the
    /// chain is no longer usable (re-checked at dispatch; revoked or
    /// expired), the caller cancelled, or the deadline passed.
    pub(super) fn pre_dispatch(
        &self,
        grant: GrantId,
        cancelled: bool,
        deadline: Instant,
    ) -> Result<Option<ReleaseReason>, Error> {
        if let Some(code) = self.chain_refusal(grant)? {
            return Ok(Some(chain_stop(code)));
        }
        if cancelled {
            return Ok(Some(ReleaseReason::Cancelled));
        }
        if Instant::now() >= deadline {
            return Ok(Some(ReleaseReason::DeadlineExceeded));
        }
        Ok(None)
    }

    /// Why a dispatched call stopped, re-checked after the producer
    /// returned: the chain (revocation before expiry, in walk order), then
    /// the deadline, then the caller's cancel.
    pub(super) fn stop_reason(
        &self,
        grant: GrantId,
        deadline: Instant,
    ) -> Result<ReleaseReason, Error> {
        Ok(match self.chain_refusal(grant)? {
            Some(code) => chain_stop(code),
            None if Instant::now() >= deadline => ReleaseReason::DeadlineExceeded,
            None => ReleaseReason::Cancelled,
        })
    }

    /// Calls the producer with a signal that fires on the caller's cancel,
    /// the deadline, a revocation, or a chain that stops being usable, and
    /// waits at most until the deadline plus [`PRODUCER_GRACE`].
    async fn produce(
        self: &Arc<Self>,
        request: AcquireRequest,
        grant: GrantId,
        flight: &Flight<'_>,
    ) -> Produced {
        let Flight {
            cancel,
            deadline,
            registration,
            ..
        } = *flight;
        let forward_to = Arc::clone(&registration.cancel);
        let caller = cancel.clone();
        let watcher = Arc::clone(self);
        let forward = tokio::spawn(async move {
            tokio::select! {
                () = caller.cancelled() => {}
                () = sleep_until(deadline) => {}
                () = watcher.chain_lost(grant) => {}
            }
            forward_to.cancel();
        });
        let backstop = deadline.checked_add(PRODUCER_GRACE).unwrap_or(deadline);
        let acquire = self
            .producer
            .acquire(request, registration.signal.clone(), deadline);
        let produced = tokio::select! {
            result = acquire => match result {
                Ok(output) => Produced::Output(output),
                Err(error) => Produced::Error(error),
            },
            () = sleep_until(backstop) => Produced::Abandoned,
        };
        forward.abort();
        produced
    }

    /// Completes once `grant`'s chain is no longer usable, or cannot be
    /// read (the closed side).
    async fn chain_lost(self: Arc<Self>, grant: GrantId) {
        loop {
            sleep(CHAIN_POLL).await;
            let this = Arc::clone(&self);
            let live = tokio::task::spawn_blocking(move || this.chain_refusal(grant)).await;
            if !matches!(live, Ok(Ok(None))) {
                return;
            }
        }
    }

    /// The producer returned output: B3, B4, B5.
    async fn finish(
        self: &Arc<Self>,
        call: &Call,
        limits: CaptureLimits,
        id: InvocationId,
        output: ProducerOutput,
        elapsed: u64,
    ) -> Result<Reply, Error> {
        let transferred = len_u64(&output.envelope);
        if transferred > limits.max_transfer_bytes.unwrap_or(0) {
            let failure = Failure::TransferFailed {
                class: TransferClass::TooLarge,
            };
            return self.settle_failed(id, failure, spent(elapsed, 0)).await;
        }
        let call = call.clone();
        self.run_step(move |this| this.publish(&call, &limits, id, &output, elapsed))
            .await
    }

    /// B3 through B5 for a returned output; re-checks the chain at
    /// settlement and marks the capture when it was revoked or expired
    /// meanwhile.
    fn publish(
        &self,
        call: &Call,
        limits: &CaptureLimits,
        id: InvocationId,
        output: &ProducerOutput,
        elapsed: u64,
    ) -> Result<Reply, Error> {
        // NOTE: the one marker covers both ways a chain stops being live
        // after the effect started; the contract carries no second flag.
        let revoked_after_effect = self.chain_refusal(call.grant)?.is_some();
        let source = output.source();
        let frame_room = u64::from(call.payload_budget()).saturating_sub(source_len(&source));
        let output_cap = limits.max_output_bytes.unwrap_or(0).min(frame_room);
        let (text_view, truncated) = cut_text(output.text_view.as_deref(), output_cap);
        let output_bytes = text_view
            .as_ref()
            .map_or(0, |text| len_u64(text.as_bytes()));
        let mut actual = spent(elapsed, len_u64(&output.envelope));
        actual.output_bytes = output_bytes;
        let mut transfer = Transfer::new(&output.envelope, source.clone(), actual);
        transfer.text_view.clone_from(&text_view);
        transfer.truncated = truncated;
        transfer.output_bytes = output_bytes;
        transfer.revoked_after_effect = revoked_after_effect;
        self.store
            .complete_transfer(id, &transfer)
            .context(StoreSnafu)?;
        self.store.publish(id).context(StoreSnafu)?;
        self.store
            .settle(id, SettleOutcome::Success)
            .context(StoreSnafu)?;
        let outcome = CaptureOutcome {
            artifact_ref: artifact_ref(id),
            source,
            text_view,
            truncated,
            output_bytes,
            revoked_after_effect,
        };
        Ok(Reply::of(id, ResponseBody::Captured(outcome)))
    }

    /// The producer returned a failure: release when it proves no effect,
    /// settle the actual cost otherwise.
    async fn fail(
        self: &Arc<Self>,
        grant: GrantId,
        id: InvocationId,
        error: ProducerError,
        deadline: Instant,
        elapsed: u64,
    ) -> Result<Reply, Error> {
        match error {
            ProducerError::Unavailable { contacted: false } => {
                self.release(id, ReleaseReason::ProducerUnavailable).await
            }
            ProducerError::Cancelled {
                effect_started: false,
            } => {
                let stop = self
                    .run_step(move |this| this.stop_reason(grant, deadline))
                    .await?;
                self.release(id, stop).await
            }
            ProducerError::Transfer { class } => {
                self.settle_failed(id, Failure::TransferFailed { class }, spent(elapsed, 0))
                    .await
            }
            ProducerError::Extraction { class } => {
                self.settle_failed(id, Failure::ExtractionFailed { class }, spent(elapsed, 0))
                    .await
            }
            // WHY UnknownEffect: a producer that was reached and then
            // reported itself unavailable cannot say whether its effect
            // happened.
            ProducerError::Unavailable { contacted: true } => {
                self.run_step(move |this| this.store.mark_unknown_effect(id).context(StoreSnafu))
                    .await?;
                Ok(Reply::of(id, ResponseBody::Failed(Failure::UnknownEffect)))
            }
            // NOTE: a producer that stopped after its effect started
            // returned no envelope, so there is nothing to publish; the
            // call settles its actual cost (contract § Early stops). A
            // revocation or expiry that stopped it reads as a
            // cancellation: the effect started under a live chain.
            ProducerError::Cancelled {
                effect_started: true,
            } => {
                let past_deadline = Instant::now() >= deadline;
                let failure = if past_deadline {
                    Failure::DeadlineExceeded
                } else {
                    Failure::Cancelled
                };
                self.settle_failed(id, failure, spent(elapsed, 0)).await
            }
        }
    }

    /// B5: releases the whole reservation for `reason`.
    async fn release(
        self: &Arc<Self>,
        id: InvocationId,
        reason: ReleaseReason,
    ) -> Result<Reply, Error> {
        let status = self
            .run_step(move |this| this.store.release(id, reason).context(StoreSnafu))
            .await?;
        let terminal = status.terminal.unwrap_or(Terminal::Released { reason });
        Ok(Reply::of(
            id,
            ResponseBody::Failed(terminal.reply_failure().unwrap_or(Failure::Cancelled)),
        ))
    }

    /// B5: settles a dispatched call whose producer started and failed.
    async fn settle_failed(
        self: &Arc<Self>,
        id: InvocationId,
        failure: Failure,
        actual: Cost,
    ) -> Result<Reply, Error> {
        self.run_step(move |this| {
            this.store
                .settle(id, SettleOutcome::Failed { failure, actual })
                .context(StoreSnafu)
        })
        .await?;
        Ok(Reply::of(id, ResponseBody::Failed(failure)))
    }

    /// Resolves an invocation whose step failed inside the daemon: a call
    /// still at B1 releases as `Abandoned` (the producer was never
    /// called), a call at B2 becomes `UnknownEffect`, and a call at B3 or
    /// later is left for restart recovery to roll forward.
    pub(super) fn after_error(&self, id: InvocationId) -> Result<Reply, Error> {
        let Some(status) = self.store.invocation(id).context(StoreSnafu)? else {
            return Ok(Reply::failed(Failure::UnknownEffect));
        };
        let status = match status.state {
            InvocationState::IntentPersisted => self
                .store
                .release(id, ReleaseReason::Abandoned)
                .context(StoreSnafu)?,
            InvocationState::Dispatched => {
                self.store.mark_unknown_effect(id).context(StoreSnafu)?
            }
            _ => status,
        };
        match status.terminal {
            Some(_) => self.replay(&status),
            None => Ok(Reply::of(id, ResponseBody::Failed(Failure::UnknownEffect))),
        }
    }

    /// The reply to a replayed capture: the designated chain is
    /// re-authorized first, and a chain that no longer authorizes the
    /// capture is refused with the current reason, never answered with
    /// stored content.
    fn replay_capture(&self, call: &Call, status: &InvocationStatus) -> Result<Reply, Error> {
        if let Some(failure) = self.replay_refusal(call, Capability::Capture)? {
            return self.deny(call, Capability::Capture, None, failure);
        }
        self.replay(status)
    }

    /// The reply for an idempotent replay: the current or terminal outcome
    /// of the existing invocation. Nothing is dispatched.
    pub(super) fn replay(&self, status: &InvocationStatus) -> Result<Reply, Error> {
        let body = match status.terminal {
            None => ResponseBody::InProgress,
            Some(Terminal::Settled { failure: None }) => match self.captured(status)? {
                Some(outcome) => ResponseBody::Captured(outcome),
                None => ResponseBody::Failed(Failure::UnknownEffect),
            },
            Some(terminal) => {
                ResponseBody::Failed(terminal.reply_failure().unwrap_or(Failure::UnknownEffect))
            }
        };
        Ok(Reply::of(status.id, body))
    }

    /// The capture outcome a settled invocation published.
    fn captured(&self, status: &InvocationStatus) -> Result<Option<CaptureOutcome>, Error> {
        let Some(artifact) = status.artifact else {
            return Ok(None);
        };
        Ok(self
            .store
            .artifact(artifact)
            .context(StoreSnafu)?
            .map(|info| CaptureOutcome {
                artifact_ref: info.artifact,
                source: info.source,
                text_view: info.text_view,
                truncated: info.truncated,
                output_bytes: info.output_bytes,
                revoked_after_effect: info.revoked_after_effect,
            }))
    }

    /// Runs one store step on the blocking pool.
    async fn run_step<T, F>(self: &Arc<Self>, step: F) -> Result<T, Error>
    where
        T: Send + 'static,
        F: FnOnce(&Self) -> Result<T, Error> + Send + 'static,
    {
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || step(&this))
            .await
            .context(crate::error::TaskSnafu)?
    }
}

/// The release reason for a chain that stopped being usable with `code`:
/// `Expired` for an expired link, `Revoked` for every other reason.
///
/// NOTE: `GrantNotYetValid` after a successful B1 needs the clock to move
/// backward; it releases as `Revoked`, the closed reading of a chain that
/// no longer authorizes.
pub(super) const fn chain_stop(code: DenyCode) -> ReleaseReason {
    match code {
        DenyCode::GrantExpired => ReleaseReason::Expired,
        _ => ReleaseReason::Revoked,
    }
}

/// Logs a daemon failure without payload.
fn warn_internal(error: &Error) {
    tracing::warn!(%error, "capture step failed inside the daemon");
}

/// Actual consumption of a call that ran for `elapsed` ms and made one
/// fetch transferring `transferred` bytes.
const fn spent(elapsed: u64, transferred: u64) -> Cost {
    Cost {
        wall_time_ms: elapsed,
        fetches: 1,
        bytes_transferred: transferred,
        output_bytes: 0,
        tokens: 0,
        ops_band: 0,
    }
}

/// Milliseconds since `started`.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// A byte length as `u64`.
fn len_u64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// Bytes the evidence identity adds to a reply.
fn source_len(source: &syntheke::SourceRef) -> u64 {
    len_u64(source.fingerprint.as_bytes())
        .saturating_add(len_u64(source.schema_id.as_bytes()))
        .saturating_add(len_u64(source.producer_revision.as_bytes()))
}

/// Cuts `text` to at most `max` bytes on a character boundary. Returns the
/// kept text and whether anything was cut.
pub(super) fn cut_text(text: Option<&str>, max: u64) -> (Option<String>, bool) {
    let Some(text) = text else {
        return (None, false);
    };
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    if text.len() <= max {
        return (Some(text.to_owned()), false);
    }
    let end = (0..=max)
        .rev()
        .find(|&index| text.is_char_boundary(index))
        .unwrap_or(0);
    (Some(text.get(..end).unwrap_or_default().to_owned()), true)
}
