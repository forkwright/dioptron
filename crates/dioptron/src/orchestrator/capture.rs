//! The capture lifecycle: B1 intent, B2 dispatch, the producer call, B3
//! transfer, B4 publish, B5 settle; or release or `UnknownEffect` on each
//! failure path (contract § Invocation lifecycle, § Revocation of queued
//! and running calls, § Cancellation and deadline).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use phylake::store::{
    Begin, Intent, InvocationStatus, SettleOutcome, Terminal, Transfer, artifact_ref,
};
use snafu::ResultExt as _;
use syntheke::{
    Capability, CaptureLimits, CaptureOutcome, CaptureRequest, Cost, Failure, InvocationId,
    ReleaseReason, ResponseBody, TransferClass,
};
use tokio::time::{Instant, sleep_until};

use super::{Call, Inner, Registration, Reply, internal};
use crate::cancel::CancelSignal;
use crate::error::{Error, StoreSnafu};
use crate::producer::{AcquireRequest, Producer, ProducerError, ProducerOutput};

/// Declared transfer bound when the caller sets none: the first
/// consumer's 1 MB body cap.
pub(super) const DEFAULT_MAX_TRANSFER: u64 = 1_048_576;

/// Declared output bound when the caller sets none.
pub(super) const DEFAULT_MAX_OUTPUT: u64 = 65_536;

/// How long past its deadline a producer may take to report how it
/// stopped before the call is resolved as `UnknownEffect`. Shorter than
/// the server's dispatch grace, so the reply still reaches the caller.
const PRODUCER_GRACE: Duration = Duration::from_secs(1);

/// The declared maximum cost of a capture.
pub(super) fn capture_cost(limits: &CaptureLimits, deadline_ms: u32) -> Cost {
    Cost {
        wall_time_ms: u64::from(deadline_ms),
        fetches: 1,
        bytes_transferred: limits.max_transfer_bytes.unwrap_or(DEFAULT_MAX_TRANSFER),
        output_bytes: limits.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT),
        tokens: 0,
        ops_band: 0,
    }
}

/// One invocation's signals and timing while it runs.
#[derive(Clone, Copy)]
struct Flight<'a> {
    /// The server's cancel signal for the request.
    cancel: &'a CancelSignal,
    /// The request deadline on the monotonic clock.
    deadline: Instant,
    /// The running-set entry: the producer's signal and the revoked flag.
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
        let status = match begin {
            Ok(Begin::Persisted(status)) => status,
            Ok(Begin::Replayed(status)) => {
                return self.run_blocking(move |this| this.replay(&status)).await;
            }
            Ok(Begin::Conflict) => return Reply::failed(Failure::IdempotencyConflict),
            Ok(Begin::Refused { failure, .. }) => return Reply::failed(failure),
            Ok(_) => return Reply::failed(Failure::UnknownEffect),
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
        let reply = self.run_invocation(&call, &capture, id, &flight).await;
        self.deregister(id);
        match reply {
            Ok(reply) => reply,
            Err(error) => {
                // WHY: the step that failed may have been B3 or later,
                // which no release can undo; recovery at the next start
                // finishes it. Marking UnknownEffect succeeds only while
                // the call is at B2, so its own failure is expected.
                let _marked = self
                    .run_step(move |this| this.store.mark_unknown_effect(id).context(StoreSnafu))
                    .await;
                internal(&error)
            }
        }
    }

    /// B1: authorizes and persists the intent, or answers a replay.
    fn begin_capture(&self, call: &Call, capture: &CaptureRequest) -> Result<Begin, Error> {
        let Some(key) = &call.key else {
            return Ok(Begin::Conflict);
        };
        let declared = capture_cost(&capture.limits, call.deadline_ms);
        let authz = Self::authz(
            call,
            Capability::Capture,
            Some(&capture.target),
            Some(capture.session),
            declared,
        );
        let intent = Intent::new(self.fresh_invocation()?, authz, key, call.digest);
        self.store.begin(&intent).context(StoreSnafu)
    }

    /// B1 committed: re-check, dispatch, call the producer, and finish.
    async fn run_invocation(
        self: &Arc<Self>,
        call: &Call,
        capture: &CaptureRequest,
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
            limits: capture.limits,
            egress_policy: capture.egress_policy.clone(),
        };
        let produced = self.produce(request, flight).await;
        let elapsed = elapsed_ms(flight.started);
        match produced {
            Produced::Output(output) => self.finish(call, capture, id, output, elapsed).await,
            Produced::Error(error) => {
                let revoked = flight.registration.revoked.load(Ordering::SeqCst);
                self.fail(id, error, revoked, deadline, elapsed).await
            }
            Produced::Abandoned => {
                self.run_step(move |this| this.store.mark_unknown_effect(id).context(StoreSnafu))
                    .await?;
                Ok(Reply::of(id, ResponseBody::Failed(Failure::UnknownEffect)))
            }
        }
    }

    /// The release reason when the call must stop before dispatch: the
    /// chain is no longer usable (re-checked at dispatch), the caller
    /// cancelled, or the deadline passed.
    pub(super) fn pre_dispatch(
        &self,
        grant: syntheke::GrantId,
        cancelled: bool,
        deadline: Instant,
    ) -> Result<Option<ReleaseReason>, Error> {
        if self.chain_refusal(grant)?.is_some() {
            return Ok(Some(ReleaseReason::Revoked));
        }
        if cancelled {
            return Ok(Some(ReleaseReason::Cancelled));
        }
        if Instant::now() >= deadline {
            return Ok(Some(ReleaseReason::DeadlineExceeded));
        }
        Ok(None)
    }

    /// Calls the producer with a signal that fires on the caller's cancel,
    /// a revocation, or the deadline, and waits at most until the deadline
    /// plus [`PRODUCER_GRACE`].
    async fn produce(&self, request: AcquireRequest, flight: &Flight<'_>) -> Produced {
        let Flight {
            cancel,
            deadline,
            registration,
            ..
        } = *flight;
        let forward_to = Arc::clone(&registration.cancel);
        let caller = cancel.clone();
        let forward = tokio::spawn(async move {
            tokio::select! {
                () = caller.cancelled() => {}
                () = sleep_until(deadline) => {}
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

    /// The producer returned output: B3, B4, B5.
    async fn finish(
        self: &Arc<Self>,
        call: &Call,
        capture: &CaptureRequest,
        id: InvocationId,
        output: ProducerOutput,
        elapsed: u64,
    ) -> Result<Reply, Error> {
        let transfer_cap = capture
            .limits
            .max_transfer_bytes
            .unwrap_or(DEFAULT_MAX_TRANSFER);
        let transferred = u64::try_from(output.envelope.len()).unwrap_or(u64::MAX);
        if transferred > transfer_cap {
            let failure = Failure::TransferFailed {
                class: TransferClass::TooLarge,
            };
            let actual = spent(elapsed, 0);
            return self.settle_failed(id, failure, actual).await;
        }
        let call = call.clone();
        let limits = capture.limits;
        self.run_step(move |this| this.publish(&call, &limits, id, &output, elapsed))
            .await
    }

    /// B3 through B5 for a returned output; re-checks the chain at
    /// settlement and marks the capture when it was revoked meanwhile.
    fn publish(
        &self,
        call: &Call,
        limits: &CaptureLimits,
        id: InvocationId,
        output: &ProducerOutput,
        elapsed: u64,
    ) -> Result<Reply, Error> {
        let revoked_after_effect = self.chain_refusal(call.grant)?.is_some();
        let output_cap = limits.max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT);
        let source = output.source();
        let frame_room = u64::from(call.payload_budget()).saturating_sub(source_len(&source));
        let (text_view, truncated) =
            cut_text(output.text_view.as_deref(), output_cap.min(frame_room));
        let output_bytes = text_view
            .as_ref()
            .map_or(0, |text| len_u64(text.as_bytes()));
        let artifact = artifact_ref(id);
        let mut transfer = Transfer::new(&output.envelope, source.clone(), {
            let mut actual = spent(elapsed, len_u64(&output.envelope));
            actual.output_bytes = output_bytes;
            actual
        });
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
            artifact_ref: artifact,
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
        id: InvocationId,
        error: ProducerError,
        revoked: bool,
        deadline: Instant,
        elapsed: u64,
    ) -> Result<Reply, Error> {
        let stop = if revoked {
            ReleaseReason::Revoked
        } else if Instant::now() >= deadline {
            ReleaseReason::DeadlineExceeded
        } else {
            ReleaseReason::Cancelled
        };
        match error {
            ProducerError::Unavailable { contacted: false } => {
                self.release(id, ReleaseReason::ProducerUnavailable).await
            }
            ProducerError::Cancelled {
                effect_started: false,
            } => self.release(id, stop).await,
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
            // call settles its actual cost. A revocation that stopped it
            // reads as a cancellation: the effect happened under a grant
            // that was live when it started.
            ProducerError::Cancelled {
                effect_started: true,
            } => {
                let failure = if stop == ReleaseReason::DeadlineExceeded {
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
        Ok(Reply::of(
            id,
            ResponseBody::Failed(
                status
                    .terminal
                    .and_then(Terminal::reply_failure)
                    .unwrap_or(release_failure(reason)),
            ),
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

/// The failure a caller observes for a call that stopped for `reason`.
const fn release_failure(reason: ReleaseReason) -> Failure {
    match reason {
        ReleaseReason::Revoked => Failure::denied(syntheke::DenyCode::GrantRevoked),
        ReleaseReason::ProducerUnavailable => Failure::ProducerUnavailable,
        ReleaseReason::DeadlineExceeded => Failure::DeadlineExceeded,
        _ => Failure::Cancelled,
    }
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
