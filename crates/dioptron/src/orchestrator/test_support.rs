//! In-process fixtures for orchestrator tests: a store in a tempdir with
//! an operator, an agent, and a session, and an orchestrator over a
//! scripted producer.
#![expect(clippy::expect_used, reason = "test helpers must fail loudly")]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use epitrope::Clock;
use phylake::keyfile::RootKey;
use phylake::store::{NewSession, RootGrant, TenantRegistration};
use phylake::{Store, StoreOptions};
use syntheke::{
    AuditScope, Capability, CaptureLimits, CaptureRequest, Ceilings, GrantId, GrantIssueRequest,
    IdempotencyKey, InvocationId, Mode, Request, RequestBody, Response, ResponseBody, SessionId,
    SessionScope, SourceRef, TenantClass, TenantId, Timestamp,
};
use tokio::time::Instant;

use super::{Drain, Orchestrator};
use crate::cancel::{CancelHandle, cancel_pair};
use crate::fixture::{FixtureProducer, Script};
use crate::producer::{ProducerError, ProducerOutput};
use crate::server::{ConnIdentity, Dispatcher as _};

pub(super) const NOW: Timestamp = Timestamp::from_unix_millis(1_000_000);
pub(super) const OPERATOR: TenantId = TenantId::from_bytes([0x0a; 16]);
pub(super) const AGENT: TenantId = TenantId::from_bytes([0x0b; 16]);
pub(super) const ROOT: GrantId = GrantId::from_bytes([0xa0; 16]);
pub(super) const SESSION: SessionId = SessionId::from_bytes([0x5e; 16]);

pub(super) const OK: &str = "https://example.com/ok";
pub(super) const DOWN: &str = "https://example.com/down";
pub(super) const CONTACTED: &str = "https://example.com/contacted";
pub(super) const RESET: &str = "https://example.com/reset";
pub(super) const BAD: &str = "https://example.com/bad";
pub(super) const STALL: &str = "https://example.com/stall";
pub(super) const STARTED: &str = "https://example.com/started";
pub(super) const LATE: &str = "https://example.com/late";

/// The envelope the `OK` and `LATE` targets deliver: 10 000 bytes.
pub(super) fn envelope() -> Vec<u8> {
    (0..10_000_u32)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

fn output(fingerprint: &str) -> ProducerOutput {
    let source = SourceRef {
        fingerprint: fingerprint.to_owned(),
        schema_id: "zetesis.evidence.v1".to_owned(),
        producer_revision: "fixture-1".to_owned(),
    };
    ProducerOutput::new(envelope(), source, Some("é".repeat(40)))
}

fn producer() -> FixtureProducer {
    FixtureProducer::new()
        .with(OK, Script::Deliver(output("fp-ok")))
        .with(LATE, Script::DeliverOnCancel(output("fp-late")))
        .with(
            DOWN,
            Script::Fail(ProducerError::Unavailable { contacted: false }),
        )
        .with(
            CONTACTED,
            Script::Fail(ProducerError::Unavailable { contacted: true }),
        )
        .with(
            RESET,
            Script::Fail(ProducerError::Transfer {
                class: syntheke::TransferClass::Reset,
            }),
        )
        .with(
            BAD,
            Script::Fail(ProducerError::Extraction {
                class: syntheke::ExtractionClass::Malformed,
            }),
        )
        .with(
            STALL,
            Script::Stall {
                effect_started: false,
            },
        )
        .with(
            STARTED,
            Script::Stall {
                effect_started: true,
            },
        )
}

/// A wall clock a test moves by hand; the store and the orchestrator
/// share it.
#[derive(Debug)]
pub(super) struct StepClock(AtomicI64);

impl StepClock {
    /// Sets the time to `millis` since the Unix epoch.
    pub(super) fn set(&self, millis: i64) {
        self.0.store(millis, Ordering::SeqCst);
    }
}

impl Clock for StepClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0.load(Ordering::SeqCst))
    }
}

/// A store, an orchestrator over it, and the fixture producer's handle.
pub(super) struct Rig {
    _dir: tempfile::TempDir,
    pub(super) clock: Arc<StepClock>,
    pub(super) store: Arc<Store>,
    pub(super) producer: Arc<FixtureProducer>,
    pub(super) orchestrator: Orchestrator<Arc<FixtureProducer>>,
    _drain: Drain,
    next_id: std::sync::atomic::AtomicU64,
}

impl Rig {
    /// The operator (root grant over every capability, audit `All`) and
    /// an agent child tenant; the operator owns `SESSION`.
    pub(super) fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let step = Arc::new(StepClock(AtomicI64::new(NOW.unix_millis())));
        let clock: Arc<dyn Clock + Send + Sync> = step.clone();
        let root = RootKey::generate(&dir.path().join("root.key")).expect("root key");
        let store = StoreOptions::new(dir.path().join("store"), Arc::clone(&clock))
            .create(&root)
            .expect("store");
        let mut operator = TenantRegistration::new(OPERATOR, TenantClass::Operator, [1; 32]);
        operator.bound_uids = vec![0];
        store.register_tenant(&operator).expect("operator");
        let mut agent = TenantRegistration::new(AGENT, TenantClass::Agent, [2; 32]);
        agent.parent = Some(OPERATOR);
        store.register_tenant(&agent).expect("agent");
        let capabilities: BTreeSet<Capability> = Capability::ALL.iter().copied().collect();
        let mut grant = RootGrant::new(
            ROOT,
            OPERATOR,
            capabilities,
            vec!["*".to_owned()],
            (
                Timestamp::from_unix_millis(0),
                Timestamp::from_unix_millis(9_000_000),
            ),
            4,
        );
        grant.audit_scope = AuditScope::All;
        store.install_root_grant(&grant).expect("root grant");
        store
            .create_session(&NewSession::new(
                SESSION,
                OPERATOR,
                InvocationId::from_bytes([0xee; 16]),
            ))
            .expect("session");
        let store = Arc::new(store);
        let producer = Arc::new(producer());
        let (orchestrator, drain) =
            Orchestrator::new(Arc::clone(&store), Arc::clone(&producer), clock);
        Self {
            _dir: dir,
            clock: step,
            store,
            producer,
            orchestrator,
            _drain: drain,
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Dispatches `body` for `tenant` under `grant` and waits for the
    /// response.
    pub(super) async fn call(&self, tenant: TenantId, request: Request) -> Response {
        let (_handle, signal) = cancel_pair();
        self.call_with(tenant, request, signal, far(), 1024 * 1024)
            .await
    }

    /// As [`Rig::call`], with an explicit signal, deadline, and frame
    /// bound.
    pub(super) async fn call_with(
        &self,
        tenant: TenantId,
        request: Request,
        signal: crate::cancel::CancelSignal,
        deadline: Instant,
        max_frame: u32,
    ) -> Response {
        let conn = ConnIdentity {
            tenant,
            uid: 0,
            pid: None,
            version: 1,
            max_frame,
        };
        self.orchestrator
            .dispatch(conn, request, signal, deadline)
            .await
    }

    /// A request with a fresh request id.
    pub(super) fn request(
        &self,
        grant: GrantId,
        key: Option<&str>,
        mode: Mode,
        body: RequestBody,
    ) -> Request {
        Request {
            request_id: self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            grant,
            idempotency_key: key.map(idem),
            mode,
            deadline_ms: 30_000,
            body,
        }
    }

    /// Issues a child of the root grant to the agent over the operator's
    /// session scope.
    pub(super) async fn agent_grant(&self, capabilities: Vec<Capability>) -> GrantId {
        self.issue(child(AGENT, capabilities), "issue-agent-grant")
            .await
    }

    /// Issues `issue` under the root grant as the operator.
    pub(super) async fn issue(&self, issue: GrantIssueRequest, key: &str) -> GrantId {
        let request = self.request(
            ROOT,
            Some(key),
            Mode::Execute,
            RequestBody::GrantIssue(issue),
        );
        match self.call(OPERATOR, request).await.body {
            ResponseBody::GrantIssued(issued) => issued.grant,
            other => panic!("grant not issued: {other:?}"),
        }
    }

    /// Revokes `target` under the root grant as the operator.
    pub(super) async fn revoke(&self, target: GrantId, key: &str) {
        let request = self.request(
            ROOT,
            Some(key),
            Mode::Execute,
            RequestBody::GrantRevoke(syntheke::GrantRevokeRequest {
                target_grant: target,
            }),
        );
        let response = self.call(OPERATOR, request).await;
        assert!(
            matches!(response.body, ResponseBody::GrantRevoked(_)),
            "revocation failed: {response:?}"
        );
    }
}

/// A child grant request for `holder` over its own sessions on
/// example.com, valid from the epoch to 8 000 000 ms.
pub(super) fn child(holder: TenantId, capabilities: Vec<Capability>) -> GrantIssueRequest {
    GrantIssueRequest {
        holder,
        capabilities,
        session_scope: SessionScope::Own,
        target_scope: vec!["example.com".to_owned()],
        ceilings: Ceilings::default(),
        not_before: Timestamp::from_unix_millis(0),
        expires_at: Timestamp::from_unix_millis(8_000_000),
        max_depth: None,
    }
}

impl Rig {
    /// Opens a session for the agent under `grant`.
    pub(super) async fn agent_session(&self, grant: GrantId, key: &str) -> SessionId {
        let request = self.request(grant, Some(key), Mode::Execute, RequestBody::SessionCreate);
        match self.call(AGENT, request).await.body {
            ResponseBody::SessionOpened(opened) => opened.session,
            other => panic!("agent session not opened: {other:?}"),
        }
    }
}

/// A capture of `target` into `SESSION`.
pub(super) fn capture(target: &str) -> RequestBody {
    RequestBody::Capture(CaptureRequest {
        session: SESSION,
        target: target.to_owned(),
        limits: CaptureLimits {
            max_output_bytes: Some(1_000),
            max_transfer_bytes: Some(1_000_000),
        },
        egress_policy: None,
    })
}

/// An idempotency key from a label, padded to 16 bytes.
pub(super) fn idem(label: &str) -> IdempotencyKey {
    let mut bytes = label.as_bytes().to_vec();
    bytes.resize(bytes.len().max(16), b'.');
    IdempotencyKey::new(bytes).expect("key length")
}

/// A deadline far enough away never to fire in a test.
pub(super) fn far() -> Instant {
    Instant::now()
        .checked_add(Duration::from_mins(10))
        .expect("deadline")
}

/// A cancel pair whose handle the caller keeps.
pub(super) fn signal() -> (CancelHandle, crate::cancel::CancelSignal) {
    cancel_pair()
}

/// Waits until the producer has answered `calls` calls.
pub(super) async fn producer_called(producer: &FixtureProducer, calls: u64) {
    while producer.calls() < calls {
        tokio::task::yield_now().await;
    }
}
