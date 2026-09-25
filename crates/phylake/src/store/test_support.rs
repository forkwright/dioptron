//! Test-only helpers for the store: a settable clock, reproducible
//! entropy, a crash failpoint, a seeded cast of tenants and grants, a
//! stand-in producer counter, and logical and raw-disk dumps.
#![expect(clippy::expect_used, reason = "test helpers must fail loudly")]

use std::collections::BTreeSet;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

use epitrope::{AuthzRequest, Clock, IssueContext, LedgerId, LedgerView as _};
use fjall::Readable as _;
use sha2::{Digest as _, Sha256};
use syntheke::{
    ArtifactRef, Capability, Ceilings, Cost, GrantId, GrantIssueRequest, IdempotencyKey,
    InvocationId, SessionId, SessionScope, SourceRef, TenantClass, TenantId, Timestamp,
};

use syntheke::{AuditRecord, QueryPage, ReadChunk};

use super::keyring::TenantKeyring;
use super::{
    ALL_KEYSPACES, ArtifactInfo, Begin, Boundary, Crash, Failpoint, GrantIssue, Intent,
    IssueOutcome, NewSession, Phase, RootGrant, SettleOutcome, Slot, Store, StoreOptions,
    TenantRegistration, Transfer, slot,
};
use crate::Result;
use crate::crypto::{Entropy, KeyId, Keyspace, SealingKey, sealed_key_id};
use crate::keyfile::RootKey;

/// The root key every fixture store uses.
pub(crate) const ROOT_BYTES: [u8; 32] = [0x5a; 32];

/// The instant tests run at.
pub(crate) const NOW: Timestamp = Timestamp::from_unix_millis(1_000_000);

/// The operator. Ids are ASCII so a raw-disk scan can look for them.
pub(crate) const OPERATOR: TenantId = TenantId::from_bytes(*b"TENANT-OPERATOR1");
/// An agent, child of the operator.
pub(crate) const AGENT: TenantId = TenantId::from_bytes(*b"TENANT-AGENT-017");
/// A second agent with no grant on the first agent's sessions.
pub(crate) const OTHER: TenantId = TenantId::from_bytes(*b"TENANT-OTHER-042");

/// The operator's root grant.
pub(crate) const G_ROOT: GrantId = GrantId::from_bytes([0xa0; 16]);
/// The agent's grant, a child of the root.
pub(crate) const G_AGENT: GrantId = GrantId::from_bytes([0xb0; 16]);

/// The agent's session.
pub(crate) const S_AGENT: SessionId = SessionId::from_bytes(*b"SESSION-AGENT-01");

/// The target every capture names.
pub(crate) const TARGET: &str = "https://example.com/custody-marker/7f3a";

/// A clock tests can move.
#[derive(Debug)]
pub(crate) struct TestClock(AtomicI64);

impl TestClock {
    /// A clock at [`NOW`].
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(NOW.unix_millis())))
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_unix_millis(self.0.load(Ordering::SeqCst))
    }
}

/// Reproducible entropy: SHA-256 of a process-wide counter. Each draw is
/// distinct within a process, so nonces never repeat across reopens.
pub(crate) struct CountingEntropy;

static ENTROPY_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Entropy for CountingEntropy {
    fn fill<'a>(&mut self, dest: &'a mut [MaybeUninit<u8>]) -> Result<&'a mut [u8]> {
        let mut drawn = Vec::with_capacity(dest.len());
        while drawn.len() < dest.len() {
            let counter = ENTROPY_COUNTER.fetch_add(1, Ordering::SeqCst);
            let block: [u8; 32] = Sha256::new()
                .chain_update(b"phylake-test-entropy")
                .chain_update(counter.to_le_bytes())
                .finalize()
                .into();
            drawn.extend_from_slice(&block);
        }
        drawn.truncate(dest.len());
        Ok(dest.write_copy_of_slice(&drawn))
    }
}

/// A failpoint that crashes at one boundary and phase.
#[derive(Debug)]
pub(crate) struct CrashAt {
    pub(crate) boundary: Boundary,
    pub(crate) phase: Phase,
}

impl Failpoint for CrashAt {
    fn before_commit(&self, boundary: Boundary) -> Result<(), Crash> {
        if boundary == self.boundary && self.phase == Phase::BeforeCommit {
            return Err(Crash);
        }
        Ok(())
    }

    fn after_commit(&self, boundary: Boundary) -> Result<(), Crash> {
        if boundary == self.boundary && self.phase == Phase::AfterCommit {
            return Err(Crash);
        }
        Ok(())
    }
}

/// Stands in for the producer: counts calls, never touches the store.
#[derive(Debug, Default)]
pub(crate) struct ProducerCounter(AtomicU32);

impl ProducerCounter {
    /// Records one producer call.
    pub(crate) fn call(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    /// Calls so far.
    pub(crate) fn calls(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A store directory in a tempdir.
pub(crate) struct Fixture {
    _dir: tempfile::TempDir,
    pub(crate) path: PathBuf,
    pub(crate) clock: Arc<TestClock>,
}

impl Fixture {
    /// A fresh tempdir; no store yet.
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("store");
        Self {
            _dir: dir,
            path,
            clock: TestClock::new(),
        }
    }

    /// Options for this fixture's store.
    pub(crate) fn options(&self) -> StoreOptions {
        let clock: Arc<dyn Clock + Send + Sync> = self.clock.clone();
        StoreOptions::new(&self.path, clock).entropy(Box::new(CountingEntropy))
    }

    /// Creates the store.
    pub(crate) fn create(&self) -> Store {
        self.options()
            .create(&RootKey::from_bytes(ROOT_BYTES))
            .expect("create store")
    }

    /// Creates the store and seeds the cast.
    pub(crate) fn seeded(&self) -> Store {
        let store = self.create();
        seed(&store);
        store
    }

    /// Reopens the store with no failpoint.
    pub(crate) fn reopen(&self) -> Store {
        self.options()
            .open(&RootKey::from_bytes(ROOT_BYTES))
            .expect("reopen store")
    }

    /// Reopens the store with `failpoint`.
    pub(crate) fn reopen_with(&self, failpoint: Arc<dyn Failpoint>) -> Store {
        self.options()
            .failpoint(failpoint)
            .open(&RootKey::from_bytes(ROOT_BYTES))
            .expect("reopen store")
    }
}

/// Ceilings with `fetches` and `bytes_transferred` set.
pub(crate) const fn ceilings(fetches: u64, bytes: u64) -> Ceilings {
    Ceilings {
        wall_time_ms: None,
        fetches: Some(fetches),
        bytes_transferred: Some(bytes),
        output_bytes: None,
        tokens: None,
        ops_band: None,
    }
}

/// Registers the operator, the agent, and the other agent; installs the
/// root grant; issues the agent's grant; opens the agent's session.
pub(crate) fn seed(store: &Store) {
    for (id, class, parent) in [
        (OPERATOR, TenantClass::Operator, None),
        (AGENT, TenantClass::Agent, Some(OPERATOR)),
        (OTHER, TenantClass::Agent, Some(OPERATOR)),
    ] {
        let mut registration = TenantRegistration::new(id, class, [0x77; 32]);
        registration.parent = parent;
        registration.bound_uids = vec![1000];
        store.register_tenant(&registration).expect("register");
    }
    let mut root = RootGrant::new(
        G_ROOT,
        OPERATOR,
        Capability::ALL.iter().copied().collect(),
        vec!["*".to_owned()],
        (
            Timestamp::from_unix_millis(0),
            Timestamp::from_unix_millis(9_000_000),
        ),
        4,
    );
    root.ceilings = ceilings(100, 1_048_576);
    store.install_root_grant(&root).expect("root grant");
    issue_agent_grant(store, G_AGENT, ceilings(10, 524_288));
    store
        .create_session(&NewSession::new(S_AGENT, AGENT, invocation(0xe0)))
        .expect("session");
}

/// Issues a grant under the root to the agent.
pub(crate) fn issue_agent_grant(store: &Store, id: GrantId, ceilings: Ceilings) {
    let request = GrantIssueRequest {
        holder: AGENT,
        capabilities: vec![
            Capability::SessionCreate,
            Capability::Capture,
            Capability::Read,
            Capability::GrantIssue,
        ],
        session_scope: SessionScope::Own,
        target_scope: vec!["example.com".to_owned()],
        ceilings,
        not_before: Timestamp::from_unix_millis(0),
        expires_at: Timestamp::from_unix_millis(5_000_000),
        max_depth: None,
    };
    let context = IssueContext {
        issuer: OPERATOR,
        designated: G_ROOT,
        child: id,
    };
    let outcome = store
        .issue_grant(&GrantIssue::new(context, &request, invocation(0xe1)))
        .expect("issue");
    assert!(
        matches!(outcome, IssueOutcome::Issued { .. }),
        "the agent grant attenuates the root: {outcome:?}"
    );
}

/// An invocation id from one byte.
pub(crate) const fn invocation(byte: u8) -> InvocationId {
    InvocationId::from_bytes([byte; 16])
}

/// An artifact id from one byte.
pub(crate) const fn artifact(byte: u8) -> ArtifactRef {
    ArtifactRef::from_bytes([byte; 16])
}

/// A 24-byte idempotency key from one byte.
pub(crate) fn idem(byte: u8) -> IdempotencyKey {
    IdempotencyKey::new(vec![byte; 24]).expect("key length")
}

/// The declared maximum of every test capture.
pub(crate) const DECLARED: Cost = Cost {
    wall_time_ms: 1_000,
    fetches: 1,
    bytes_transferred: 4_096,
    output_bytes: 1_024,
    tokens: 0,
    ops_band: 0,
};

/// The actual consumption of every test capture.
pub(crate) const ACTUAL: Cost = Cost {
    wall_time_ms: 300,
    fetches: 1,
    bytes_transferred: 2_000,
    output_bytes: 500,
    tokens: 0,
    ops_band: 0,
};

/// The agent's capture of [`TARGET`] into its session under `grant`.
pub(crate) const fn capture(grant: GrantId) -> AuthzRequest<'static> {
    AuthzRequest {
        tenant: AGENT,
        grant,
        capability: Capability::Capture,
        target: Some(TARGET),
        session: Some(S_AGENT),
        declared: DECLARED,
    }
}

/// The envelope every test capture stores.
pub(crate) const ENVELOPE: &[u8] =
    b"<html><body>PHYLAKE-CUSTODY-PLAINTEXT-7f3a from https://example.com/custody-marker/7f3a</body></html>";

/// The source reference of every test capture.
pub(crate) fn source() -> SourceRef {
    SourceRef {
        fingerprint: format!("fp:{TARGET}"),
        schema_id: "zetesis.evidence.v1".to_owned(),
        producer_revision: "fixture-1".to_owned(),
    }
}

/// Every ledger a capture under `G_AGENT` debits.
pub(crate) const CAPTURE_LEDGERS: [LedgerId; 4] = [
    LedgerId::Grant(G_AGENT),
    LedgerId::Grant(G_ROOT),
    LedgerId::Session(S_AGENT),
    LedgerId::Tenant(AGENT),
];

/// The used amount on each capture ledger.
pub(crate) fn ledger_usage(store: &Store) -> Vec<Cost> {
    let snapshot = store.snapshot();
    CAPTURE_LEDGERS
        .iter()
        .map(|&ledger| snapshot.used(ledger).expect("ledger read"))
        .collect()
}

/// One keyspace's raw entries.
pub(crate) type Entries = Vec<(Vec<u8>, Vec<u8>)>;

/// Every keyspace's raw keys and values, by keyspace name.
pub(crate) type Dump = Vec<(&'static str, Entries)>;

/// Every keyspace's raw keys and values, from one snapshot.
pub(crate) fn dump(store: &Store) -> Dump {
    let snapshot = store.db.read_tx();
    ALL_KEYSPACES
        .iter()
        .map(|&keyspace| {
            let handle = store.ks.get(keyspace).expect("keyspace");
            let entries = snapshot
                .iter(handle)
                .map(|guard| {
                    let (key, value) = guard.into_inner().expect("entry");
                    (key.to_vec(), value.to_vec())
                })
                .collect();
            (keyspace.name(), entries)
        })
        .collect()
}

/// The number of entries in `keyspace` of a dump.
pub(crate) fn count(dump: &Dump, keyspace: &str) -> usize {
    dump.iter()
        .find(|(name, _)| *name == keyspace)
        .map_or(0, |(_, entries)| entries.len())
}

/// The contents of every file under `root`.
pub(crate) fn read_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let mut bytes = std::fs::read(&path).expect("read file");
                // WHY: fjall preallocates each journal file to 64 MiB of
                // zeros. Dropping the zero tail, less a margin longer than
                // any needle, keeps the scan fast without hiding a needle
                // that ends in zero bytes.
                let used = bytes
                    .iter()
                    .rposition(|&byte| byte != 0)
                    .map_or(0, |last| last.saturating_add(65));
                bytes.truncate(used);
                files.push((path, bytes));
            }
        }
    }
    files
}

/// Occurrences of `needle` in `haystack`.
pub(crate) fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// The set of capabilities in `list`.
pub(crate) fn caps(list: &[Capability]) -> BTreeSet<Capability> {
    list.iter().copied().collect()
}

/// The root key rotation tests move to.
pub(crate) const NEXT_ROOT_BYTES: [u8; 32] = [0xa5; 32];

/// A failpoint that crashes the `nth` time (counting from 1) `boundary`
/// reaches `phase`.
#[derive(Debug)]
pub(crate) struct CrashAtNth {
    boundary: Boundary,
    phase: Phase,
    nth: u32,
    hits: AtomicU32,
}

impl CrashAtNth {
    /// Crashes at the `nth` hit of `boundary` in `phase`.
    pub(crate) fn new(boundary: Boundary, phase: Phase, nth: u32) -> Arc<Self> {
        Arc::new(Self {
            boundary,
            phase,
            nth,
            hits: AtomicU32::new(0),
        })
    }

    fn hit(&self, boundary: Boundary, phase: Phase) -> Result<(), Crash> {
        if boundary == self.boundary && phase == self.phase {
            let hits = self.hits.fetch_add(1, Ordering::SeqCst).saturating_add(1);
            if hits == self.nth {
                return Err(Crash);
            }
        }
        Ok(())
    }
}

impl Failpoint for CrashAtNth {
    fn before_commit(&self, boundary: Boundary) -> Result<(), Crash> {
        self.hit(boundary, Phase::BeforeCommit)
    }

    fn after_commit(&self, boundary: Boundary) -> Result<(), Crash> {
        self.hit(boundary, Phase::AfterCommit)
    }
}

/// Runs one capture by the agent under [`G_AGENT`] through B5 and returns
/// its artifact. `byte` picks the invocation, artifact, and idempotency
/// key; `envelope` is stored verbatim.
pub(crate) fn publish_capture(store: &Store, byte: u8, envelope: &[u8]) -> ArtifactRef {
    let key = idem(byte);
    let begin = store
        .begin(&Intent::new(
            invocation(byte),
            capture(G_AGENT),
            &key,
            [byte; 32],
        ))
        .expect("B1");
    assert!(matches!(begin, Begin::Persisted(_)), "{begin:?}");
    store.dispatch(invocation(byte)).expect("B2");
    let transfer = Transfer::new(artifact(byte), envelope, source(), ACTUAL);
    store
        .complete_transfer(invocation(byte), &transfer)
        .expect("B3");
    store.publish(invocation(byte)).expect("B4");
    store
        .settle(invocation(byte), SettleOutcome::Success)
        .expect("B5");
    artifact(byte)
}

/// What a reader sees of the agent's captures, session, and audit trail.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Reads {
    pub(crate) artifacts: Vec<Option<ArtifactInfo>>,
    pub(crate) envelopes: Vec<Option<ReadChunk>>,
    pub(crate) session: Option<QueryPage>,
    pub(crate) audit: Vec<AuditRecord>,
}

/// Reads `artifacts`, their envelopes, the agent's session, and the
/// agent's audit trail.
pub(crate) fn reads(store: &Store, artifacts: &[ArtifactRef]) -> Reads {
    Reads {
        artifacts: artifacts
            .iter()
            .map(|&id| store.artifact(id).expect("artifact"))
            .collect(),
        envelopes: artifacts
            .iter()
            .map(|&id| store.read_artifact(id, 0, 1 << 20).expect("envelope"))
            .collect(),
        session: store
            .session_artifacts(S_AGENT, None, 100)
            .expect("session"),
        audit: store.audit_records(AGENT, None, 1000).expect("audit"),
    }
}

/// Which of a keyring's opener sets a record kind uses.
type Openers = fn(&TenantKeyring) -> [&SealingKey; 2];

/// Tenant-sealed record kinds and the keys that open each, listed
/// independently of the rekey walk.
const TENANT_SLOTS: [(Slot, Openers); 6] = [
    (slot::IDEM, TenantKeyring::meta_openers),
    (slot::ARTIFACT, TenantKeyring::meta_openers),
    (slot::PENDING_ARTIFACT, TenantKeyring::meta_openers),
    (slot::BLOB, TenantKeyring::blob_openers),
    (slot::SESSION_INDEX, TenantKeyring::meta_openers),
    (slot::AUDIT, TenantKeyring::audit_openers),
];

/// One tenant-sealed record: keyspace, record key, header key id.
pub(crate) type SealedRecord = (&'static str, Vec<u8>, KeyId);

/// Every record sealed under `tenant`'s keys that its keyring opens.
pub(crate) fn tenant_sealed(store: &Store, tenant: TenantId) -> Vec<SealedRecord> {
    let snapshot = store.db.read_tx();
    let keys = store.tenant_keys(&snapshot, tenant).expect("keyring");
    let mut found = Vec::new();
    for (slot, openers) in TENANT_SLOTS {
        for guard in snapshot.iter(store.ks.get(slot.keyspace).expect("keyspace")) {
            let (key, sealed) = guard.into_inner().expect("entry");
            if Store::open_bytes(&openers(&keys), slot, &key, &sealed).is_ok() {
                let id = sealed_key_id(&sealed).expect("header");
                found.push((slot.keyspace.name(), key.to_vec(), id));
            }
        }
    }
    found
}

/// The raw value at `key` in `keyspace`.
pub(crate) fn raw(store: &Store, keyspace: Keyspace, key: &[u8]) -> Option<Vec<u8>> {
    store
        .db
        .read_tx()
        .get(store.ks.get(keyspace).expect("keyspace"), key)
        .expect("read")
        .map(|value| value.to_vec())
}

/// Copies the directory tree at `from` to `to`, which must not exist.
pub(crate) fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir(to).expect("create copy");
    for entry in std::fs::read_dir(from).expect("read_dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

/// Total occurrences of `needle` in every file under `root`.
pub(crate) fn disk_hits(root: &Path, needle: &[u8]) -> usize {
    read_tree(root)
        .iter()
        .map(|(_, bytes)| occurrences(bytes, needle))
        .sum()
}
