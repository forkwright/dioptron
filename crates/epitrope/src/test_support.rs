//! In-memory views and the synthetic cast shared by the unit tests.
//!
//! The cast follows the contract fixtures: the operator holds root grant
//! `A`, agent `B` holds `B` (a child of `A`) and owns session `S`,
//! sub-agent `C` holds `C` (a child of `B` issued by agent `B`), and tenant
//! `F` holds nothing on `B`'s sessions.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use syntheke::{
    AuditScope, AuditSeq, Capability, Ceilings, Cost, GrantId, SessionId, SessionScope, TenantId,
    Timestamp,
};

use crate::grant::{Grant, Revocation};
use crate::origin::TargetScope;
use crate::view::{GrantView, LedgerId, LedgerView, ViewError};

pub(crate) const OPERATOR: TenantId = TenantId::from_bytes([0x0a; 16]);
pub(crate) const AGENT: TenantId = TenantId::from_bytes([0x0b; 16]);
pub(crate) const SUB: TenantId = TenantId::from_bytes([0x0c; 16]);
pub(crate) const FOREIGN: TenantId = TenantId::from_bytes([0x0f; 16]);

pub(crate) const G_ROOT: GrantId = GrantId::from_bytes([0xa0; 16]);
pub(crate) const G_AGENT: GrantId = GrantId::from_bytes([0xb0; 16]);
pub(crate) const G_SUB: GrantId = GrantId::from_bytes([0xc0; 16]);
pub(crate) const G_FOREIGN: GrantId = GrantId::from_bytes([0xf0; 16]);
pub(crate) const G_MISSING: GrantId = GrantId::from_bytes([0xee; 16]);
pub(crate) const G_NEW: GrantId = GrantId::from_bytes([0xd0; 16]);

pub(crate) const S_AGENT: SessionId = SessionId::from_bytes([0x5b; 16]);
pub(crate) const S_OPERATOR: SessionId = SessionId::from_bytes([0x5a; 16]);
pub(crate) const S_FOREIGN: SessionId = SessionId::from_bytes([0x5f; 16]);
pub(crate) const S_MISSING: SessionId = SessionId::from_bytes([0x5e; 16]);

/// The instant most tests run at.
pub(crate) const NOW: Timestamp = Timestamp::from_unix_millis(1_000_000);
/// When the root grant expires.
pub(crate) const ROOT_EXPIRES: Timestamp = Timestamp::from_unix_millis(9_000_000);
/// When the agent and sub-agent grants expire.
pub(crate) const CHILD_EXPIRES: Timestamp = Timestamp::from_unix_millis(5_000_000);

pub(crate) fn ts(millis: i64) -> Timestamp {
    Timestamp::from_unix_millis(millis)
}

pub(crate) fn caps(list: &[Capability]) -> BTreeSet<Capability> {
    list.iter().copied().collect()
}

pub(crate) fn scope(patterns: &[&str]) -> TargetScope {
    match TargetScope::parse(patterns) {
        Ok(scope) => scope,
        Err(error) => panic!("test pattern must parse: {error}"),
    }
}

pub(crate) fn ceilings(fetches: u64, bytes: u64) -> Ceilings {
    Ceilings {
        fetches: Some(fetches),
        bytes_transferred: Some(bytes),
        ..Ceilings::default()
    }
}

/// The operator's root grant: every capability, every target, its own
/// lineage's sessions.
pub(crate) fn root_grant() -> Grant {
    Grant {
        id: G_ROOT,
        issuer: OPERATOR,
        holder: OPERATOR,
        capabilities: Capability::ALL.iter().copied().collect(),
        session_scope: SessionScope::Own,
        target_scope: scope(&["*"]),
        audit_scope: AuditScope::All,
        ceilings: ceilings(100, 1_048_576),
        not_before: ts(0),
        expires_at: ROOT_EXPIRES,
        parent: None,
        depth: 0,
        max_depth: 4,
    }
}

/// A child of `parent` held by `holder`, copying the parent's axes.
pub(crate) fn child_of(parent: &Grant, id: GrantId, holder: TenantId) -> Grant {
    Grant {
        id,
        issuer: parent.holder,
        holder,
        capabilities: parent.capabilities.clone(),
        session_scope: parent.session_scope.clone(),
        target_scope: parent.target_scope.clone(),
        audit_scope: AuditScope::OwnAndOwnedSessions,
        ceilings: parent.ceilings,
        not_before: parent.not_before,
        expires_at: parent.expires_at,
        parent: Some(parent.id),
        depth: parent.depth.saturating_add(1),
        max_depth: parent.max_depth,
    }
}

pub(crate) fn agent_grant() -> Grant {
    Grant {
        capabilities: caps(&[
            Capability::SessionCreate,
            Capability::Capture,
            Capability::Read,
            Capability::GrantIssue,
        ]),
        target_scope: scope(&["example.com", "*.example.org"]),
        ceilings: ceilings(10, 524_288),
        expires_at: CHILD_EXPIRES,
        ..child_of(&root_grant(), G_AGENT, AGENT)
    }
}

pub(crate) fn sub_grant() -> Grant {
    Grant {
        capabilities: caps(&[Capability::Capture, Capability::Read]),
        session_scope: SessionScope::Sessions(vec![S_AGENT]),
        target_scope: scope(&["https://example.com"]),
        ceilings: ceilings(2, 65_536),
        ..child_of(&agent_grant(), G_SUB, SUB)
    }
}

/// A root grant held by the foreign tenant.
pub(crate) fn foreign_grant() -> Grant {
    Grant {
        id: G_FOREIGN,
        issuer: FOREIGN,
        holder: FOREIGN,
        ..root_grant()
    }
}

/// An in-memory snapshot that counts reads and can be told to fail.
#[derive(Default)]
pub(crate) struct MemView {
    pub(crate) grants: BTreeMap<GrantId, Grant>,
    pub(crate) revocations: BTreeMap<GrantId, Revocation>,
    pub(crate) owners: BTreeMap<SessionId, TenantId>,
    pub(crate) parents: BTreeMap<TenantId, TenantId>,
    pub(crate) used: BTreeMap<LedgerId, Cost>,
    pub(crate) session_ceilings: BTreeMap<SessionId, Ceilings>,
    pub(crate) tenant_ceilings: BTreeMap<TenantId, Ceilings>,
    pub(crate) reads: Cell<usize>,
    pub(crate) fail: bool,
}

impl MemView {
    /// The fixture cast.
    pub(crate) fn cast() -> Self {
        let mut view = Self::default();
        for grant in [root_grant(), agent_grant(), sub_grant(), foreign_grant()] {
            view.grants.insert(grant.id, grant);
        }
        view.owners.insert(S_AGENT, AGENT);
        view.owners.insert(S_OPERATOR, OPERATOR);
        view.owners.insert(S_FOREIGN, FOREIGN);
        view.parents.insert(AGENT, OPERATOR);
        view.parents.insert(SUB, AGENT);
        view
    }

    pub(crate) fn revoke(&mut self, grant: GrantId) {
        self.revocations.insert(
            grant,
            Revocation {
                grant,
                at_seq: AuditSeq::new(7),
                at_time: NOW,
            },
        );
    }

    pub(crate) fn set_used(&mut self, ledger: LedgerId, used: Cost) {
        self.used.insert(ledger, used);
    }

    fn read(&self) -> Result<(), ViewError> {
        self.reads.set(self.reads.get().saturating_add(1));
        if self.fail {
            Err(ViewError::new("synthetic read failure"))
        } else {
            Ok(())
        }
    }
}

impl GrantView for MemView {
    fn grant(&self, id: GrantId) -> Result<Option<Grant>, ViewError> {
        self.read()?;
        Ok(self.grants.get(&id).cloned())
    }

    fn revocation(&self, id: GrantId) -> Result<Option<Revocation>, ViewError> {
        self.read()?;
        Ok(self.revocations.get(&id).copied())
    }

    fn session_owner(&self, id: SessionId) -> Result<Option<TenantId>, ViewError> {
        self.read()?;
        Ok(self.owners.get(&id).copied())
    }

    fn tenant_parent(&self, id: TenantId) -> Result<Option<TenantId>, ViewError> {
        self.read()?;
        Ok(self.parents.get(&id).copied())
    }
}

impl LedgerView for MemView {
    fn used(&self, id: LedgerId) -> Result<Cost, ViewError> {
        self.read()?;
        Ok(self.used.get(&id).copied().unwrap_or_default())
    }

    fn session_ceilings(&self, id: SessionId) -> Result<Ceilings, ViewError> {
        self.read()?;
        Ok(self.session_ceilings.get(&id).copied().unwrap_or_default())
    }

    fn tenant_ceilings(&self, id: TenantId) -> Result<Ceilings, ViewError> {
        self.read()?;
        Ok(self.tenant_ceilings.get(&id).copied().unwrap_or_default())
    }
}
