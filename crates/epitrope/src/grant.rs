//! Grants, revocation records, and delegation narrowing (contract
//! § Grants, § Delegation attenuation).

use std::collections::BTreeSet;

use snafu::ResultExt as _;
use syntheke::{
    AuditScope, AuditSeq, Capability, Ceilings, Cost, DenyCode, Dimension, GrantId,
    GrantIssueRequest, NarrowingAxis, SessionScope, TenantId, Timestamp,
};

use crate::audit::audit_scope_within;
use crate::chain::{ChainStatus, check_chain};
use crate::clock::Clock;
use crate::error::{Error, TenantLineageSnafu, ViewSnafu};
use crate::origin::TargetScope;
use crate::view::{GrantView, LedgerId, Snapshot};

/// The most parent links [`in_lineage`] follows before it reports
/// [`Error::TenantLineage`].
pub const MAX_TENANT_LINEAGE: usize = 255;

/// Whether `tenant` is `ancestor` or descends from it through tenant
/// parent links.
///
/// WHY lineage: a session scope of `Own` means the sessions the holder
/// owns, and a tenant's sub-tenants act on its behalf, so their sessions
/// count as the holder's. Without it the operator's root grant, scoped
/// `Own`, could never cover an agent's session, and no chain from it could
/// authorize an agent in its own sessions.
///
/// # Errors
///
/// [`Error::View`] when a read fails; [`Error::TenantLineage`] when the
/// parent chain does not end within [`MAX_TENANT_LINEAGE`] links.
pub fn in_lineage(
    view: &dyn GrantView,
    tenant: TenantId,
    ancestor: TenantId,
) -> Result<bool, Error> {
    let mut current = tenant;
    for _ in 0..=MAX_TENANT_LINEAGE {
        if current == ancestor {
            return Ok(true);
        }
        match view.tenant_parent(current).context(ViewSnafu)? {
            Some(parent) => current = parent,
            None => return Ok(false),
        }
    }
    TenantLineageSnafu { tenant }.fail()
}

/// A standing permission held by a tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// This grant.
    pub id: GrantId,
    /// The tenant that issued it. For a child grant, the parent's holder.
    pub issuer: TenantId,
    /// The tenant that holds it.
    pub holder: TenantId,
    /// The capabilities it confers.
    pub capabilities: BTreeSet<Capability>,
    /// The sessions it applies to. `Own` means sessions owned by the holder
    /// or by a tenant in its lineage ([`in_lineage`]).
    pub session_scope: SessionScope,
    /// The origins a `Capture` under it may target.
    pub target_scope: TargetScope,
    /// The audit records an `AuditQuery` under it may read.
    pub audit_scope: AuditScope,
    /// Per-dimension ceilings on this grant's own ledger.
    pub ceilings: Ceilings,
    /// Start of validity (inclusive).
    pub not_before: Timestamp,
    /// End of validity (exclusive).
    pub expires_at: Timestamp,
    /// The parent grant; `None` for a root grant.
    pub parent: Option<GrantId>,
    /// Links above this one; 0 for a root grant.
    pub depth: u8,
    /// The chain's maximum depth: a child of this grant must have a depth
    /// below it.
    pub max_depth: u8,
}

/// A revocation record. Revocation is recorded, not erased: the grant
/// record stays and chain validity fails at this link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revocation {
    /// The revoked grant.
    pub grant: GrantId,
    /// Audit sequence at which the revocation took effect (its epoch).
    pub at_seq: AuditSeq,
    /// Wall time of the effect.
    pub at_time: Timestamp,
}

/// The result of [`check_issue`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IssueDecision {
    /// The child attenuates its parent on every axis; this is the grant to
    /// store.
    Issued(Box<Grant>),
    /// The parent grant is missing or not held by the issuer. Identical for
    /// both.
    NotFoundOrDenied,
    /// The parent chain is not usable now.
    Denied {
        /// Why the chain is not usable.
        code: DenyCode,
    },
    /// The child does not attenuate its parent on `axis`.
    Narrowing {
        /// The first failing axis.
        axis: NarrowingAxis,
    },
}

impl IssueDecision {
    /// The failure the caller observes, or `None` when issued.
    #[must_use]
    pub const fn refusal(&self) -> Option<syntheke::Failure> {
        match self {
            Self::Issued(_) => None,
            Self::NotFoundOrDenied => Some(syntheke::Failure::NotFoundOrDenied),
            Self::Denied { code } => Some(syntheke::Failure::denied(*code)),
            Self::Narrowing { axis } => Some(syntheke::Failure::narrowing(*axis)),
        }
    }
}

/// Who issues a child grant, under which grant, and the new grant's id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssueContext {
    /// The tenant the connection authenticated as.
    pub issuer: TenantId,
    /// The grant the `GrantIssue` request designates: the child's parent.
    pub designated: GrantId,
    /// The id the new child grant will carry.
    pub child: GrantId,
}

/// Decides whether `context.issuer` may issue the child grant `request`
/// describes under the designated grant, at `clock.now()`.
///
/// The designated grant is the parent. It must be held by the issuer
/// (otherwise [`IssueDecision::NotFoundOrDenied`], identical for a missing
/// grant), its whole chain must be usable now, and every link must confer
/// `GrantIssue` ([`NarrowingAxis::IssuerAuthority`]). The child then must
/// attenuate the parent on every axis ([`narrowing_violation`]); each
/// ceiling is compared with the parent's remaining ceiling from the
/// parent's ledger.
///
/// The child's audit scope is `OwnAndOwnedSessions`: contract version 1
/// carries no audit scope in a grant request, so a delegated grant never
/// carries `All`. [`narrowing_violation`] still checks it
/// ([`NarrowingAxis::AuditScope`]) for grants built any other way.
///
/// # Errors
///
/// [`Error::View`] when a read fails, [`Error::ChainBroken`] or
/// [`Error::ChainMalformed`] when the parent chain is inconsistent, and
/// [`Error::TenantLineage`] as [`in_lineage`].
pub fn check_issue(
    view: &dyn Snapshot,
    context: &IssueContext,
    request: &GrantIssueRequest,
    clock: &dyn Clock,
) -> Result<IssueDecision, Error> {
    let IssueContext {
        issuer,
        designated,
        child,
    } = *context;
    let parent = match view.grant(designated).context(ViewSnafu)? {
        Some(parent) if parent.id == designated && parent.holder == issuer => parent,
        _ => return Ok(IssueDecision::NotFoundOrDenied),
    };
    let chain = match check_chain(view, parent, clock.now())? {
        ChainStatus::Valid(chain) => chain,
        ChainStatus::Invalid { code, .. } => return Ok(IssueDecision::Denied { code }),
    };
    if !chain
        .iter()
        .all(|link| link.capabilities.contains(&Capability::GrantIssue))
    {
        return Ok(IssueDecision::Narrowing {
            axis: NarrowingAxis::IssuerAuthority,
        });
    }
    let Some(parent) = chain.into_iter().next() else {
        // INVARIANT: check_chain returns the leaf first and never an empty
        // chain; refuse rather than issue if that ever breaks.
        return Ok(IssueDecision::NotFoundOrDenied);
    };
    let Ok(target_scope) = TargetScope::parse(&request.target_scope) else {
        return Ok(IssueDecision::Narrowing {
            axis: NarrowingAxis::TargetScope,
        });
    };
    let Some(depth) = parent.depth.checked_add(1) else {
        return Ok(IssueDecision::Narrowing {
            axis: NarrowingAxis::Depth,
        });
    };
    let candidate = Grant {
        id: child,
        issuer,
        holder: request.holder,
        capabilities: request.capabilities.iter().copied().collect(),
        session_scope: request.session_scope.clone(),
        target_scope,
        audit_scope: AuditScope::OwnAndOwnedSessions,
        ceilings: request.ceilings,
        not_before: request.not_before,
        expires_at: request.expires_at,
        parent: Some(parent.id),
        depth,
        max_depth: request.max_depth.unwrap_or(parent.max_depth),
    };
    let parent_used = view.used(LedgerId::Grant(parent.id)).context(ViewSnafu)?;
    Ok(
        match narrowing_violation(view, &parent, &parent_used, &candidate)? {
            Some(axis) => IssueDecision::Narrowing { axis },
            None => IssueDecision::Issued(Box::new(candidate)),
        },
    )
}

/// The first axis on which `child` fails to attenuate `parent`, or `None`
/// when it attenuates on every axis.
///
/// Axes are checked in the order capabilities, audit scope, session scope,
/// target scope, ceilings, expiry, depth, issuer authority:
///
/// - capabilities: a subset of the parent's;
/// - audit scope: at most the parent's ([`audit_scope_within`]);
/// - session scope: `Own` under `Own` only when the child's holder is in the
///   parent holder's lineage; an explicit set under `Own` only when every
///   session exists and its owner is in the parent holder's lineage; an
///   explicit set under an explicit set only as a subset; `Own` under an
///   explicit set never;
/// - target scope: every child pattern covered by a parent pattern;
/// - ceilings: where the parent sets a ceiling, the child sets one no larger
///   than the parent's ceiling minus `parent_used`;
/// - expiry: `parent.not_before <= child.not_before < child.expires_at <=
///   parent.expires_at`;
/// - depth: the child is one below the parent, its depth is below the
///   parent's maximum, and its maximum is at most the parent's;
/// - issuer authority: the child names the parent and is issued by the
///   parent's holder.
///
/// # Errors
///
/// [`Error::View`] when a read fails; [`Error::TenantLineage`] as
/// [`in_lineage`].
pub fn narrowing_violation(
    view: &dyn GrantView,
    parent: &Grant,
    parent_used: &Cost,
    child: &Grant,
) -> Result<Option<NarrowingAxis>, Error> {
    let checks: [(NarrowingAxis, bool); 8] = [
        (
            NarrowingAxis::Capabilities,
            child.capabilities.is_subset(&parent.capabilities),
        ),
        (
            NarrowingAxis::AuditScope,
            audit_scope_within(child.audit_scope, parent.audit_scope),
        ),
        (
            NarrowingAxis::SessionScope,
            session_scope_within(view, parent, child)?,
        ),
        (
            NarrowingAxis::TargetScope,
            parent.target_scope.covers(&child.target_scope),
        ),
        (
            NarrowingAxis::Ceilings,
            ceilings_within(&parent.ceilings, parent_used, &child.ceilings),
        ),
        (
            NarrowingAxis::Expiry,
            parent.not_before <= child.not_before
                && child.not_before < child.expires_at
                && child.expires_at <= parent.expires_at,
        ),
        (
            NarrowingAxis::Depth,
            parent.depth.checked_add(1) == Some(child.depth)
                && child.depth < parent.max_depth
                && child.max_depth <= parent.max_depth,
        ),
        (
            NarrowingAxis::IssuerAuthority,
            child.parent == Some(parent.id) && child.issuer == parent.holder,
        ),
    ];
    Ok(checks
        .into_iter()
        .find_map(|(axis, holds)| (!holds).then_some(axis)))
}

/// Whether `child`'s session scope admits no session `parent`'s refuses.
fn session_scope_within(
    view: &dyn GrantView,
    parent: &Grant,
    child: &Grant,
) -> Result<bool, Error> {
    Ok(match (&parent.session_scope, &child.session_scope) {
        (SessionScope::Own, SessionScope::Own) => in_lineage(view, child.holder, parent.holder)?,
        (SessionScope::Own, SessionScope::Sessions(sessions)) => {
            for &session in sessions {
                let admitted = match view.session_owner(session).context(ViewSnafu)? {
                    Some(owner) => in_lineage(view, owner, parent.holder)?,
                    None => false,
                };
                if !admitted {
                    return Ok(false);
                }
            }
            true
        }
        (SessionScope::Sessions(allowed), SessionScope::Sessions(sessions)) => {
            sessions.iter().all(|session| allowed.contains(session))
        }
        // WHY false: `Own` under an explicit set would follow the child
        // holder's future sessions, which the parent never named; an
        // unknown scope from a later contract version fails closed.
        _ => false,
    })
}

/// Whether each child ceiling is within the parent's remaining ceiling.
fn ceilings_within(parent: &Ceilings, parent_used: &Cost, child: &Ceilings) -> bool {
    Dimension::ALL.iter().all(
        |&dimension| match (parent.get(dimension), child.get(dimension)) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(ceiling), Some(amount)) => {
                amount <= ceiling.saturating_sub(parent_used.get(dimension))
            }
        },
    )
}

#[cfg(test)]
mod tests;
