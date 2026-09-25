//! Designated-grant authorization and the dry-run planner.

use snafu::ResultExt as _;
use syntheke::{
    Capability, Cost, DenyCode, Dimension, Failure, GrantId, InvocationState, Mode, Plan,
    SessionId, SessionScope, TenantId,
};

use crate::budget::{BudgetCheck, BudgetRefusal, LedgerState, ReservationPlan, plan_reservation};
use crate::chain::{ChainStatus, check_chain};
use crate::clock::Clock;
use crate::error::{Error, SessionNotApplicableSnafu, ViewSnafu};
use crate::grant::{Grant, in_lineage};
use crate::origin::Origin;
use crate::session::{SessionRequirement, session_requirement};
use crate::view::{LedgerId, Snapshot};

/// One call to authorize.
///
/// WHY no mode field: the decision is the same for `Execute` and `DryRun`,
/// which is what makes a dry-run an honest preview. The mode only decides
/// what the store persists; see [`Decision::next_state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthzRequest<'a> {
    /// The tenant the connection authenticated as. Never taken from the
    /// request body.
    pub tenant: TenantId,
    /// The grant the request designates. Authorization considers only this
    /// grant's chain.
    pub grant: GrantId,
    /// The capability invoked.
    pub capability: Capability,
    /// The target the caller supplied; required for `Capture`.
    pub target: Option<&'a str>,
    /// The session the call acts in. Whether one is required, optional,
    /// or forbidden is [`session_requirement`] of the capability.
    pub session: Option<SessionId>,
    /// The declared maximum cost, reserved against every ledger.
    pub declared: Cost,
}

/// The authorization decision for one call.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// The call may proceed.
    Allowed {
        /// The authorizing chain, leaf (the designated grant) first.
        chain: Vec<GrantId>,
        /// The reservation to commit at B1.
        reservation: ReservationPlan,
    },
    /// Refused for a policy reason on the caller's own grant.
    Denied {
        /// The reason.
        code: DenyCode,
    },
    /// One of the caller's own ledgers cannot cover the declared cost.
    BudgetExceeded {
        /// The exhausted dimension.
        dimension: Dimension,
    },
    /// The designated grant or the session is missing, or exists and the
    /// caller may not see it. Identical for both.
    NotFoundOrDenied,
}

impl Decision {
    /// The failure the caller observes, or `None` when allowed.
    #[must_use]
    pub const fn refusal(&self) -> Option<Failure> {
        match self {
            Self::Allowed { .. } => None,
            Self::Denied { code } => Some(Failure::denied(*code)),
            Self::BudgetExceeded { dimension } => Some(Failure::BudgetExceeded {
                dimension: *dimension,
            }),
            Self::NotFoundOrDenied => Some(Failure::NotFoundOrDenied),
        }
    }

    /// The state the invocation enters under `mode`, or `None` when the
    /// store writes nothing.
    ///
    /// An allowed `Execute` persists its intent (B1); a refused `Execute`
    /// records `Denied`. A dry-run ends in the in-memory `Planned` state
    /// when allowed, and writes nothing, including no audit, either way.
    #[must_use]
    pub const fn next_state(&self, mode: Mode) -> Option<InvocationState> {
        match (mode, self) {
            (Mode::Execute, Self::Allowed { .. }) => Some(InvocationState::IntentPersisted),
            (Mode::Execute, _) => Some(InvocationState::Denied),
            (Mode::DryRun, Self::Allowed { .. }) => Some(InvocationState::Planned),
            _ => None,
        }
    }
}

/// Decides one call against the designated grant's chain at `clock.now()`.
///
/// A call that names a session for a capability that acts in none
/// ([`SessionRequirement::Forbidden`]) is a fault, raised before any read.
/// Otherwise checks run in this order, and the first refusal wins:
///
/// 1. The designated grant exists and `request.tenant` holds it; otherwise
///    [`Decision::NotFoundOrDenied`] through one path, so a foreign grant
///    reads exactly as a missing one.
/// 2. Every link from the grant to its root is usable now
///    ([`check_chain`]).
/// 3. Every link confers the capability (`CapabilityNotGranted`).
/// 4. The capability is one this build serves; `Ingest` is refused as
///    `NotSupported` until the knowledge pipeline (D7) lands.
/// 5. A capability that requires a session names one (`SessionRequired`).
///    When the call names a session: it exists and every link's session
///    scope admits it (`Own` admits sessions whose owner is in the link
///    holder's lineage). A missing session, or one outside scope that the
///    caller does not own, is `NotFoundOrDenied`; the caller's own session
///    outside scope is `ScopeViolation`.
/// 6. A `Capture` names a target, and every link's target scope admits its
///    origin (`ScopeViolation`, also for a target that does not parse).
/// 7. Every ledger (each chain grant, the session, the tenant) covers the
///    declared cost ([`plan_reservation`]): exhaustion on one of the
///    caller's own ledgers is [`Decision::BudgetExceeded`], on any other
///    ledger `BudgetUnavailable`, which names no dimension.
///
/// # Errors
///
/// [`Error::SessionNotApplicable`], [`Error::View`],
/// [`Error::ChainBroken`], [`Error::ChainMalformed`],
/// [`Error::TenantLineage`], or [`Error::LedgerOverflow`]; the caller fails
/// closed.
pub fn authorize(
    view: &dyn Snapshot,
    request: &AuthzRequest<'_>,
    clock: &dyn Clock,
) -> Result<Decision, Error> {
    let requirement = session_requirement(request.capability);
    if request.session.is_some() && requirement == SessionRequirement::Forbidden {
        return SessionNotApplicableSnafu {
            capability: request.capability,
        }
        .fail();
    }
    let chain = match designated_chain(
        view,
        request.tenant,
        request.grant,
        request.capability,
        clock,
    )? {
        Ok(chain) => chain,
        Err(refusal) => return Ok(refusal),
    };
    // WHY here: after the grant, chain, and capability checks and before
    // any session or artifact is read, so the refusal is the same for a
    // missing, a foreign, and an own resource.
    if !is_served(request.capability) {
        return Ok(Decision::Denied {
            code: DenyCode::NotSupported,
        });
    }
    let session_owner = match request.session {
        Some(session) => match check_session(view, request.tenant, &chain, session)? {
            Ok(owner) => Some((session, owner)),
            Err(refusal) => return Ok(refusal),
        },
        None if requirement == SessionRequirement::Required => {
            return Ok(Decision::Denied {
                code: DenyCode::SessionRequired,
            });
        }
        None => None,
    };
    if !target_admitted(&chain, request.capability, request.target) {
        return Ok(Decision::Denied {
            code: DenyCode::ScopeViolation,
        });
    }
    reserve_for(
        view,
        request.tenant,
        &chain,
        session_owner,
        &request.declared,
    )
}

/// Whether this build serves `capability`. Contract version 1 defines
/// `Ingest`, and it is refused until the knowledge pipeline (D7) lands.
#[must_use]
pub const fn is_served(capability: Capability) -> bool {
    !matches!(capability, Capability::Ingest)
}

/// Checks 1 to 3 of [`authorize`]: the designated grant, its chain's
/// validity, and the capability on every link. Returns the chain, leaf
/// first, or the refusal.
///
/// # Errors
///
/// [`Error::View`], [`Error::ChainBroken`], or [`Error::ChainMalformed`];
/// the caller fails closed.
pub fn designated_chain(
    view: &dyn Snapshot,
    tenant: TenantId,
    grant: GrantId,
    capability: Capability,
    clock: &dyn Clock,
) -> Result<Result<Vec<Grant>, Decision>, Error> {
    let leaf = match view.grant(grant).context(ViewSnafu)? {
        Some(found) if found.id == grant && found.holder == tenant => found,
        _ => return Ok(Err(Decision::NotFoundOrDenied)),
    };
    let chain = match check_chain(view, leaf, clock.now())? {
        ChainStatus::Valid(chain) => chain,
        ChainStatus::Invalid { code, .. } => return Ok(Err(Decision::Denied { code })),
    };
    if !chain
        .iter()
        .all(|link| link.capabilities.contains(&capability))
    {
        return Ok(Err(Decision::Denied {
            code: DenyCode::CapabilityNotGranted,
        }));
    }
    Ok(Ok(chain))
}

/// Check 7 of [`authorize`]: plans the reservation of `declared` against
/// every ledger the call debits.
pub(crate) fn reserve_for(
    view: &dyn Snapshot,
    tenant: TenantId,
    chain: &[Grant],
    session: Option<(SessionId, TenantId)>,
    declared: &Cost,
) -> Result<Decision, Error> {
    let ledgers = ledger_states(view, tenant, chain, session)?;
    Ok(match plan_reservation(&ledgers, declared)? {
        BudgetCheck::Fits(reservation) => Decision::Allowed {
            chain: chain.iter().map(|link| link.id).collect(),
            reservation,
        },
        BudgetCheck::Exceeded(BudgetRefusal::Own { dimension, .. }) => {
            Decision::BudgetExceeded { dimension }
        }
        BudgetCheck::Exceeded(_) => Decision::Denied {
            code: DenyCode::BudgetUnavailable,
        },
    })
}

/// Checks `session` against every link; returns its owner when admitted.
fn check_session(
    view: &dyn Snapshot,
    tenant: TenantId,
    chain: &[Grant],
    session: SessionId,
) -> Result<Result<TenantId, Decision>, Error> {
    let Some(owner) = view.session_owner(session).context(ViewSnafu)? else {
        return Ok(Err(Decision::NotFoundOrDenied));
    };
    let mut admitted = true;
    for link in chain {
        admitted = match &link.session_scope {
            SessionScope::Own => in_lineage(view, owner, link.holder)?,
            SessionScope::Sessions(sessions) => sessions.contains(&session),
            _ => false,
        };
        if !admitted {
            break;
        }
    }
    Ok(if admitted {
        Ok(owner)
    } else if owner == tenant {
        Err(Decision::Denied {
            code: DenyCode::ScopeViolation,
        })
    } else {
        Err(Decision::NotFoundOrDenied)
    })
}

/// Whether the target (required for `Capture`) is inside every link's
/// target scope.
fn target_admitted(chain: &[Grant], capability: Capability, target: Option<&str>) -> bool {
    match target {
        None => capability != Capability::Capture,
        Some(target) => Origin::parse(target)
            .is_ok_and(|origin| chain.iter().all(|link| link.target_scope.matches(&origin))),
    }
}

/// Every ledger the call debits: each chain grant, the session, the tenant.
fn ledger_states(
    view: &dyn Snapshot,
    tenant: TenantId,
    chain: &[Grant],
    session: Option<(SessionId, TenantId)>,
) -> Result<Vec<LedgerState>, Error> {
    let mut ledgers = Vec::with_capacity(chain.len().saturating_add(2));
    for link in chain {
        let id = LedgerId::Grant(link.id);
        ledgers.push(LedgerState {
            id,
            ceilings: link.ceilings,
            used: view.used(id).context(ViewSnafu)?,
            own: link.holder == tenant,
        });
    }
    if let Some((session, owner)) = session {
        let id = LedgerId::Session(session);
        ledgers.push(LedgerState {
            id,
            ceilings: view.session_ceilings(session).context(ViewSnafu)?,
            used: view.used(id).context(ViewSnafu)?,
            own: owner == tenant,
        });
    }
    let id = LedgerId::Tenant(tenant);
    ledgers.push(LedgerState {
        id,
        ceilings: view.tenant_ceilings(tenant).context(ViewSnafu)?,
        used: view.used(id).context(ViewSnafu)?,
        own: true,
    });
    Ok(ledgers)
}

/// Plans a dry-run: the decision an `Execute` of the same call would get,
/// as the contract's [`Plan`].
///
/// The planner takes a [`Snapshot`], whose traits have no write method, so
/// it cannot write by construction. A refused plan carries the refusal and
/// an empty grant chain; an allowed plan carries the chain, leaf first. The
/// rule chain stays empty until a rule evaluator exists.
///
/// # Errors
///
/// As [`authorize`].
pub fn plan(
    snapshot: &dyn Snapshot,
    request: &AuthzRequest<'_>,
    clock: &dyn Clock,
) -> Result<Plan, Error> {
    let decision = authorize(snapshot, request, clock)?;
    let refusal = decision.refusal();
    let grant_chain = match decision {
        Decision::Allowed { chain, .. } => chain,
        _ => Vec::new(),
    };
    Ok(Plan {
        capability: request.capability,
        cost: request.declared,
        grant_chain,
        rule_chain: Vec::new(),
        refusal,
    })
}

#[cfg(test)]
mod tests;
