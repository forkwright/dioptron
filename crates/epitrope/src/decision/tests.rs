use syntheke::{Ceilings, SessionScope, Timestamp};

use super::*;
use crate::clock::FixedClock;
use crate::session::{SessionRequirement, session_requirement};
use crate::test_support::{
    AGENT, CHILD_EXPIRES, FOREIGN, G_AGENT, G_FOREIGN, G_MISSING, G_ROOT, G_SUB, MemView, NOW,
    S_AGENT, S_FOREIGN, S_MISSING, S_OPERATOR, SUB, sub_grant,
};

const TARGET: &str = "https://example.com/article";
/// A session the sub-agent owns but its grant does not name.
const S_SUB: SessionId = SessionId::from_bytes([0x5c; 16]);

fn cast() -> MemView {
    let mut view = MemView::cast();
    view.owners.insert(S_SUB, SUB);
    view
}

fn one_fetch() -> Cost {
    Cost {
        fetches: 1,
        bytes_transferred: 4_096,
        ..Cost::default()
    }
}

/// The sub-agent capturing the fixture target into the agent's session.
fn capture() -> AuthzRequest<'static> {
    AuthzRequest {
        tenant: SUB,
        grant: G_SUB,
        capability: Capability::Capture,
        target: Some(TARGET),
        session: Some(S_AGENT),
        declared: one_fetch(),
    }
}

fn decide(view: &MemView, request: &AuthzRequest<'_>) -> Result<Decision, Error> {
    authorize(view, request, &FixedClock(NOW))
}

fn denied(code: DenyCode) -> Decision {
    Decision::Denied { code }
}

#[test]
fn authorize_allows_a_capture_and_plans_every_ledger() -> Result<(), Error> {
    let decision = decide(&cast(), &capture())?;
    let Decision::Allowed { chain, reservation } = decision else {
        panic!("the fixture capture is allowed, got {decision:?}");
    };
    assert_eq!(chain, [G_SUB, G_AGENT, G_ROOT], "leaf first");
    assert_eq!(
        reservation.ledgers(),
        &[
            LedgerId::Grant(G_SUB),
            LedgerId::Grant(G_AGENT),
            LedgerId::Grant(G_ROOT),
            LedgerId::Session(S_AGENT),
            LedgerId::Tenant(SUB),
        ],
        "chain, session, and tenant ledgers"
    );
    assert_eq!(reservation.cost(), one_fetch(), "declared maximum");
    Ok(())
}

#[test]
fn authorize_answers_foreign_and_missing_grants_identically() -> Result<(), Error> {
    let view = cast();
    let foreign = decide(
        &view,
        &AuthzRequest {
            tenant: FOREIGN,
            ..capture()
        },
    )?;
    let missing = decide(
        &view,
        &AuthzRequest {
            tenant: FOREIGN,
            grant: G_MISSING,
            ..capture()
        },
    )?;
    assert_eq!(foreign, Decision::NotFoundOrDenied, "foreign grant");
    assert_eq!(foreign, missing, "a foreign grant reads as a missing one");
    assert_eq!(
        foreign.refusal(),
        Some(Failure::NotFoundOrDenied),
        "one outcome on the wire"
    );
    let own_grant_other_tenant = decide(
        &view,
        &AuthzRequest {
            tenant: SUB,
            grant: G_FOREIGN,
            ..capture()
        },
    )?;
    assert_eq!(
        own_grant_other_tenant, missing,
        "holding some grant does not unlock another tenant's"
    );
    let foreign_plan = plan(
        &view,
        &AuthzRequest {
            tenant: FOREIGN,
            ..capture()
        },
        &FixedClock(NOW),
    )?;
    let missing_plan = plan(
        &view,
        &AuthzRequest {
            tenant: FOREIGN,
            grant: G_MISSING,
            ..capture()
        },
        &FixedClock(NOW),
    )?;
    assert_eq!(
        foreign_plan, missing_plan,
        "dry-run plans are identical too"
    );
    let mut misfiled = cast();
    misfiled.grants.insert(G_MISSING, sub_grant());
    assert_eq!(
        decide(
            &misfiled,
            &AuthzRequest {
                grant: G_MISSING,
                ..capture()
            }
        )?,
        missing,
        "a view answer for a different grant id is not the designated grant"
    );
    Ok(())
}

#[test]
fn authorize_denies_when_an_ancestor_is_revoked() -> Result<(), Error> {
    let mut view = cast();
    view.revoke(G_ROOT);
    assert_eq!(
        decide(&view, &capture())?,
        denied(DenyCode::GrantRevoked),
        "revoking the root reaches the grandchild"
    );
    Ok(())
}

#[test]
fn authorize_denies_at_and_after_expiry() -> Result<(), Error> {
    let view = cast();
    let before = FixedClock(Timestamp::from_unix_millis(
        CHILD_EXPIRES.unix_millis().saturating_sub(1),
    ));
    assert!(
        matches!(
            authorize(&view, &capture(), &before)?,
            Decision::Allowed { .. }
        ),
        "valid one millisecond before expiry"
    );
    assert_eq!(
        authorize(&view, &capture(), &FixedClock(CHILD_EXPIRES))?,
        denied(DenyCode::GrantExpired),
        "expired at expires_at"
    );
    Ok(())
}

#[test]
fn authorize_denies_a_capability_the_designated_grant_lacks() -> Result<(), Error> {
    let request = AuthzRequest {
        capability: Capability::SessionCreate,
        target: None,
        session: None,
        ..capture()
    };
    assert_eq!(
        decide(&cast(), &request)?,
        denied(DenyCode::CapabilityNotGranted),
        "the sub-agent's grant confers no SessionCreate"
    );
    let agent = AuthzRequest {
        tenant: AGENT,
        grant: G_AGENT,
        ..request
    };
    assert!(
        matches!(decide(&cast(), &agent)?, Decision::Allowed { .. }),
        "the agent's grant does, and SessionCreate needs no session"
    );
    Ok(())
}

#[test]
fn authorize_hides_sessions_the_caller_may_not_see() -> Result<(), Error> {
    let view = cast();
    let at = |session| AuthzRequest {
        session: Some(session),
        ..capture()
    };
    let missing = decide(&view, &at(S_MISSING))?;
    assert_eq!(missing, Decision::NotFoundOrDenied, "missing session");
    assert_eq!(
        decide(&view, &at(S_FOREIGN))?,
        missing,
        "a foreign session reads as a missing one"
    );
    assert_eq!(
        decide(&view, &at(S_SUB))?,
        denied(DenyCode::ScopeViolation),
        "the caller's own session outside scope is a scope violation"
    );
    let agent_in_operator_session = AuthzRequest {
        tenant: AGENT,
        grant: G_AGENT,
        ..at(S_OPERATOR)
    };
    assert_eq!(
        decide(&view, &agent_in_operator_session)?,
        Decision::NotFoundOrDenied,
        "Own does not reach a session above the holder's lineage"
    );
    Ok(())
}

#[test]
fn authorize_admits_a_sub_agents_session_under_own() -> Result<(), Error> {
    let mut view = cast();
    if let Some(sub) = view.grants.get_mut(&G_SUB) {
        sub.session_scope = SessionScope::Own;
    }
    let request = AuthzRequest {
        session: Some(S_SUB),
        ..capture()
    };
    assert!(
        matches!(decide(&view, &request)?, Decision::Allowed { .. }),
        "the sub-agent's session is in every ancestor holder's lineage"
    );
    Ok(())
}

#[test]
fn authorize_checks_the_target_against_every_link() -> Result<(), Error> {
    let view = cast();
    let refused = [
        Some("https://example.org/"),
        Some("http://example.com/article"),
        Some("https://user@example.com/"),
        Some("not a url"),
        None,
    ];
    for target in refused {
        let request = AuthzRequest {
            target,
            ..capture()
        };
        assert_eq!(
            decide(&view, &request)?,
            denied(DenyCode::ScopeViolation),
            "target {target:?}"
        );
    }
    let mut widened = cast();
    if let Some(sub) = widened.grants.get_mut(&G_SUB) {
        sub.target_scope = crate::test_support::scope(&["*"]);
    }
    let outside_parent = AuthzRequest {
        target: Some("https://example.net/"),
        ..capture()
    };
    assert_eq!(
        decide(&widened, &outside_parent)?,
        denied(DenyCode::ScopeViolation),
        "a leaf wider than its parent is still bounded by the parent"
    );
    Ok(())
}

#[test]
fn authorize_reports_budget_on_own_ledgers_only() -> Result<(), Error> {
    let over_leaf = AuthzRequest {
        declared: Cost {
            fetches: 3,
            ..Cost::default()
        },
        ..capture()
    };
    assert_eq!(
        decide(&cast(), &over_leaf)?,
        Decision::BudgetExceeded {
            dimension: Dimension::Fetches
        },
        "the leaf allows 2 fetches"
    );
    let mut tenant_capped = cast();
    tenant_capped.tenant_ceilings.insert(
        SUB,
        Ceilings {
            output_bytes: Some(10),
            ..Ceilings::default()
        },
    );
    let wordy = AuthzRequest {
        declared: Cost {
            output_bytes: 11,
            ..one_fetch()
        },
        ..capture()
    };
    assert_eq!(
        decide(&tenant_capped, &wordy)?,
        Decision::BudgetExceeded {
            dimension: Dimension::OutputBytes
        },
        "the tenant ledger is the caller's own"
    );
    let mut parent_spent = cast();
    parent_spent.set_used(
        LedgerId::Grant(G_AGENT),
        Cost {
            fetches: 10,
            ..Cost::default()
        },
    );
    let upstream = decide(&parent_spent, &capture())?;
    assert_eq!(
        upstream,
        denied(DenyCode::BudgetUnavailable),
        "a parent's exhaustion names no dimension"
    );
    let mut session_capped = cast();
    session_capped.session_ceilings.insert(
        S_AGENT,
        Ceilings {
            fetches: Some(0),
            ..Ceilings::default()
        },
    );
    assert_eq!(
        decide(&session_capped, &capture())?,
        upstream,
        "a session another tenant owns is not the caller's ledger"
    );
    Ok(())
}

fn remaining_for(
    view: &MemView,
    tenant: TenantId,
    grant: GrantId,
    session: SessionId,
) -> Result<Ceilings, Error> {
    let chain = match designated_chain(view, tenant, grant, Capability::Capture, &FixedClock(NOW))?
    {
        Ok(chain) => chain,
        Err(refusal) => panic!("the fixture chain is usable, got {refusal:?}"),
    };
    caller_remaining(view, tenant, &chain, Some(session))
}

#[test]
fn caller_remaining_hides_ancestor_and_foreign_session_budgets() -> Result<(), Error> {
    let mut view = cast();
    view.set_used(
        LedgerId::Grant(G_AGENT),
        Cost {
            fetches: 9,
            ..Cost::default()
        },
    );
    view.session_ceilings.insert(
        S_AGENT,
        Ceilings {
            fetches: Some(0),
            ..Ceilings::default()
        },
    );
    view.tenant_ceilings.insert(
        SUB,
        Ceilings {
            output_bytes: Some(10),
            ..Ceilings::default()
        },
    );

    let remaining = remaining_for(&view, SUB, G_SUB, S_AGENT)?;

    assert_eq!(
        remaining,
        Ceilings {
            fetches: Some(2),
            bytes_transferred: Some(65_536),
            output_bytes: Some(10),
            ..Ceilings::default()
        },
        "the leaf's own ceilings and the tenant's; the parent's 1 fetch left \
         and the agent-owned session's 0 stay hidden"
    );
    Ok(())
}

#[test]
fn caller_remaining_counts_an_owned_session() -> Result<(), Error> {
    let mut view = cast();
    view.session_ceilings.insert(
        S_AGENT,
        Ceilings {
            fetches: Some(3),
            ..Ceilings::default()
        },
    );
    view.set_used(
        LedgerId::Grant(G_ROOT),
        Cost {
            bytes_transferred: 1_048_000,
            ..Cost::default()
        },
    );

    let remaining = remaining_for(&view, AGENT, G_AGENT, S_AGENT)?;

    assert_eq!(
        (remaining.fetches, remaining.bytes_transferred),
        (Some(3), Some(524_288)),
        "the owned session caps fetches; the operator's root grant, with 576 \
         bytes left, does not set the transfer default"
    );
    Ok(())
}

#[test]
fn authorize_errors_when_an_uncapped_ledger_would_overflow() {
    let mut view = cast();
    view.set_used(
        LedgerId::Tenant(SUB),
        Cost {
            wall_time_ms: u64::MAX,
            ..Cost::default()
        },
    );
    let request = AuthzRequest {
        declared: Cost {
            wall_time_ms: 1,
            ..one_fetch()
        },
        ..capture()
    };
    let result = decide(&view, &request);
    assert!(
        matches!(result, Err(Error::LedgerOverflow { .. })),
        "fails closed, got {result:?}"
    );
}

#[test]
fn authorize_propagates_view_failures() {
    let mut view = cast();
    view.fail = true;
    let result = decide(&view, &capture());
    assert!(
        matches!(result, Err(Error::View { .. })),
        "view failure surfaces, got {result:?}"
    );
}

#[test]
fn next_state_persists_only_executed_calls() -> Result<(), Error> {
    let allowed = decide(&cast(), &capture())?;
    let refused = Decision::NotFoundOrDenied;
    assert_eq!(
        allowed.next_state(Mode::Execute),
        Some(InvocationState::IntentPersisted),
        "allowed execute reaches B1"
    );
    assert_eq!(
        refused.next_state(Mode::Execute),
        Some(InvocationState::Denied),
        "refused execute records Denied"
    );
    assert_eq!(
        allowed.next_state(Mode::DryRun),
        Some(InvocationState::Planned),
        "allowed dry-run ends in memory"
    );
    assert_eq!(
        refused.next_state(Mode::DryRun),
        None,
        "refused dry-run writes nothing"
    );
    Ok(())
}

#[test]
fn refusal_maps_every_decision_to_its_failure() -> Result<(), Error> {
    let allowed = decide(&cast(), &capture())?;
    assert_eq!(allowed.refusal(), None, "allowed");
    assert_eq!(
        denied(DenyCode::ScopeViolation).refusal(),
        Some(Failure::Denied {
            code: DenyCode::ScopeViolation,
            axis: None,
        }),
        "denied"
    );
    assert_eq!(
        denied(DenyCode::BudgetUnavailable).refusal(),
        Some(Failure::Denied {
            code: DenyCode::BudgetUnavailable,
            axis: None,
        }),
        "an upstream budget denial names no dimension"
    );
    assert_eq!(
        Decision::NotFoundOrDenied.refusal(),
        Some(Failure::NotFoundOrDenied),
        "not found or denied"
    );
    assert_eq!(
        Decision::BudgetExceeded {
            dimension: Dimension::Fetches
        }
        .refusal(),
        Some(Failure::BudgetExceeded {
            dimension: Dimension::Fetches
        }),
        "budget"
    );
    Ok(())
}

#[test]
fn plan_returns_the_chain_and_cost_of_an_allowed_call() -> Result<(), Error> {
    let view = cast();
    let before = (view.grants.clone(), view.used.clone());
    let first = plan(&view, &capture(), &FixedClock(NOW))?;
    let second = plan(&view, &capture(), &FixedClock(NOW))?;
    assert_eq!(
        first,
        Plan {
            capability: Capability::Capture,
            cost: one_fetch(),
            grant_chain: vec![G_SUB, G_AGENT, G_ROOT],
            rule_chain: Vec::new(),
            refusal: None,
        },
        "the plan of the fixture capture"
    );
    assert_eq!(first, second, "two dry-runs plan identically");
    assert_eq!(
        (view.grants.clone(), view.used.clone()),
        before,
        "the snapshot is unchanged"
    );
    assert!(view.reads.get() > 0, "the planner read the snapshot");
    Ok(())
}

#[test]
fn plan_reports_the_refusal_of_a_call_that_would_be_denied() -> Result<(), Error> {
    let mut view = cast();
    view.revoke(G_AGENT);
    let refused = plan(&view, &capture(), &FixedClock(NOW))?;
    assert_eq!(
        refused.refusal,
        Some(Failure::Denied {
            code: DenyCode::GrantRevoked,
            axis: None,
        }),
        "the execute would be refused"
    );
    assert!(
        refused.grant_chain.is_empty(),
        "a refused plan names no chain"
    );
    let foreign = plan(
        &view,
        &AuthzRequest {
            tenant: FOREIGN,
            ..capture()
        },
        &FixedClock(NOW),
    )?;
    let missing = plan(
        &view,
        &AuthzRequest {
            tenant: FOREIGN,
            grant: G_MISSING,
            ..capture()
        },
        &FixedClock(NOW),
    )?;
    assert_eq!(foreign, missing, "the plan does not leak a foreign grant");
    Ok(())
}

/// The operator acting under its root grant, which confers every
/// capability, with or without its own session.
fn operator_call(capability: Capability, session: Option<SessionId>) -> AuthzRequest<'static> {
    AuthzRequest {
        tenant: crate::test_support::OPERATOR,
        grant: G_ROOT,
        capability,
        target: (capability == Capability::Capture).then_some(TARGET),
        session,
        declared: one_fetch(),
    }
}

#[test]
fn authorize_enforces_the_session_requirement_of_every_capability() -> Result<(), Error> {
    let view = cast();
    for &capability in Capability::ALL {
        let without = decide(&view, &operator_call(capability, None));
        let with = decide(&view, &operator_call(capability, Some(S_OPERATOR)));
        match session_requirement(capability) {
            SessionRequirement::Required if !is_served(capability) => {
                assert_eq!(
                    without?,
                    denied(DenyCode::NotSupported),
                    "{capability} is refused before its session is checked"
                );
                assert_eq!(
                    with?,
                    denied(DenyCode::NotSupported),
                    "{capability} in the operator's session"
                );
            }
            SessionRequirement::Required => {
                assert_eq!(
                    without?,
                    denied(DenyCode::SessionRequired),
                    "{capability} without a session"
                );
                assert!(
                    matches!(with?, Decision::Allowed { .. }),
                    "{capability} in the operator's session"
                );
            }
            SessionRequirement::Optional => {
                assert!(
                    matches!(without?, Decision::Allowed { .. }),
                    "{capability} without a session"
                );
                assert!(
                    matches!(with?, Decision::Allowed { .. }),
                    "{capability} in the operator's session"
                );
            }
            SessionRequirement::Forbidden => {
                assert!(
                    matches!(without?, Decision::Allowed { .. }),
                    "{capability} without a session"
                );
                assert!(
                    matches!(
                        with,
                        Err(Error::SessionNotApplicable { capability: named, .. })
                            if named == capability
                    ),
                    "{capability} naming a session is a fault, got {with:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn authorize_checks_the_session_requirement_after_the_capability() -> Result<(), Error> {
    let view = cast();
    let unconferred = AuthzRequest {
        capability: Capability::Query,
        target: None,
        session: None,
        ..capture()
    };
    assert_eq!(
        decide(&view, &unconferred)?,
        denied(DenyCode::CapabilityNotGranted),
        "the sub-agent's grant confers no Query"
    );
    let foreign = AuthzRequest {
        tenant: FOREIGN,
        session: None,
        ..capture()
    };
    assert_eq!(
        decide(&view, &foreign)?,
        Decision::NotFoundOrDenied,
        "a foreign grant reads as missing before the session is checked"
    );
    let sessionless = AuthzRequest {
        session: None,
        ..capture()
    };
    assert_eq!(
        decide(&view, &sessionless)?,
        denied(DenyCode::SessionRequired),
        "a capture without a session"
    );
    assert_eq!(
        plan(&view, &sessionless, &FixedClock(NOW))?.refusal,
        Some(Failure::denied(DenyCode::SessionRequired)),
        "a dry-run reports the same refusal"
    );
    Ok(())
}

#[test]
fn authorize_raises_the_forbidden_session_fault_before_reading() {
    let view = cast();
    let request = AuthzRequest {
        tenant: FOREIGN,
        grant: G_MISSING,
        ..operator_call(Capability::GrantRevoke, Some(S_OPERATOR))
    };
    let result = decide(&view, &request);
    assert!(
        matches!(result, Err(Error::SessionNotApplicable { .. })),
        "fault, got {result:?}"
    );
    assert_eq!(view.reads.get(), 0, "no read before the fault");
}

/// The sub-agent's grant with `Ingest` added on every link.
fn ingest_cast() -> MemView {
    let mut view = cast();
    for grant in view.grants.values_mut() {
        grant.capabilities.insert(Capability::Ingest);
    }
    view
}

fn ingest(session: Option<SessionId>) -> AuthzRequest<'static> {
    AuthzRequest {
        capability: Capability::Ingest,
        target: None,
        session,
        declared: Cost::default(),
        ..capture()
    }
}

#[test]
fn authorize_refuses_ingest_as_not_supported_after_the_capability() -> Result<(), Error> {
    let view = ingest_cast();
    let own = decide(&view, &ingest(Some(S_SUB)))?;
    let foreign = decide(&view, &ingest(Some(S_FOREIGN)))?;
    let missing = decide(&view, &ingest(Some(S_MISSING)))?;
    let none = decide(&view, &ingest(None))?;

    assert_eq!(own, denied(DenyCode::NotSupported), "own session");
    assert_eq!(foreign, own, "a foreign session reads the same");
    assert_eq!(missing, own, "a missing session reads the same");
    assert_eq!(none, own, "no session reads the same");
    assert_eq!(
        decide(&cast(), &ingest(Some(S_SUB)))?,
        denied(DenyCode::CapabilityNotGranted),
        "a grant without Ingest is refused at the capability check first"
    );
    let mut revoked = ingest_cast();
    revoked.revoke(G_ROOT);
    assert_eq!(
        decide(&revoked, &ingest(None))?,
        denied(DenyCode::GrantRevoked),
        "chain validity comes before the capability"
    );
    assert_eq!(
        decide(
            &view,
            &AuthzRequest {
                tenant: FOREIGN,
                ..ingest(None)
            }
        )?,
        Decision::NotFoundOrDenied,
        "a foreign designated grant is refused first"
    );
    assert_eq!(
        plan(&view, &ingest(None), &FixedClock(NOW))?.refusal,
        Some(Failure::denied(DenyCode::NotSupported)),
        "a dry-run plans the same refusal"
    );
    Ok(())
}

#[test]
fn is_served_refuses_only_ingest_in_version_1() {
    let unserved: Vec<Capability> = Capability::ALL
        .iter()
        .copied()
        .filter(|&capability| !is_served(capability))
        .collect();
    assert_eq!(unserved, [Capability::Ingest], "Ingest waits for D7");
}
