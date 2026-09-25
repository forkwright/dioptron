use syntheke::Failure;

use super::*;
use crate::clock::FixedClock;
use crate::test_support::{
    AGENT, CHILD_EXPIRES, FOREIGN, G_AGENT, G_MISSING, G_NEW, G_SUB, MemView, NOW, OPERATOR,
    S_AGENT, S_FOREIGN, S_MISSING, S_OPERATOR, SUB, agent_grant, caps, ceilings, scope, sub_grant,
    ts,
};

mod property;

/// A request the agent may issue to the sub-agent under its own grant.
fn valid_request() -> GrantIssueRequest {
    GrantIssueRequest {
        holder: SUB,
        capabilities: vec![Capability::Capture, Capability::Read],
        session_scope: SessionScope::Sessions(vec![S_AGENT]),
        target_scope: vec!["https://example.com".to_owned()],
        ceilings: ceilings(2, 65_536),
        not_before: ts(0),
        expires_at: CHILD_EXPIRES,
        max_depth: None,
    }
}

fn context(issuer: TenantId, designated: GrantId) -> IssueContext {
    IssueContext {
        issuer,
        designated,
        child: G_NEW,
    }
}

fn issue(view: &MemView, request: &GrantIssueRequest) -> Result<IssueDecision, Error> {
    check_issue(view, &context(AGENT, G_AGENT), request, &FixedClock(NOW))
}

fn axis_of(decision: &IssueDecision) -> Option<NarrowingAxis> {
    match decision {
        IssueDecision::Narrowing { axis } => Some(*axis),
        _ => None,
    }
}

#[test]
fn check_issue_issues_a_child_that_narrows_every_axis() -> Result<(), Error> {
    let decision = issue(&MemView::cast(), &valid_request())?;
    let IssueDecision::Issued(child) = decision else {
        panic!("a narrowing child is issued, got {decision:?}");
    };
    let expected = Grant {
        id: G_NEW,
        issuer: AGENT,
        holder: SUB,
        capabilities: caps(&[Capability::Capture, Capability::Read]),
        session_scope: SessionScope::Sessions(vec![S_AGENT]),
        target_scope: scope(&["https://example.com"]),
        audit_scope: AuditScope::OwnAndOwnedSessions,
        ceilings: ceilings(2, 65_536),
        not_before: ts(0),
        expires_at: CHILD_EXPIRES,
        parent: Some(G_AGENT),
        depth: 2,
        max_depth: 4,
    };
    assert_eq!(*child, expected, "the stored child");
    assert_eq!(IssueDecision::Issued(child).refusal(), None, "no refusal");
    Ok(())
}

#[test]
fn check_issue_is_deterministic_and_reads_only() -> Result<(), Error> {
    let view = MemView::cast();
    let grants = view.grants.clone();
    let first = issue(&view, &valid_request())?;
    let second = issue(&view, &valid_request())?;
    assert_eq!(first, second, "same inputs, same decision");
    assert_eq!(view.grants, grants, "no grant was written");
    Ok(())
}

/// One request per scope axis (capabilities, sessions, targets), each
/// broader than the parent there.
fn scope_cases() -> Vec<(&'static str, GrantIssueRequest, NarrowingAxis)> {
    let base = valid_request();
    vec![
        (
            "a capability the parent lacks",
            GrantIssueRequest {
                capabilities: vec![Capability::Capture, Capability::GrantRevoke],
                ..base.clone()
            },
            NarrowingAxis::Capabilities,
        ),
        (
            "Own for a holder outside the parent's lineage",
            GrantIssueRequest {
                holder: FOREIGN,
                session_scope: SessionScope::Own,
                ..base.clone()
            },
            NarrowingAxis::SessionScope,
        ),
        (
            "a session the parent's holder does not own",
            GrantIssueRequest {
                session_scope: SessionScope::Sessions(vec![S_AGENT, S_OPERATOR]),
                ..base.clone()
            },
            NarrowingAxis::SessionScope,
        ),
        (
            "a session that does not exist",
            GrantIssueRequest {
                session_scope: SessionScope::Sessions(vec![S_MISSING]),
                ..base.clone()
            },
            NarrowingAxis::SessionScope,
        ),
        (
            "a subdomain wildcard the parent does not cover",
            GrantIssueRequest {
                target_scope: vec!["*.example.com".to_owned()],
                ..base.clone()
            },
            NarrowingAxis::TargetScope,
        ),
        (
            "a pattern that does not parse",
            GrantIssueRequest {
                target_scope: vec!["https://example.com/path".to_owned()],
                ..base
            },
            NarrowingAxis::TargetScope,
        ),
    ]
}

/// One request per bound axis (ceilings, expiry, depth), each broader
/// than the parent there.
fn bound_cases() -> Vec<(&'static str, GrantIssueRequest, NarrowingAxis)> {
    let base = valid_request();
    vec![
        (
            "a ceiling above the parent's",
            GrantIssueRequest {
                ceilings: ceilings(11, 65_536),
                ..base.clone()
            },
            NarrowingAxis::Ceilings,
        ),
        (
            "no ceiling where the parent sets one",
            GrantIssueRequest {
                ceilings: Ceilings {
                    fetches: Some(1),
                    ..Ceilings::default()
                },
                ..base.clone()
            },
            NarrowingAxis::Ceilings,
        ),
        (
            "expiry after the parent's",
            GrantIssueRequest {
                expires_at: ts(CHILD_EXPIRES.unix_millis().saturating_add(1)),
                ..base.clone()
            },
            NarrowingAxis::Expiry,
        ),
        (
            "an empty validity window",
            GrantIssueRequest {
                not_before: CHILD_EXPIRES,
                ..base.clone()
            },
            NarrowingAxis::Expiry,
        ),
        (
            "a maximum depth above the parent's",
            GrantIssueRequest {
                max_depth: Some(5),
                ..base
            },
            NarrowingAxis::Depth,
        ),
    ]
}

#[test]
fn check_issue_refuses_each_axis() -> Result<(), Error> {
    let view = MemView::cast();
    for (why, request, axis) in scope_cases().into_iter().chain(bound_cases()) {
        let decision = issue(&view, &request)?;
        assert_eq!(axis_of(&decision), Some(axis), "{why}: {decision:?}");
        assert_eq!(
            decision.refusal(),
            Some(Failure::Denied {
                code: DenyCode::NarrowingViolation,
                axis: Some(axis),
            }),
            "{why} is a narrowing violation naming its axis on the wire"
        );
    }
    Ok(())
}

#[test]
fn check_issue_compares_ceilings_with_the_parents_remaining() -> Result<(), Error> {
    let mut view = MemView::cast();
    view.set_used(
        LedgerId::Grant(G_AGENT),
        Cost {
            fetches: 8,
            ..Cost::default()
        },
    );
    let at_remaining = issue(&view, &valid_request())?;
    assert!(
        matches!(at_remaining, IssueDecision::Issued(_)),
        "2 fetches fit the 2 remaining, got {at_remaining:?}"
    );
    let over = GrantIssueRequest {
        ceilings: ceilings(3, 65_536),
        ..valid_request()
    };
    assert_eq!(
        axis_of(&issue(&view, &over)?),
        Some(NarrowingAxis::Ceilings),
        "3 fetches exceed the 2 remaining"
    );
    Ok(())
}

#[test]
fn check_issue_refuses_a_parent_without_grant_issue() -> Result<(), Error> {
    let decision = check_issue(
        &MemView::cast(),
        &context(SUB, G_SUB),
        &GrantIssueRequest {
            holder: SUB,
            ..valid_request()
        },
        &FixedClock(NOW),
    )?;
    assert_eq!(
        axis_of(&decision),
        Some(NarrowingAxis::IssuerAuthority),
        "the sub-agent's grant confers no GrantIssue"
    );
    Ok(())
}

#[test]
fn check_issue_answers_foreign_and_missing_parents_identically() -> Result<(), Error> {
    let view = MemView::cast();
    let clock = FixedClock(NOW);
    let foreign = check_issue(&view, &context(FOREIGN, G_AGENT), &valid_request(), &clock)?;
    let missing = check_issue(
        &view,
        &context(FOREIGN, G_MISSING),
        &valid_request(),
        &clock,
    )?;
    assert_eq!(foreign, IssueDecision::NotFoundOrDenied, "foreign parent");
    assert_eq!(foreign, missing, "foreign reads exactly as missing");
    assert_eq!(
        foreign.refusal(),
        Some(Failure::NotFoundOrDenied),
        "one outcome on the wire"
    );
    let mut misfiled = MemView::cast();
    misfiled.grants.insert(G_MISSING, agent_grant());
    assert_eq!(
        check_issue(
            &misfiled,
            &context(AGENT, G_MISSING),
            &valid_request(),
            &clock
        )?,
        missing,
        "a view answer for a different grant id is not the designated parent"
    );
    Ok(())
}

#[test]
fn check_issue_denies_under_a_revoked_or_expired_chain() -> Result<(), Error> {
    let mut revoked = MemView::cast();
    revoked.revoke(crate::test_support::G_ROOT);
    let decision = issue(&revoked, &valid_request())?;
    assert_eq!(
        decision,
        IssueDecision::Denied {
            code: DenyCode::GrantRevoked
        },
        "revoked root"
    );
    assert_eq!(
        decision.refusal(),
        Some(Failure::Denied {
            code: DenyCode::GrantRevoked,
            axis: None,
        }),
        "revocation code on the wire, with no axis"
    );
    let expired = check_issue(
        &MemView::cast(),
        &context(AGENT, G_AGENT),
        &valid_request(),
        &FixedClock(CHILD_EXPIRES),
    )?;
    assert_eq!(
        expired,
        IssueDecision::Denied {
            code: DenyCode::GrantExpired
        },
        "the parent expired at issue time"
    );
    Ok(())
}

#[test]
fn narrowing_violation_checks_depth_against_the_parents_maximum() -> Result<(), Error> {
    let view = MemView::cast();
    let parent = Grant {
        depth: 3,
        ..agent_grant()
    };
    let child = Grant {
        depth: 4,
        issuer: AGENT,
        parent: Some(G_AGENT),
        ..sub_grant()
    };
    assert_eq!(
        narrowing_violation(&view, &parent, &Cost::default(), &child)?,
        Some(NarrowingAxis::Depth),
        "depth 4 reaches the maximum of 4"
    );
    let skipped = Grant { depth: 3, ..child };
    assert_eq!(
        narrowing_violation(&view, &parent, &Cost::default(), &skipped)?,
        Some(NarrowingAxis::Depth),
        "a child must sit exactly one below its parent"
    );
    Ok(())
}

#[test]
fn narrowing_violation_checks_issuer_and_parent_link() -> Result<(), Error> {
    let view = MemView::cast();
    let parent = agent_grant();
    let wrong_issuer = Grant {
        issuer: OPERATOR,
        ..sub_grant()
    };
    assert_eq!(
        narrowing_violation(&view, &parent, &Cost::default(), &wrong_issuer)?,
        Some(NarrowingAxis::IssuerAuthority),
        "only the parent's holder issues under it"
    );
    let wrong_parent = Grant {
        parent: Some(G_MISSING),
        ..sub_grant()
    };
    assert_eq!(
        narrowing_violation(&view, &parent, &Cost::default(), &wrong_parent)?,
        Some(NarrowingAxis::IssuerAuthority),
        "the child names its parent"
    );
    assert_eq!(
        narrowing_violation(&view, &parent, &Cost::default(), &sub_grant())?,
        None,
        "the cast's sub-agent grant narrows its parent"
    );
    Ok(())
}

#[test]
fn narrowing_violation_refuses_wider_scopes_and_windows() -> Result<(), Error> {
    let view = MemView::cast();
    let parent = sub_grant();
    let child = |grant: Grant| Grant {
        id: G_NEW,
        issuer: SUB,
        holder: SUB,
        parent: Some(G_SUB),
        depth: 3,
        ..grant
    };
    let base = child(sub_grant());
    let cases = [
        (
            "Own under an explicit set",
            Grant {
                session_scope: SessionScope::Own,
                ..base.clone()
            },
            NarrowingAxis::SessionScope,
        ),
        (
            "a session outside the parent's set",
            Grant {
                session_scope: SessionScope::Sessions(vec![S_AGENT, S_FOREIGN]),
                ..base.clone()
            },
            NarrowingAxis::SessionScope,
        ),
        (
            "an audit scope wider than the parent's",
            Grant {
                audit_scope: AuditScope::All,
                ..base.clone()
            },
            NarrowingAxis::AuditScope,
        ),
        (
            "a start before the parent's",
            Grant {
                not_before: ts(-1),
                ..base.clone()
            },
            NarrowingAxis::Expiry,
        ),
    ];
    for (why, grant, axis) in cases {
        assert_eq!(
            narrowing_violation(&view, &parent, &Cost::default(), &grant)?,
            Some(axis),
            "{why}"
        );
    }
    assert_eq!(
        narrowing_violation(&view, &parent, &Cost::default(), &base)?,
        None,
        "an identical child is not broader"
    );
    Ok(())
}

#[test]
fn in_lineage_follows_tenant_parents() -> Result<(), Error> {
    let view = MemView::cast();
    assert!(
        in_lineage(&view, SUB, OPERATOR)?,
        "sub-agent under operator"
    );
    assert!(
        in_lineage(&view, SUB, SUB)?,
        "a tenant is in its own lineage"
    );
    assert!(!in_lineage(&view, AGENT, SUB)?, "lineage runs upward only");
    assert!(!in_lineage(&view, FOREIGN, OPERATOR)?, "no parent link");
    Ok(())
}

#[test]
fn in_lineage_errors_on_a_parent_cycle() {
    let mut view = MemView::cast();
    view.parents.insert(OPERATOR, SUB);
    let result = in_lineage(&view, AGENT, FOREIGN);
    assert!(
        matches!(result, Err(Error::TenantLineage { tenant, .. }) if tenant == AGENT),
        "a cycle is a fault, got {result:?}"
    );
}

#[test]
fn check_issue_propagates_view_failures() {
    let mut view = MemView::cast();
    view.fail = true;
    let result = issue(&view, &valid_request());
    assert!(
        matches!(result, Err(Error::View { .. })),
        "view failure surfaces, got {result:?}"
    );
}
