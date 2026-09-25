use super::*;
use crate::test_support::{
    AGENT, CHILD_EXPIRES, G_AGENT, G_ROOT, G_SUB, MemView, NOW, OPERATOR, agent_grant,
    foreign_grant, root_grant, sub_grant, ts,
};

fn walk(view: &MemView, now: Timestamp) -> Result<ChainStatus, Error> {
    check_chain(view, sub_grant(), now)
}

#[test]
fn check_chain_returns_the_chain_leaf_first() -> Result<(), Error> {
    let status = walk(&MemView::cast(), NOW)?;
    assert_eq!(
        status,
        ChainStatus::Valid(vec![sub_grant(), agent_grant(), root_grant()]),
        "leaf, parent, root"
    );
    Ok(())
}

#[test]
fn check_chain_invalidates_grandchild_when_root_is_revoked() -> Result<(), Error> {
    let mut view = MemView::cast();
    view.revoke(G_ROOT);
    let grants_before = view.grants.clone();
    let status = walk(&view, NOW)?;
    assert_eq!(
        status,
        ChainStatus::Invalid {
            code: DenyCode::GrantRevoked,
            failing_link: G_ROOT
        },
        "the revoked root fails the grandchild's walk"
    );
    assert_eq!(view.grants, grants_before, "no descendant was rewritten");
    Ok(())
}

#[test]
fn check_chain_reports_the_first_failing_link_from_the_leaf() -> Result<(), Error> {
    let mut view = MemView::cast();
    view.revoke(G_ROOT);
    view.revoke(G_AGENT);
    assert_eq!(
        walk(&view, NOW)?,
        ChainStatus::Invalid {
            code: DenyCode::GrantRevoked,
            failing_link: G_AGENT
        },
        "the walk stops at the first revoked link"
    );
    Ok(())
}

#[test]
fn check_chain_treats_expires_at_as_exclusive() -> Result<(), Error> {
    let view = MemView::cast();
    let before = CHILD_EXPIRES.unix_millis().saturating_sub(1);
    assert!(
        matches!(walk(&view, ts(before))?, ChainStatus::Valid(_)),
        "one millisecond before expiry is valid"
    );
    assert_eq!(
        walk(&view, CHILD_EXPIRES)?,
        ChainStatus::Invalid {
            code: DenyCode::GrantExpired,
            failing_link: G_SUB
        },
        "now == expires_at is expired"
    );
    Ok(())
}

#[test]
fn check_chain_treats_not_before_as_inclusive() -> Result<(), Error> {
    let mut view = MemView::cast();
    let start = ts(500_000);
    if let Some(agent) = view.grants.get_mut(&G_AGENT) {
        agent.not_before = start;
    }
    assert!(
        matches!(walk(&view, start)?, ChainStatus::Valid(_)),
        "now == not_before is valid"
    );
    assert_eq!(
        walk(&view, ts(499_999))?,
        ChainStatus::Invalid {
            code: DenyCode::GrantNotYetValid,
            failing_link: G_AGENT
        },
        "one millisecond before not_before is not yet valid"
    );
    Ok(())
}

#[test]
fn check_chain_reports_an_expired_ancestor() -> Result<(), Error> {
    let mut view = MemView::cast();
    if let Some(agent) = view.grants.get_mut(&G_AGENT) {
        agent.expires_at = NOW;
    }
    assert_eq!(
        walk(&view, NOW)?,
        ChainStatus::Invalid {
            code: DenyCode::GrantExpired,
            failing_link: G_AGENT
        },
        "an expired parent fails the child"
    );
    Ok(())
}

#[test]
fn check_chain_reports_revocation_before_expiry() -> Result<(), Error> {
    let mut view = MemView::cast();
    view.revoke(G_SUB);
    assert_eq!(
        walk(&view, CHILD_EXPIRES)?,
        ChainStatus::Invalid {
            code: DenyCode::GrantRevoked,
            failing_link: G_SUB
        },
        "revocation wins within one link"
    );
    Ok(())
}

#[test]
fn check_chain_errors_when_a_parent_is_missing() {
    let mut view = MemView::cast();
    view.grants.remove(&G_ROOT);
    let result = walk(&view, NOW);
    assert!(
        matches!(result, Err(Error::ChainBroken { grant, .. }) if grant == G_ROOT),
        "missing root, got {result:?}"
    );
}

#[test]
fn check_chain_errors_on_malformed_links() {
    let mut depth = MemView::cast();
    if let Some(agent) = depth.grants.get_mut(&G_AGENT) {
        agent.depth = 2;
    }
    let mut issuer = MemView::cast();
    if let Some(agent) = issuer.grants.get_mut(&G_AGENT) {
        agent.holder = OPERATOR;
    }
    let mut root = MemView::cast();
    if let Some(grant) = root.grants.get_mut(&G_ROOT) {
        grant.depth = 1;
    }
    let mut at_maximum = MemView::cast();
    if let Some(agent) = at_maximum.grants.get_mut(&G_AGENT) {
        agent.max_depth = 2;
    }
    let mut raised = MemView::cast();
    if let Some(agent) = raised.grants.get_mut(&G_AGENT) {
        agent.max_depth = 3;
    }
    let mut misfiled = MemView::cast();
    misfiled.grants.insert(G_AGENT, foreign_grant());
    let sub = sub_grant();
    let sub_at_two = Grant {
        max_depth: 2,
        ..sub_grant()
    };
    let cases = [
        (
            depth,
            &sub,
            G_SUB,
            "child depth is not parent depth plus one",
        ),
        (
            issuer,
            &sub,
            G_SUB,
            "child issuer is not the parent's holder",
        ),
        (root, &sub, G_AGENT, "root depth is not zero"),
        (
            at_maximum,
            &sub_at_two,
            G_SUB,
            "child depth reaches the parent's maximum",
        ),
        (
            raised,
            &sub,
            G_SUB,
            "child raises the parent's maximum depth",
        ),
        (misfiled, &sub, G_SUB, "the view answers with another grant"),
    ];
    for (view, leaf, at, why) in cases {
        let result = check_chain(&view, leaf.clone(), NOW);
        assert!(
            matches!(result, Err(Error::ChainMalformed { grant, .. }) if grant == at),
            "{why}, got {result:?}"
        );
    }
    assert_eq!(agent_grant().holder, AGENT, "the cast itself is unchanged");
}

#[test]
fn check_chain_propagates_view_failures() {
    let mut view = MemView::cast();
    view.fail = true;
    let result = walk(&view, NOW);
    assert!(
        matches!(result, Err(Error::View { .. })),
        "view failure surfaces, got {result:?}"
    );
}
