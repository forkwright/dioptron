use syntheke::AuditSeq;

use super::*;
use crate::clock::FixedClock;
use crate::test_support::{
    AGENT, FOREIGN, G_AGENT, G_FOREIGN, G_MISSING, G_NEW, G_ROOT, G_SUB, MemView, NOW, OPERATOR,
    SUB, agent_grant, caps, child_of, root_grant, sub_grant,
};

/// A second child of the root, beside the agent's grant.
const G_SIBLING: GrantId = GrantId::from_bytes([0xb1; 16]);
/// Two grants whose parent links form a cycle.
const G_LOOP_A: GrantId = GrantId::from_bytes([0x1a; 16]);
const G_LOOP_B: GrantId = GrantId::from_bytes([0x1b; 16]);

/// The fixture cast with `GrantRevoke` on the agent's grant, a grandchild
/// `G_NEW` under the sub-agent's grant, and a sibling of the agent's grant.
fn cast() -> MemView {
    let mut view = MemView::cast();
    let mut agent = agent_grant();
    agent.capabilities.insert(Capability::GrantRevoke);
    view.grants.insert(G_AGENT, agent);
    let grandchild = child_of(&sub_grant(), G_NEW, SUB);
    view.grants.insert(G_NEW, grandchild);
    let sibling = child_of(&root_grant(), G_SIBLING, OPERATOR);
    view.grants.insert(G_SIBLING, sibling);
    view
}

/// The agent revoking `target` under its own grant.
fn revoke(view: &MemView, target: GrantId) -> Result<RevokeDecision, Error> {
    check_revoke(view, AGENT, G_AGENT, target, &FixedClock(NOW))
}

fn record(grant: GrantId) -> Revocation {
    Revocation {
        grant,
        at_seq: AuditSeq::new(7),
        at_time: NOW,
    }
}

#[test]
fn check_revoke_allows_the_designated_grant_itself() -> Result<(), Error> {
    assert_eq!(
        revoke(&cast(), G_AGENT)?,
        RevokeDecision::Revoke { target: G_AGENT },
        "a grant revokes itself"
    );
    Ok(())
}

#[test]
fn check_revoke_allows_a_child() -> Result<(), Error> {
    assert_eq!(
        revoke(&cast(), G_SUB)?,
        RevokeDecision::Revoke { target: G_SUB },
        "the sub-agent's grant is a child of the agent's"
    );
    Ok(())
}

#[test]
fn check_revoke_allows_a_grandchild() -> Result<(), Error> {
    assert_eq!(
        revoke(&cast(), G_NEW)?,
        RevokeDecision::Revoke { target: G_NEW },
        "the walk reaches the designated grant two links up"
    );
    Ok(())
}

#[test]
fn check_revoke_hides_a_sibling() -> Result<(), Error> {
    assert_eq!(
        revoke(&cast(), G_SIBLING)?,
        RevokeDecision::NotFoundOrDenied,
        "a sibling shares a parent but is not a descendant"
    );
    Ok(())
}

#[test]
fn check_revoke_refuses_an_ancestor() -> Result<(), Error> {
    assert_eq!(
        revoke(&cast(), G_ROOT)?,
        RevokeDecision::NotFoundOrDenied,
        "a grant cannot revoke its own parent"
    );
    Ok(())
}

#[test]
fn check_revoke_answers_foreign_and_missing_targets_identically() -> Result<(), Error> {
    let view = cast();
    let foreign = revoke(&view, G_FOREIGN)?;
    let missing = revoke(&view, G_MISSING)?;
    assert_eq!(foreign, RevokeDecision::NotFoundOrDenied, "foreign target");
    assert_eq!(foreign, missing, "a foreign target reads as a missing one");
    assert_eq!(
        missing.refusal(),
        Some(Failure::NotFoundOrDenied),
        "one outcome on the wire"
    );
    Ok(())
}

#[test]
fn check_revoke_answers_a_foreign_designated_grant_as_missing() -> Result<(), Error> {
    let view = cast();
    let clock = FixedClock(NOW);
    let foreign = check_revoke(&view, FOREIGN, G_AGENT, G_SUB, &clock)?;
    let missing = check_revoke(&view, AGENT, G_MISSING, G_SUB, &clock)?;
    assert_eq!(foreign, RevokeDecision::NotFoundOrDenied, "foreign grant");
    assert_eq!(
        foreign, missing,
        "a foreign designated grant reads as missing"
    );
    Ok(())
}

#[test]
fn check_revoke_denies_without_the_grant_revoke_capability() -> Result<(), Error> {
    let view = cast();
    let decision = check_revoke(&view, SUB, G_SUB, G_SUB, &FixedClock(NOW))?;
    assert_eq!(
        decision,
        RevokeDecision::Denied {
            code: DenyCode::CapabilityNotGranted
        },
        "the sub-agent's grant confers no GrantRevoke"
    );
    assert_eq!(
        decision.refusal(),
        Some(Failure::denied(DenyCode::CapabilityNotGranted)),
        "the refusal on the wire"
    );
    let mut root_only = cast();
    root_only.grants.insert(G_AGENT, agent_grant());
    assert_eq!(
        revoke(&root_only, G_SUB)?,
        RevokeDecision::Denied {
            code: DenyCode::CapabilityNotGranted
        },
        "the root conferring GrantRevoke does not lend it to the leaf"
    );
    Ok(())
}

#[test]
fn check_revoke_denies_when_the_designated_chain_is_revoked() -> Result<(), Error> {
    let mut view = cast();
    view.revoke(G_ROOT);
    assert_eq!(
        revoke(&view, G_SUB)?,
        RevokeDecision::Denied {
            code: DenyCode::GrantRevoked
        },
        "a revoked ancestor of the designated grant refuses the call"
    );
    Ok(())
}

#[test]
fn check_revoke_is_idempotent_on_an_already_revoked_target() -> Result<(), Error> {
    let mut view = cast();
    assert_eq!(
        revoke(&view, G_SUB)?,
        RevokeDecision::Revoke { target: G_SUB },
        "first revocation writes a record"
    );
    view.revoke(G_SUB);
    let first = revoke(&view, G_SUB)?;
    let second = revoke(&view, G_SUB)?;
    assert_eq!(
        first,
        RevokeDecision::AlreadyRevoked {
            record: record(G_SUB)
        },
        "a repeat returns the existing record"
    );
    assert_eq!(first, second, "and keeps returning it");
    assert_eq!(first.refusal(), None, "a repeat succeeds");
    assert_eq!(
        revoke(&view, G_NEW)?,
        RevokeDecision::Revoke { target: G_NEW },
        "a descendant of a revoked grant still takes its own record"
    );
    Ok(())
}

#[test]
fn check_revoke_ends_a_cyclic_walk_outside_the_subtree() -> Result<(), Error> {
    let mut view = cast();
    let mut loop_a = child_of(&root_grant(), G_LOOP_A, FOREIGN);
    loop_a.parent = Some(G_LOOP_B);
    let mut loop_b = child_of(&root_grant(), G_LOOP_B, FOREIGN);
    loop_b.parent = Some(G_LOOP_A);
    loop_b.capabilities = caps(&[Capability::Read]);
    view.grants.insert(G_LOOP_A, loop_a);
    view.grants.insert(G_LOOP_B, loop_b);
    assert_eq!(
        revoke(&view, G_LOOP_A)?,
        RevokeDecision::NotFoundOrDenied,
        "a parent cycle ends the walk"
    );
    assert!(
        view.reads.get() <= SUBTREE_WALK_LIMIT.saturating_add(8),
        "the walk is bounded, read {} times",
        view.reads.get()
    );
    Ok(())
}

#[test]
fn check_revoke_treats_a_misfiled_record_as_outside() -> Result<(), Error> {
    let mut view = cast();
    view.grants.insert(G_MISSING, sub_grant());
    assert_eq!(
        revoke(&view, G_MISSING)?,
        RevokeDecision::NotFoundOrDenied,
        "a view answer for a different id is not the target"
    );
    Ok(())
}

#[test]
fn check_revoke_propagates_view_failures() {
    let mut view = cast();
    view.fail = true;
    let result = revoke(&view, G_SUB);
    assert!(
        matches!(result, Err(Error::View { .. })),
        "view failure surfaces, got {result:?}"
    );
}
