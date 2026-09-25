//! Grant, revocation, and session writes, and the read views over them.

use epitrope::{GrantView as _, IssueContext, LedgerView as _, Origin};
use syntheke::{
    Capability, DenyCode, Failure, GrantId, GrantIssueRequest, InvocationState, NarrowingAxis,
    OutcomeKind, SessionId, SessionScope, TenantId, Timestamp,
};

use crate::Error;
use crate::store::test_support::{
    AGENT, Fixture, G_AGENT, G_ROOT, OPERATOR, OTHER, S_AGENT, caps, capture, ceilings, dump,
    invocation,
};
use crate::store::{GrantIssue, IssueOutcome, NewSession, RevokeGrant, RootGrant};

/// A child of the agent's grant for the other agent.
fn child_request(fetches: u64) -> GrantIssueRequest {
    GrantIssueRequest {
        holder: OTHER,
        capabilities: vec![Capability::Capture],
        session_scope: SessionScope::Sessions(vec![S_AGENT]),
        target_scope: vec!["example.com".to_owned()],
        ceilings: ceilings(fetches, 1_024),
        not_before: Timestamp::from_unix_millis(0),
        expires_at: Timestamp::from_unix_millis(4_000_000),
        max_depth: None,
    }
}

const G_CHILD: GrantId = GrantId::from_bytes([0xc0; 16]);

fn issue(store: &crate::store::Store, request: &GrantIssueRequest) -> IssueOutcome {
    let context = IssueContext {
        issuer: AGENT,
        designated: G_AGENT,
        child: G_CHILD,
    };
    store
        .issue_grant(&GrantIssue::new(context, request, invocation(0x40)))
        .expect("issue")
}

#[test]
fn snapshot_reads_grants_sessions_and_tenants() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let snapshot = store.snapshot();
    let grant = snapshot.grant(G_AGENT).expect("read").expect("present");
    assert_eq!(grant.holder, AGENT, "holder");
    assert_eq!(grant.parent, Some(G_ROOT), "parent");
    let origin = Origin::parse("https://example.com/a").expect("origin");
    assert!(
        grant.target_scope.matches(&origin),
        "target scope round-trips"
    );
    assert_eq!(snapshot.grant(G_CHILD).expect("read"), None, "absent grant");
    assert_eq!(
        snapshot.session_owner(S_AGENT).expect("read"),
        Some(AGENT),
        "owner"
    );
    assert_eq!(
        snapshot.tenant_parent(AGENT).expect("read"),
        Some(OPERATOR),
        "parent"
    );
    assert_eq!(
        snapshot.revocation(G_AGENT).expect("read"),
        None,
        "not revoked"
    );
    assert_eq!(
        snapshot
            .session_ceilings(SessionId::from_bytes([1; 16]))
            .expect("read"),
        syntheke::Ceilings::default(),
        "an unknown session sets no ceiling"
    );
}

#[test]
fn issued_child_is_stored_and_audited() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let outcome = issue(&store, &child_request(5));
    assert_eq!(
        outcome,
        IssueOutcome::Issued {
            grant: G_CHILD,
            parent: G_AGENT
        },
        "the child attenuates its parent"
    );
    let child = store
        .snapshot()
        .grant(G_CHILD)
        .expect("read")
        .expect("stored");
    assert_eq!(child.depth, 2, "depth");
    let audited = store
        .audit_records(AGENT, None, 100)
        .expect("audit")
        .into_iter()
        .any(|record| {
            record.invocation == invocation(0x40)
                && record.capability == Capability::GrantIssue
                && record.outcome == OutcomeKind::Success
        });
    assert!(audited, "the issue is audited");

    let before = dump(&store);
    assert_eq!(
        issue(&store, &child_request(5)),
        outcome,
        "a repeat returns the grant"
    );
    assert_eq!(dump(&store), before, "a repeat writes nothing");
}

#[test]
fn broader_child_is_refused_and_audited() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let outcome = issue(&store, &child_request(11));
    assert_eq!(
        outcome,
        IssueOutcome::Refused {
            failure: Failure::narrowing(NarrowingAxis::Ceilings)
        },
        "11 fetches exceed the parent's 10"
    );
    assert_eq!(
        store.snapshot().grant(G_CHILD).expect("read"),
        None,
        "not stored"
    );
    let denied = store
        .audit_records(AGENT, None, 100)
        .expect("audit")
        .into_iter()
        .any(|record| {
            record.invocation == invocation(0x40) && record.state == InvocationState::Denied
        });
    assert!(denied, "the refusal is audited");
}

#[test]
fn different_grant_under_a_taken_id_conflicts() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    issue(&store, &child_request(5));
    let context = IssueContext {
        issuer: AGENT,
        designated: G_AGENT,
        child: G_CHILD,
    };
    let other = child_request(4);
    let error = store
        .issue_grant(&GrantIssue::new(context, &other, invocation(0x41)))
        .expect_err("conflict");
    assert!(
        matches!(error, Error::Conflict { what: "grant", .. }),
        "{error:?}"
    );
}

#[test]
fn revocation_invalidates_the_subtree_and_is_idempotent() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let revocation = store
        .revoke_grant(&RevokeGrant::new(OPERATOR, G_ROOT, invocation(0x50)))
        .expect("revoke")
        .expect("grant exists");
    assert_eq!(revocation.grant, G_ROOT, "revoked grant");
    let epoch = store
        .audit_records(OPERATOR, None, 100)
        .expect("audit")
        .into_iter()
        .find(|record| record.invocation == invocation(0x50))
        .expect("audited");
    assert_eq!(
        revocation.at_seq, epoch.seq,
        "the epoch is the revoking call's sequence"
    );

    let plan = store.plan(&capture(G_AGENT)).expect("plan");
    assert_eq!(
        plan.refusal,
        Some(Failure::denied(DenyCode::GrantRevoked)),
        "a revoked root invalidates the child"
    );

    let before = dump(&store);
    let again = store
        .revoke_grant(&RevokeGrant::new(OPERATOR, G_ROOT, invocation(0x51)))
        .expect("revoke again");
    assert_eq!(again, Some(revocation), "the first record stands");
    assert_eq!(dump(&store), before, "a repeat writes nothing");
    let missing = store
        .revoke_grant(&RevokeGrant::new(OPERATOR, G_CHILD, invocation(0x52)))
        .expect("revoke missing");
    assert_eq!(missing, None, "a missing grant reads as absent");
}

#[test]
fn fork_records_lineage() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let fork = SessionId::from_bytes([0x5c; 16]);
    let opened = store
        .fork_session(&NewSession::new(fork, AGENT, invocation(0x60)), S_AGENT)
        .expect("fork")
        .expect("parent exists");
    assert_eq!(opened.parent_session, Some(S_AGENT), "lineage");
    assert_eq!(opened.owner, AGENT, "owner");
    assert_eq!(
        store.snapshot().session_owner(fork).expect("read"),
        Some(AGENT),
        "the fork is stored"
    );
    let missing = store
        .fork_session(
            &NewSession::new(SessionId::from_bytes([0x5d; 16]), AGENT, invocation(0x61)),
            SessionId::from_bytes([0x5e; 16]),
        )
        .expect("fork of missing");
    assert_eq!(missing, None, "a missing parent reads as absent");
}

#[test]
fn session_create_is_idempotent_and_conflicts_on_a_different_owner() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let before = dump(&store);
    let opened = store
        .create_session(&NewSession::new(S_AGENT, AGENT, invocation(0x62)))
        .expect("repeat");
    assert_eq!(opened.session, S_AGENT, "the stored session");
    assert_eq!(dump(&store), before, "a repeat writes nothing");
    let error = store
        .create_session(&NewSession::new(S_AGENT, OTHER, invocation(0x63)))
        .expect_err("other owner");
    assert!(
        matches!(
            error,
            Error::Conflict {
                what: "session",
                ..
            }
        ),
        "{error:?}"
    );
    let error = store
        .create_session(&NewSession::new(
            SessionId::from_bytes([0x5f; 16]),
            TenantId::from_bytes([0x99; 16]),
            invocation(0x64),
        ))
        .expect_err("unknown owner");
    assert!(matches!(error, Error::TenantMissing { .. }), "{error:?}");
}

#[test]
fn session_ceiling_bounds_reservations() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let tight = SessionId::from_bytes([0x5a; 16]);
    let mut new = NewSession::new(tight, AGENT, invocation(0x65));
    new.ceilings = ceilings(0, 0);
    store.create_session(&new).expect("session");
    assert_eq!(
        store.snapshot().session_ceilings(tight).expect("read"),
        ceilings(0, 0),
        "stored ceilings"
    );
    let mut request = capture(G_AGENT);
    request.session = Some(tight);
    let plan = store.plan(&request).expect("plan");
    assert!(
        matches!(plan.refusal, Some(Failure::BudgetExceeded { .. })),
        "{plan:?}"
    );
}

#[test]
fn root_grant_needs_a_holder_and_parsable_patterns() {
    let fixture = Fixture::new();
    let store = fixture.seeded();
    let validity = (
        Timestamp::from_unix_millis(0),
        Timestamp::from_unix_millis(1),
    );
    let orphan = RootGrant::new(
        GrantId::from_bytes([0xa1; 16]),
        TenantId::from_bytes([0x99; 16]),
        caps(&[Capability::Read]),
        vec!["*".to_owned()],
        validity,
        1,
    );
    let error = store.install_root_grant(&orphan).expect_err("no holder");
    assert!(matches!(error, Error::TenantMissing { .. }), "{error:?}");

    let bad = RootGrant::new(
        GrantId::from_bytes([0xa2; 16]),
        OPERATOR,
        caps(&[Capability::Read]),
        vec!["user@example.com".to_owned()],
        validity,
        1,
    );
    let error = store.install_root_grant(&bad).expect_err("bad pattern");
    assert!(matches!(error, Error::Authz { .. }), "{error:?}");

    let conflicting = RootGrant::new(
        G_ROOT,
        OPERATOR,
        caps(&[Capability::Read]),
        vec!["*".to_owned()],
        validity,
        1,
    );
    let error = store
        .install_root_grant(&conflicting)
        .expect_err("taken id");
    assert!(
        matches!(error, Error::Conflict { what: "grant", .. }),
        "{error:?}"
    );
}
