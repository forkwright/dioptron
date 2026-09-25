//! Property: a child passes the narrowing check exactly when it is not
//! broader than its parent on any axis. A passing child is never broader,
//! and a refused child is broader on some axis.
//!
//! The expected relations are recomputed here from first principles (a
//! fixed tenant lineage table, admitted-session and admitted-origin
//! samples), not by calling the checks under test.

use std::cell::Cell;

use proptest::collection::vec as vec_of;
use proptest::option::of as option_of;
use proptest::prelude::*;
use proptest::sample::{select, subsequence};
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use super::*;
use crate::origin::{Origin, OriginPattern};
use syntheke::SessionId;

const TENANTS: [TenantId; 4] = [OPERATOR, AGENT, SUB, FOREIGN];

const PATTERNS: [&str; 12] = [
    "example.com",
    "https://example.com",
    "http://example.com:8080",
    "example.com:443",
    "*.example.org",
    "a.example.org",
    "https://*.b.example.org",
    "example.org",
    "*.example.com",
    "*",
    "192.0.2.1",
    "http://a.example.org",
];

const ORIGINS: [&str; 14] = [
    "https://b.example.org/",
    "https://example.org:8080/",
    "https://example.com/",
    "http://example.com/",
    "https://example.com:8080/",
    "http://example.com:8080/",
    "http://example.com:443/",
    "https://a.example.org/",
    "http://a.example.org/",
    "https://x.b.example.org/",
    "https://example.org/",
    "https://192.0.2.1/",
    "https://other.example.net/",
    "https://a.example.com/",
];

/// Tenants whose sessions an `Own` scope held by `holder` admits, written
/// out from the cast's parent links (sub-agent under agent under operator).
fn lineage_members(holder: TenantId) -> Vec<TenantId> {
    match holder {
        h if h == OPERATOR => vec![OPERATOR, AGENT, SUB],
        h if h == AGENT => vec![AGENT, SUB],
        h => vec![h],
    }
}

/// Whether a scope held by `holder` admits `session`, owned by `owner`.
fn admits(
    scope: &SessionScope,
    holder: TenantId,
    session: Option<SessionId>,
    owner: Option<TenantId>,
) -> bool {
    match scope {
        SessionScope::Own => owner.is_some_and(|o| lineage_members(holder).contains(&o)),
        SessionScope::Sessions(set) => session.is_some_and(|s| set.contains(&s)),
        _ => false,
    }
}

/// Every session the property probes: the cast's sessions, a missing one,
/// and a not-yet-created session for each tenant.
fn session_universe() -> Vec<(Option<SessionId>, Option<TenantId>)> {
    let mut universe = vec![
        (Some(S_AGENT), Some(AGENT)),
        (Some(S_OPERATOR), Some(OPERATOR)),
        (Some(S_FOREIGN), Some(FOREIGN)),
        (Some(S_MISSING), None),
    ];
    universe.extend(TENANTS.iter().map(|&tenant| (None, Some(tenant))));
    universe
}

/// Patterns the agent's grant (`example.com`, `*.example.org`) covers.
/// Generation draws from these most of the time so that enough children
/// pass the check for the property to bite.
const COVERED: [&str; 5] = [
    "example.com",
    "https://example.com",
    "a.example.org",
    "https://*.b.example.org",
    "http://a.example.org",
];

/// The scope axes of a child (holder, capabilities, sessions, targets,
/// audit), each drawn close to the parent four times in five and anywhere
/// in its range otherwise, so both passing and refused children occur.
fn scope_axes() -> impl Strategy<Value = Grant> {
    let parent_caps: Vec<Capability> = agent_grant().capabilities.into_iter().collect();
    let sessions = vec![S_AGENT, S_OPERATOR, S_FOREIGN, S_MISSING];
    (
        prop_oneof![
            4 => select(vec![AGENT, SUB]),
            1 => select(TENANTS.to_vec()),
        ],
        prop_oneof![
            4 => subsequence(parent_caps, 0..=4),
            1 => subsequence(Capability::ALL.to_vec(), 0..=Capability::ALL.len()),
        ],
        prop_oneof![
            2 => Just(SessionScope::Own),
            2 => subsequence(vec![S_AGENT], 0..=1).prop_map(SessionScope::Sessions),
            1 => subsequence(sessions, 0..=2).prop_map(SessionScope::Sessions),
        ],
        prop_oneof![
            4 => vec_of(select(COVERED.to_vec()), 0..=3),
            1 => vec_of(select(PATTERNS.to_vec()), 0..=3),
        ],
        prop_oneof![
            4 => Just(AuditScope::OwnAndOwnedSessions),
            1 => Just(AuditScope::All),
        ],
    )
        .prop_map(
            |(holder, capabilities, session_scope, targets, audit_scope)| Grant {
                id: G_NEW,
                holder,
                capabilities: capabilities.into_iter().collect(),
                session_scope,
                target_scope: scope(&targets),
                audit_scope,
                ..agent_grant()
            },
        )
}

/// A child with bound axes (ceilings, window, depth, issuer, parent link)
/// drawn the same way, plus the parent ledger's used fetches.
fn child_strategy() -> impl Strategy<Value = (Grant, u64)> {
    let expiry = CHILD_EXPIRES.unix_millis();
    let ceilings = (
        prop_oneof![4 => (0..=8_u64).prop_map(Some), 1 => option_of(0..=12_u64)],
        prop_oneof![
            4 => (0..=524_288_u64).prop_map(Some),
            1 => option_of(0..=600_000_u64),
        ],
        option_of(0..=10_u64),
    );
    let window = (
        prop_oneof![4 => 0..=3_i64, 1 => -3..=3_i64],
        prop_oneof![
            4 => expiry.saturating_sub(3)..=expiry,
            1 => expiry.saturating_sub(3)..=expiry.saturating_add(3),
        ],
    );
    let shape = (
        prop_oneof![4 => Just(2_u8), 1 => 1..=3_u8],
        prop_oneof![4 => 3..=4_u8, 1 => 3..=5_u8],
        prop_oneof![4 => Just(AGENT), 1 => Just(OPERATOR)],
        prop_oneof![9 => Just(G_AGENT), 1 => Just(G_MISSING)],
    );
    let used = prop_oneof![4 => 0..=2_u64, 1 => 0..=12_u64];
    (scope_axes(), ceilings, window, shape, used).prop_map(
        |(
            base,
            (fetches, bytes, output),
            (not_before, expires_at),
            (depth, max_depth, issuer, parent),
            used,
        )| {
            let child = Grant {
                issuer,
                ceilings: Ceilings {
                    fetches,
                    bytes_transferred: bytes,
                    output_bytes: output,
                    ..Ceilings::default()
                },
                not_before: ts(not_before),
                expires_at: ts(expires_at),
                parent: Some(parent),
                depth,
                max_depth,
                ..base
            };
            (child, used)
        },
    )
}

/// The independent statement of "not broader", axis by axis.
fn assert_not_broader(parent: &Grant, used: &Cost, child: &Grant) -> Result<(), TestCaseError> {
    for capability in &child.capabilities {
        prop_assert!(
            parent.capabilities.contains(capability),
            "{capability} not in the parent"
        );
    }
    prop_assert!(
        child.audit_scope == parent.audit_scope
            || (child.audit_scope == AuditScope::OwnAndOwnedSessions
                && parent.audit_scope == AuditScope::All),
        "audit scope widened"
    );
    for (session, owner) in session_universe() {
        if admits(&child.session_scope, child.holder, session, owner) {
            prop_assert!(
                admits(&parent.session_scope, parent.holder, session, owner),
                "child admits {session:?} owned by {owner:?}; parent does not"
            );
        }
    }
    for text in ORIGINS {
        let origin = Origin::parse(text).map_err(|e| TestCaseError::fail(e.to_string()))?;
        if child.target_scope.matches(&origin) {
            prop_assert!(
                parent.target_scope.matches(&origin),
                "child admits {text}; parent does not"
            );
        }
    }
    for &dimension in Dimension::ALL {
        if let Some(ceiling) = parent.ceilings.get(dimension) {
            let remaining = ceiling.saturating_sub(used.get(dimension));
            prop_assert!(
                child
                    .ceilings
                    .get(dimension)
                    .is_some_and(|c| c <= remaining),
                "{dimension} ceiling above the parent's remaining {remaining}"
            );
        }
    }
    prop_assert!(parent.not_before <= child.not_before, "starts earlier");
    prop_assert!(child.not_before < child.expires_at, "empty window");
    prop_assert!(child.expires_at <= parent.expires_at, "expires later");
    prop_assert_eq!(Some(child.depth), parent.depth.checked_add(1), "depth link");
    prop_assert!(child.depth < parent.max_depth, "depth at the maximum");
    prop_assert!(child.max_depth <= parent.max_depth, "maximum raised");
    prop_assert_eq!(child.issuer, parent.holder, "issuer");
    prop_assert_eq!(child.parent, Some(parent.id), "parent link");
    Ok(())
}

#[test]
fn narrowing_violation_refuses_exactly_the_broader_children() {
    let view = MemView::cast();
    let parent = agent_grant();
    let passed = Cell::new(0_u32);
    let refused = Cell::new(0_u32);
    let config = Config {
        cases: 4_096,
        ..Config::default()
    };
    // WHY a fixed seed: the property runs identically on every machine; a
    // failure reproduces from the test alone.
    let rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
    let mut runner = TestRunner::new_with_rng(config, rng);
    let result = runner.run(&child_strategy(), |(child, used_fetches)| {
        let used = Cost {
            fetches: used_fetches,
            ..Cost::default()
        };
        let verdict = narrowing_violation(&view, &parent, &used, &child)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        let independent = assert_not_broader(&parent, &used, &child);
        if let Some(axis) = verdict {
            refused.set(refused.get().saturating_add(1));
            // WHY both directions: a check that refused too much would pass
            // the soundness half alone; the sample universes are chosen so
            // every broader child has a witness.
            prop_assert!(
                independent.is_err(),
                "refused on {axis} a child the independent statement finds not broader"
            );
            return Ok(());
        }
        passed.set(passed.get().saturating_add(1));
        independent
    });
    assert!(result.is_ok(), "property failed: {result:?}");
    assert!(
        passed.get() >= 200,
        "the property must exercise passing children, got {}",
        passed.get()
    );
    assert!(
        refused.get() >= 200,
        "and refused ones, got {}",
        refused.get()
    );
}

#[test]
fn covers_implies_every_admitted_origin_is_admitted() -> Result<(), Error> {
    let origins = ORIGINS
        .iter()
        .map(|text| Origin::parse(text))
        .collect::<Result<Vec<_>, _>>()?;
    for outer in PATTERNS {
        let outer = OriginPattern::parse(outer)?;
        for inner in PATTERNS {
            let inner = OriginPattern::parse(inner)?;
            if !outer.covers(&inner) {
                continue;
            }
            for origin in &origins {
                assert!(
                    !inner.matches(origin) || outer.matches(origin),
                    "{outer:?} covers {inner:?} yet refuses {origin}"
                );
            }
        }
    }
    Ok(())
}
