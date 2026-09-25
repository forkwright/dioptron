use syntheke::{GrantId, SessionId, TenantId};

use super::*;

const LEAF: LedgerId = LedgerId::Grant(GrantId::from_bytes([1; 16]));
const PARENT: LedgerId = LedgerId::Grant(GrantId::from_bytes([2; 16]));
const SESSION: LedgerId = LedgerId::Session(SessionId::from_bytes([3; 16]));
const TENANT: LedgerId = LedgerId::Tenant(TenantId::from_bytes([4; 16]));

fn fetches(n: u64) -> Cost {
    Cost {
        fetches: n,
        ..Cost::default()
    }
}

fn ledger(id: LedgerId, ceilings: Ceilings, used: Cost, own: bool) -> LedgerState {
    LedgerState {
        id,
        ceilings,
        used,
        own,
    }
}

fn capped(dimension: Dimension, ceiling: u64) -> Ceilings {
    let mut ceilings = Ceilings::default();
    let slot = match dimension {
        Dimension::WallTimeMs => &mut ceilings.wall_time_ms,
        Dimension::Fetches => &mut ceilings.fetches,
        Dimension::BytesTransferred => &mut ceilings.bytes_transferred,
        Dimension::OutputBytes => &mut ceilings.output_bytes,
        Dimension::Tokens => &mut ceilings.tokens,
        Dimension::OpsBand => &mut ceilings.ops_band,
        _ => panic!("a dimension this test does not know: {dimension}"),
    };
    *slot = Some(ceiling);
    ceilings
}

fn amount(dimension: Dimension, value: u64) -> Cost {
    let mut cost = Cost::default();
    let slot = match dimension {
        Dimension::WallTimeMs => &mut cost.wall_time_ms,
        Dimension::Fetches => &mut cost.fetches,
        Dimension::BytesTransferred => &mut cost.bytes_transferred,
        Dimension::OutputBytes => &mut cost.output_bytes,
        Dimension::Tokens => &mut cost.tokens,
        Dimension::OpsBand => &mut cost.ops_band,
        _ => panic!("a dimension this test does not know: {dimension}"),
    };
    *slot = value;
    cost
}

#[test]
fn plan_reservation_fits_at_exactly_the_ceiling() -> Result<(), Error> {
    let ledgers = [
        ledger(LEAF, capped(Dimension::Fetches, 10), fetches(7), true),
        ledger(TENANT, Ceilings::default(), fetches(1_000), true),
    ];
    let check = plan_reservation(&ledgers, &fetches(3))?;
    let BudgetCheck::Fits(plan) = check else {
        panic!("7 + 3 <= 10 fits, got {check:?}");
    };
    assert_eq!(plan.cost(), fetches(3), "declared maximum reserved");
    assert_eq!(plan.ledgers(), &[LEAF, TENANT], "every ledger, in order");
    assert_eq!(
        plan.debits().collect::<Vec<_>>(),
        [(LEAF, fetches(3)), (TENANT, fetches(3))],
        "each ledger debits the declared maximum"
    );
    Ok(())
}

#[test]
fn plan_reservation_reports_each_exceeded_dimension_separately() -> Result<(), Error> {
    for &dimension in Dimension::ALL {
        let ledgers = [ledger(LEAF, capped(dimension, 5), Cost::default(), true)];
        let check = plan_reservation(&ledgers, &amount(dimension, 6))?;
        assert_eq!(
            check,
            BudgetCheck::Exceeded(BudgetRefusal::Own {
                ledger: LEAF,
                dimension
            }),
            "6 over a ceiling of 5 on {dimension}"
        );
        let other = Dimension::ALL
            .iter()
            .copied()
            .find(|&d| d != dimension)
            .unwrap_or(dimension);
        let check = plan_reservation(&ledgers, &amount(other, u64::MAX))?;
        assert!(
            matches!(check, BudgetCheck::Fits(_)),
            "a ceiling on {dimension} never limits {other}"
        );
    }
    Ok(())
}

#[test]
fn plan_reservation_withholds_upstream_dimension() -> Result<(), Error> {
    let ledgers = [
        ledger(LEAF, capped(Dimension::Fetches, 10), Cost::default(), true),
        ledger(PARENT, capped(Dimension::Fetches, 10), fetches(9), false),
    ];
    let check = plan_reservation(&ledgers, &fetches(2))?;
    assert_eq!(
        check,
        BudgetCheck::Exceeded(BudgetRefusal::Upstream),
        "a parent's exhaustion names no dimension"
    );
    assert_eq!(
        BudgetRefusal::Upstream.failure(),
        Failure::Denied {
            code: syntheke::DenyCode::CapabilityNotGranted
        },
        "upstream reads as the chain not conferring the call"
    );
    Ok(())
}

#[test]
fn plan_reservation_prefers_the_callers_own_ledger() -> Result<(), Error> {
    let ledgers = [
        ledger(
            PARENT,
            capped(Dimension::Fetches, 1),
            Cost::default(),
            false,
        ),
        ledger(
            SESSION,
            capped(Dimension::OutputBytes, 1),
            Cost::default(),
            true,
        ),
    ];
    let declared = Cost {
        fetches: 2,
        output_bytes: 2,
        ..Cost::default()
    };
    let check = plan_reservation(&ledgers, &declared)?;
    let BudgetCheck::Exceeded(refusal) = check else {
        panic!("both exceed, got {check:?}");
    };
    assert_eq!(
        refusal.failure(),
        Failure::BudgetExceeded {
            dimension: Dimension::OutputBytes
        },
        "the own ledger's dimension is reported"
    );
    Ok(())
}

#[test]
fn plan_reservation_treats_capped_overflow_as_exceeded() -> Result<(), Error> {
    let ledgers = [ledger(
        LEAF,
        capped(Dimension::Fetches, u64::MAX),
        fetches(u64::MAX),
        true,
    )];
    let check = plan_reservation(&ledgers, &fetches(1))?;
    assert!(
        matches!(check, BudgetCheck::Exceeded(BudgetRefusal::Own { .. })),
        "u64::MAX + 1 exceeds any ceiling, got {check:?}"
    );
    Ok(())
}

#[test]
fn plan_reservation_errors_on_uncapped_overflow() {
    let ledgers = [ledger(TENANT, Ceilings::default(), fetches(u64::MAX), true)];
    let result = plan_reservation(&ledgers, &fetches(1));
    assert!(
        matches!(
            result,
            Err(Error::LedgerOverflow {
                dimension: Dimension::Fetches,
                ..
            })
        ),
        "an uncapped ledger that would overflow is a fault, got {result:?}"
    );
}

#[test]
fn settle_debits_actual_and_releases_the_remainder() -> Result<(), Error> {
    let reserved = Cost {
        fetches: 3,
        bytes_transferred: 1_000,
        ..Cost::default()
    };
    let actual = Cost {
        fetches: 1,
        bytes_transferred: 1_000,
        ..Cost::default()
    };
    let settlement = settle(&reserved, &actual)?;
    assert_eq!(settlement.debit, actual, "actual kept");
    assert_eq!(settlement.release, fetches(2), "two fetches released");
    let nothing = settle(&reserved, &Cost::default())?;
    assert_eq!(nothing.release, reserved, "zero consumption releases all");
    Ok(())
}

#[test]
fn settle_reports_overrun_with_the_clamped_settlement() {
    let reserved = fetches(2);
    let actual = Cost {
        fetches: 5,
        output_bytes: 0,
        ..Cost::default()
    };
    let result = settle(&reserved, &actual);
    let Err(Error::SettleOverrun {
        dimension,
        reserved: r,
        actual: a,
        settlement,
        ..
    }) = result
    else {
        panic!("5 over a reservation of 2 overruns, got {result:?}");
    };
    assert_eq!(dimension, Dimension::Fetches, "overrun dimension");
    assert_eq!((r, a), (2, 5), "reserved and actual reported");
    assert_eq!(settlement.debit, fetches(2), "debit clamped to reserved");
    assert_eq!(settlement.release, Cost::default(), "nothing released");
}

#[test]
fn unknown_effect_settlement_charges_the_whole_reservation() {
    let reserved = Cost {
        fetches: 1,
        wall_time_ms: 30_000,
        ..Cost::default()
    };
    let settlement = unknown_effect_settlement(&reserved);
    assert_eq!(settlement.debit, reserved, "reserved cost charged");
    assert_eq!(settlement.release, Cost::default(), "nothing released");
}

#[test]
fn reserve_then_settle_then_release_restores_the_ledger() -> Result<(), Error> {
    let before = fetches(4);
    let reserved = fetches(3);
    let held = reserve(&before, &reserved)?;
    assert_eq!(held, fetches(7), "reservation debited");
    let settlement = settle(&reserved, &fetches(1))?;
    let after = release(&held, &settlement.release)?;
    assert_eq!(after, fetches(5), "only the actual fetch stays spent");
    Ok(())
}

#[test]
fn reserve_errors_on_overflow() {
    let result = reserve(&fetches(u64::MAX), &fetches(1));
    assert!(
        matches!(
            result,
            Err(Error::LedgerOverflow {
                dimension: Dimension::Fetches,
                ..
            })
        ),
        "checked add, got {result:?}"
    );
}

#[test]
fn release_errors_on_underflow() {
    let result = release(&fetches(1), &fetches(2));
    assert!(
        matches!(
            result,
            Err(Error::LedgerUnderflow {
                dimension: Dimension::Fetches,
                ..
            })
        ),
        "checked sub, got {result:?}"
    );
}
