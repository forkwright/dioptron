use super::*;

fn every_failure() -> Vec<Failure> {
    vec![
        Failure::ProtocolError,
        Failure::AuthFailed,
        Failure::denied(DenyCode::GrantExpired),
        Failure::NotFoundOrDenied,
        Failure::BudgetExceeded {
            dimension: Dimension::Fetches,
        },
        Failure::ProducerUnavailable,
        Failure::TransferFailed {
            class: TransferClass::Reset,
        },
        Failure::ExtractionFailed {
            class: ExtractionClass::Malformed,
        },
        Failure::DeadlineExceeded,
        Failure::Cancelled,
        Failure::UnknownEffect,
        Failure::IdempotencyConflict,
    ]
}

#[test]
fn kind_names_match_the_contract_table() {
    let names: Vec<&str> = every_failure().iter().map(|f| f.kind().name()).collect();
    assert_eq!(
        names,
        [
            "ProtocolError",
            "AuthFailed",
            "Denied",
            "NotFoundOrDenied",
            "BudgetExceeded",
            "ProducerUnavailable",
            "TransferFailed",
            "ExtractionFailed",
            "DeadlineExceeded",
            "Cancelled",
            "UnknownEffect",
            "IdempotencyConflict",
        ],
        "the twelve contract outcome kinds, in table order"
    );
}

#[test]
fn from_name_inverts_name_for_every_vocabulary() {
    fn check<T: Copy + PartialEq + core::fmt::Debug>(
        all: &[T],
        name: fn(T) -> &'static str,
        parse: fn(&str) -> Option<T>,
    ) {
        for &value in all {
            assert_eq!(parse(name(value)), Some(value), "{value:?} round-trips");
        }
        assert_eq!(parse("NoSuchName"), None, "unknown names do not parse");
    }
    check(DenyCode::ALL, DenyCode::name, DenyCode::from_name);
    check(
        NarrowingAxis::ALL,
        NarrowingAxis::name,
        NarrowingAxis::from_name,
    );
    check(
        TransferClass::ALL,
        TransferClass::name,
        TransferClass::from_name,
    );
    check(
        ExtractionClass::ALL,
        ExtractionClass::name,
        ExtractionClass::from_name,
    );
    check(OutcomeKind::ALL, OutcomeKind::name, OutcomeKind::from_name);
    check(
        InvocationState::ALL,
        InvocationState::name,
        InvocationState::from_name,
    );
    check(
        ReleaseReason::ALL,
        ReleaseReason::name,
        ReleaseReason::from_name,
    );
    check(Dimension::ALL, Dimension::name, Dimension::from_name);
}

#[test]
fn terminal_states_are_denied_and_the_b5_states() {
    let terminal: Vec<&str> = InvocationState::ALL
        .iter()
        .filter(|s| s.is_terminal())
        .map(|s| s.name())
        .collect();
    assert_eq!(
        terminal,
        ["Denied", "Settled", "Released", "UnknownEffect"],
        "terminal set"
    );
    let volatile: Vec<&str> = InvocationState::ALL
        .iter()
        .filter(|s| !s.is_durable())
        .map(|s| s.name())
        .collect();
    assert_eq!(volatile, ["Planned"], "only Planned is in memory");
}

#[test]
fn display_writes_the_contract_name() {
    assert_eq!(
        OutcomeKind::NotFoundOrDenied.to_string(),
        "NotFoundOrDenied",
        "display is the name"
    );
}

#[test]
fn is_well_formed_ties_the_axis_to_narrowing_violation() {
    for &code in DenyCode::ALL {
        let narrowing = code == DenyCode::NarrowingViolation;
        let bare = Failure::Denied { code, axis: None };
        let with_axis = Failure::Denied {
            code,
            axis: Some(NarrowingAxis::Depth),
        };
        assert_eq!(bare.is_well_formed(), !narrowing, "{code} without an axis");
        assert_eq!(with_axis.is_well_formed(), narrowing, "{code} with an axis");
    }
    for &axis in NarrowingAxis::ALL {
        assert!(
            Failure::narrowing(axis).is_well_formed(),
            "{axis}: narrowing() is well formed"
        );
    }
    assert!(
        every_failure().iter().all(|f| f.is_well_formed()),
        "every other kind is well formed"
    );
}
