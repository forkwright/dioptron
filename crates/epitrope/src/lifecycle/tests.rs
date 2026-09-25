use super::*;

/// Every step, with every release reason.
fn every_step() -> Vec<Step> {
    let mut steps = vec![
        Step::Deny,
        Step::PersistIntent,
        Step::Dispatch,
        Step::CompleteTransfer,
        Step::Publish,
        Step::Settle,
        Step::MarkUnknownEffect,
    ];
    steps.extend(
        ReleaseReason::ALL
            .iter()
            .map(|&reason| Step::Release(reason)),
    );
    steps
}

/// The contract table, written out independently of `next_state`.
fn expected(from: &str, step: Step) -> Option<&'static str> {
    let released_from_b1 = ["Abandoned", "Revoked", "Cancelled", "DeadlineExceeded"];
    let released_from_b2 = [
        "Revoked",
        "Cancelled",
        "DeadlineExceeded",
        "ProducerUnavailable",
    ];
    if let Step::Release(reason) = step {
        let allowed = match from {
            "IntentPersisted" => released_from_b1.as_slice(),
            "Dispatched" => released_from_b2.as_slice(),
            _ => &[],
        };
        return allowed.contains(&reason.name()).then_some("Released");
    }
    match (from, step) {
        ("Planned", Step::Deny) => Some("Denied"),
        ("Planned", Step::PersistIntent) => Some("IntentPersisted"),
        ("IntentPersisted", Step::Dispatch) => Some("Dispatched"),
        ("Dispatched", Step::CompleteTransfer) => Some("TransferComplete"),
        ("Dispatched" | "Published", Step::Settle) => Some("Settled"),
        ("Dispatched", Step::MarkUnknownEffect) => Some("UnknownEffect"),
        ("TransferComplete", Step::Publish) => Some("Published"),
        _ => None,
    }
}

#[test]
fn next_state_matches_the_full_transition_matrix() {
    let mut legal = 0_usize;
    for &from in InvocationState::ALL {
        for step in every_step() {
            let got = next_state(from, step);
            match expected(from.name(), step) {
                Some(to) => {
                    legal = legal.saturating_add(1);
                    assert_eq!(
                        got.ok().map(InvocationState::name),
                        Some(to),
                        "{from} --{step:?}-> {to}"
                    );
                }
                None => assert!(
                    matches!(
                        got,
                        Err(Error::IllegalTransition { from: f, step: s, .. })
                            if f == from && s == step
                    ),
                    "{from} --{step:?}-> must be illegal"
                ),
            }
        }
    }
    assert_eq!(legal, 16, "the table has 16 legal (state, step) pairs");
}

#[test]
fn next_state_refuses_every_step_from_terminal_states() {
    for &from in InvocationState::ALL.iter().filter(|s| s.is_terminal()) {
        for step in every_step() {
            assert!(
                next_state(from, step).is_err(),
                "terminal {from} refuses {step:?}"
            );
        }
    }
}

#[test]
fn next_state_refuses_a_second_settlement() {
    let settled = next_state(InvocationState::Published, Step::Settle);
    assert_eq!(settled.ok(), Some(InvocationState::Settled), "first settle");
    assert!(
        next_state(InvocationState::Settled, Step::Settle).is_err(),
        "settlement happens once"
    );
    assert!(
        next_state(
            InvocationState::Released,
            Step::Release(ReleaseReason::Abandoned)
        )
        .is_err(),
        "release happens once"
    );
}

#[test]
fn recovery_action_follows_the_contract_per_state() {
    let expected = [
        ("Planned", None),
        ("Denied", None),
        ("IntentPersisted", Some(RecoveryAction::ReleaseAbandoned)),
        ("Dispatched", Some(RecoveryAction::MarkUnknownEffect)),
        ("TransferComplete", Some(RecoveryAction::RollForwardPublish)),
        ("Published", Some(RecoveryAction::RollForwardSettle)),
        ("Settled", None),
        ("Released", None),
        ("UnknownEffect", None),
    ];
    assert_eq!(
        InvocationState::ALL.len(),
        expected.len(),
        "every state has an expectation"
    );
    for (&state, (name, action)) in InvocationState::ALL.iter().zip(expected) {
        assert_eq!(state.name(), name, "state order");
        assert_eq!(recovery_action(state), action, "recovery of {name}");
    }
}

#[test]
fn recovery_steps_are_legal_and_reach_the_contract_state() {
    let cases = [
        (InvocationState::IntentPersisted, InvocationState::Released),
        (InvocationState::Dispatched, InvocationState::UnknownEffect),
        (
            InvocationState::TransferComplete,
            InvocationState::Published,
        ),
        (InvocationState::Published, InvocationState::Settled),
    ];
    for (state, to) in cases {
        let action = recovery_action(state);
        let reached = action.map(|a| next_state(state, a.step()));
        assert!(
            matches!(reached, Some(Ok(s)) if s == to),
            "recovery from {state} reaches {to}"
        );
    }
    assert_eq!(
        RecoveryAction::ReleaseAbandoned.step(),
        Step::Release(ReleaseReason::Abandoned),
        "B1 releases as Abandoned"
    );
}
