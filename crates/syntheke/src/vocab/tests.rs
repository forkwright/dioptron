use super::*;

#[test]
fn capability_names_match_the_contract_table() {
    let names: Vec<&str> = Capability::ALL.iter().map(|c| c.name()).collect();
    assert_eq!(
        names,
        [
            "SessionCreate",
            "SessionFork",
            "Capture",
            "Ingest",
            "Read",
            "Query",
            "GrantIssue",
            "GrantRevoke",
            "AuditQuery",
        ],
        "the nine version 1 capabilities, in table order"
    );
    for &capability in Capability::ALL {
        assert_eq!(
            Capability::from_name(capability.name()),
            Some(capability),
            "{capability} round-trips"
        );
    }
    assert_eq!(Capability::from_name("capture"), None, "names are exact");
}

#[test]
fn only_reads_queries_and_audit_reads_are_stateless() {
    let stateless: Vec<Capability> = Capability::ALL
        .iter()
        .copied()
        .filter(|c| !c.is_state_changing())
        .collect();
    assert_eq!(
        stateless,
        [Capability::Read, Capability::Query, Capability::AuditQuery],
        "every other capability needs an idempotency key"
    );
}

#[test]
fn small_vocabularies_parse_their_names() {
    assert_eq!(Mode::from_name("DryRun"), Some(Mode::DryRun), "mode");
    assert_eq!(Mode::ALL.len(), 2, "two modes");
    assert_eq!(
        TenantClass::from_name("SubAgent"),
        Some(TenantClass::SubAgent),
        "tenant class"
    );
    assert_eq!(TenantClass::ALL.len(), 3, "three tenant classes");
    assert_eq!(
        AuditScope::from_name("OwnAndOwnedSessions"),
        Some(AuditScope::OwnAndOwnedSessions),
        "audit scope"
    );
    assert_eq!(AuditScope::ALL.len(), 2, "two audit scopes");
}
