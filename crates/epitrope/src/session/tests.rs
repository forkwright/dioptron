use super::*;

#[test]
fn session_requirement_matches_the_contract_table() {
    let expected = [
        (Capability::SessionCreate, SessionRequirement::Forbidden),
        (Capability::SessionFork, SessionRequirement::Required),
        (Capability::Capture, SessionRequirement::Required),
        (Capability::Ingest, SessionRequirement::Required),
        (Capability::Read, SessionRequirement::Required),
        (Capability::Query, SessionRequirement::Required),
        (Capability::GrantIssue, SessionRequirement::Forbidden),
        (Capability::GrantRevoke, SessionRequirement::Forbidden),
        (Capability::AuditQuery, SessionRequirement::Optional),
    ];
    let listed: Vec<Capability> = expected.iter().map(|&(c, _)| c).collect();
    assert_eq!(
        listed,
        Capability::ALL,
        "the table covers every version 1 capability"
    );
    for (capability, requirement) in expected {
        assert_eq!(session_requirement(capability), requirement, "{capability}");
    }
}
