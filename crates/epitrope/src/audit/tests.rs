use super::*;

#[test]
fn default_audit_scope_encodes_d17_7() {
    assert_eq!(
        default_audit_scope(TenantClass::Operator),
        AuditScope::All,
        "operator reads all audit"
    );
    assert_eq!(
        default_audit_scope(TenantClass::Agent),
        AuditScope::OwnAndOwnedSessions,
        "agent reads its own and owned sessions"
    );
    assert_eq!(
        default_audit_scope(TenantClass::SubAgent),
        AuditScope::OwnAndOwnedSessions,
        "sub-agent reads its own and owned sessions"
    );
}

#[test]
fn audit_scope_within_orders_own_below_all() {
    let own = AuditScope::OwnAndOwnedSessions;
    let all = AuditScope::All;
    assert!(audit_scope_within(own, all), "own within all");
    assert!(audit_scope_within(own, own), "own within own");
    assert!(audit_scope_within(all, all), "all within all");
    assert!(!audit_scope_within(all, own), "all not within own");
}

#[test]
fn applied_audit_scope_clamps_to_the_grant() {
    let own = AuditScope::OwnAndOwnedSessions;
    let all = AuditScope::All;
    assert_eq!(applied_audit_scope(all, own), own, "clamped down");
    assert_eq!(applied_audit_scope(own, all), own, "narrower request kept");
    assert_eq!(applied_audit_scope(all, all), all, "operator reads all");
}

#[test]
fn rule_view_returns_the_call_facts() {
    let chain = [GrantId::from_bytes([2; 16]), GrantId::from_bytes([3; 16])];
    let view = RuleView::new(
        TenantId::from_bytes([1; 16]),
        TenantClass::SubAgent,
        Capability::Capture,
        Some(SessionId::from_bytes([4; 16])),
        Some("https://example.com/"),
        &chain,
    );
    assert_eq!(view.tenant(), TenantId::from_bytes([1; 16]), "tenant");
    assert_eq!(view.class(), TenantClass::SubAgent, "class");
    assert_eq!(view.capability(), Capability::Capture, "capability");
    assert_eq!(
        view.session(),
        Some(SessionId::from_bytes([4; 16])),
        "session"
    );
    assert_eq!(view.target(), Some("https://example.com/"), "target");
    assert_eq!(view.grant_chain(), &chain, "chain");
}
