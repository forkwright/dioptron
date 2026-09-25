//! Audit scope defaults (D17.7) and the rule evaluator's view.

use syntheke::{AuditScope, Capability, GrantId, SessionId, TenantClass, TenantId};

/// The audit scope a tenant class's default grant carries, encoding the
/// audit-partition access decision D17.7 as a grant: the operator reads
/// `All`, an agent or sub-agent reads `OwnAndOwnedSessions`.
///
/// A class a later contract version adds gets the narrower scope.
#[must_use]
pub const fn default_audit_scope(class: TenantClass) -> AuditScope {
    match class {
        TenantClass::Operator => AuditScope::All,
        _ => AuditScope::OwnAndOwnedSessions,
    }
}

/// Whether `inner` reads no audit record that `outer` does not.
///
/// `OwnAndOwnedSessions` sits within `All`; each scope sits within itself.
/// A scope a later contract version adds sits only within itself.
#[must_use]
pub fn audit_scope_within(inner: AuditScope, outer: AuditScope) -> bool {
    inner == outer || (inner == AuditScope::OwnAndOwnedSessions && outer == AuditScope::All)
}

/// The scope an `AuditQuery` is answered with: the requested scope when the
/// grant covers it, otherwise the grant's own (narrower) scope. The reply
/// reports this value as the scope applied.
#[must_use]
pub fn applied_audit_scope(requested: AuditScope, granted: AuditScope) -> AuditScope {
    if audit_scope_within(requested, granted) {
        requested
    } else {
        granted
    }
}

/// What the rule evaluator sees of one call.
///
/// WHY no audit accessor: a rule must not read audit during evaluation
/// (contract § Audit partitions). This type exposes the call's facts and
/// the grant chain's identifiers only, and no method reaches audit records
/// or audit scope. Adding one is a contract change.
///
/// ```compile_fail
/// use epitrope::RuleView;
/// use syntheke::{Capability, TenantClass, TenantId};
///
/// let view = RuleView::new(
///     TenantId::from_bytes([1; 16]),
///     TenantClass::Agent,
///     Capability::Read,
///     None,
///     None,
///     &[],
/// );
/// let _ = view.audit();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleView<'a> {
    tenant: TenantId,
    class: TenantClass,
    capability: Capability,
    session: Option<SessionId>,
    target: Option<&'a str>,
    grant_chain: &'a [GrantId],
}

impl<'a> RuleView<'a> {
    /// Builds the view of one call. `grant_chain` is leaf first.
    ///
    /// # Examples
    ///
    /// ```
    /// use epitrope::RuleView;
    /// use syntheke::{Capability, TenantClass, TenantId};
    ///
    /// let view = RuleView::new(
    ///     TenantId::from_bytes([1; 16]),
    ///     TenantClass::Agent,
    ///     Capability::Read,
    ///     None,
    ///     None,
    ///     &[],
    /// );
    /// assert_eq!(view.capability(), Capability::Read);
    /// ```
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        class: TenantClass,
        capability: Capability,
        session: Option<SessionId>,
        target: Option<&'a str>,
        grant_chain: &'a [GrantId],
    ) -> Self {
        Self {
            tenant,
            class,
            capability,
            session,
            target,
            grant_chain,
        }
    }

    /// The acting tenant.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The acting tenant's class.
    #[must_use]
    pub const fn class(&self) -> TenantClass {
        self.class
    }

    /// The capability invoked.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// The session the call acts in, if any.
    #[must_use]
    pub const fn session(&self) -> Option<SessionId> {
        self.session
    }

    /// The target the caller supplied, if any.
    #[must_use]
    pub const fn target(&self) -> Option<&'a str> {
        self.target
    }

    /// The authorizing grant chain, leaf first.
    #[must_use]
    pub const fn grant_chain(&self) -> &'a [GrantId] {
        self.grant_chain
    }
}

#[cfg(test)]
mod tests;
