//! Capability, mode, tenant class, and scope vocabulary.

use crate::ids::SessionId;
use crate::names::named_enum;

named_enum! {
    /// A verb the capability surface offers (contract § Capabilities and mode).
    ///
    /// Non-exhaustive: a later contract version may add capabilities without
    /// renumbering.
    pub enum Capability {
        /// Open a new session owned by the acting tenant.
        SessionCreate => "SessionCreate",
        /// Branch an existing readable session into a new lineage with
        /// provenance.
        SessionFork => "SessionFork",
        /// Acquire a target through the producer seam and store it as an
        /// immutable artifact with provenance.
        Capture => "Capture",
        /// Submit a stored artifact into the knowledge pipeline.
        Ingest => "Ingest",
        /// Read a stored artifact the tenant is authorized to see.
        Read => "Read",
        /// Query indexed or knowledge state within the tenant's read scope.
        Query => "Query",
        /// Issue a child grant that attenuates one the tenant holds.
        GrantIssue => "GrantIssue",
        /// Revoke a grant the tenant issued, and its descendants.
        GrantRevoke => "GrantRevoke",
        /// Read audit records within the tenant's audit scope.
        AuditQuery => "AuditQuery",
    }
}

impl Capability {
    /// Whether an executed call of this capability changes durable state and
    /// therefore must carry an idempotency key (contract § Idempotency).
    #[must_use]
    pub const fn is_state_changing(self) -> bool {
        match self {
            Self::SessionCreate
            | Self::SessionFork
            | Self::Capture
            | Self::Ingest
            | Self::GrantIssue
            | Self::GrantRevoke => true,
            Self::Read | Self::Query | Self::AuditQuery => false,
        }
    }
}

named_enum! {
    /// Whether a request runs or only plans.
    pub enum Mode {
        /// Authorize, reserve, and perform the call.
        Execute => "Execute",
        /// Authorize and cost the call, then stop in the in-memory `Planned`
        /// state. Writes nothing durable, including no audit record.
        DryRun => "DryRun",
    }
}

named_enum! {
    /// The class of a tenant (`docs/design/tenancy.md`). Classes share one
    /// capability surface and differ only in the grants they hold.
    pub enum TenantClass {
        /// The single human operator.
        Operator => "Operator",
        /// An agent tenant.
        Agent => "Agent",
        /// A sub-agent tenant with a parent tenant.
        SubAgent => "SubAgent",
    }
}

named_enum! {
    /// The audit records an `AuditQuery` grant can see (contract § Audit
    /// partitions, D17.7).
    pub enum AuditScope {
        /// Every audit record. The operator's default.
        All => "All",
        /// The tenant's own records plus records from sessions it owns. The
        /// agent and sub-agent default.
        OwnAndOwnedSessions => "OwnAndOwnedSessions",
    }
}

/// The sessions a grant applies to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[non_exhaustive]
pub enum SessionScope {
    /// Sessions the holder owns.
    Own,
    /// An explicit set of sessions.
    Sessions(Vec<SessionId>),
}

#[cfg(test)]
mod tests {
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
}
