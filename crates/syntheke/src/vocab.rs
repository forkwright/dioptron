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
mod tests;
