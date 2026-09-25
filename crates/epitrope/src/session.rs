//! Whether a capability acts in a session (contract § Session requirement).

use syntheke::Capability;

/// How a capability relates to the session a call acts in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionRequirement {
    /// The call must name a session; a call without one is refused with
    /// `Denied{SessionRequired}`.
    Required,
    /// The call may name a session, which then narrows what it reads.
    Optional,
    /// The call acts in no session. Its request body carries none, so a
    /// session supplied for it is a caller fault
    /// ([`crate::Error::SessionNotApplicable`]), never a decision.
    Forbidden,
}

/// The session requirement of `capability`.
///
/// | Capability | Requirement |
/// |---|---|
/// | `Capture`, `Ingest`, `Read`, `Query`, `SessionFork` | required |
/// | `AuditQuery` | optional (it narrows the audit scope) |
/// | `SessionCreate`, `GrantIssue`, `GrantRevoke` | forbidden |
///
/// WHY a capability a later contract version adds is required: requiring a
/// session refuses a call that names none, which is the closed side until
/// the new capability states its own requirement.
#[must_use]
pub const fn session_requirement(capability: Capability) -> SessionRequirement {
    match capability {
        Capability::AuditQuery => SessionRequirement::Optional,
        Capability::SessionCreate | Capability::GrantIssue | Capability::GrantRevoke => {
            SessionRequirement::Forbidden
        }
        _ => SessionRequirement::Required,
    }
}

#[cfg(test)]
mod tests;
