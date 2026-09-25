//! Read-only views the decisions consult.
//!
//! WHY traits with read methods only: the dry-run planner and every
//! decision take these as trait objects, and a trait with no write method
//! gives a caller no way to write through it. The store implements them
//! over a consistent snapshot.

use core::fmt;

use syntheke::{Ceilings, Cost, GrantId, SessionId, TenantId};

use crate::grant::{Grant, Revocation};

/// A failure reported by a view implementation, such as a storage read
/// error. Decisions surface it as [`crate::Error::View`] and fail closed.
pub struct ViewError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl ViewError {
    /// Wraps the implementation's error.
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>) -> Self {
        Self(source.into())
    }
}

impl fmt::Debug for ViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ViewError").field(&self.0).finish()
    }
}

impl fmt::Display for ViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for ViewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Grants, revocation records, and session ownership.
pub trait GrantView {
    /// The grant `id`, or `None` when the view holds no such grant.
    ///
    /// # Errors
    ///
    /// Any failure of the underlying read.
    fn grant(&self, id: GrantId) -> Result<Option<Grant>, ViewError>;

    /// The revocation record for grant `id`, or `None` when it is not
    /// revoked.
    ///
    /// # Errors
    ///
    /// Any failure of the underlying read.
    fn revocation(&self, id: GrantId) -> Result<Option<Revocation>, ViewError>;

    /// The tenant that owns session `id`, or `None` when no such session
    /// exists.
    ///
    /// # Errors
    ///
    /// Any failure of the underlying read.
    fn session_owner(&self, id: SessionId) -> Result<Option<TenantId>, ViewError>;

    /// The parent tenant of `id`, or `None` for a tenant without one (the
    /// operator) or an unknown tenant.
    ///
    /// # Errors
    ///
    /// Any failure of the underlying read.
    fn tenant_parent(&self, id: TenantId) -> Result<Option<TenantId>, ViewError>;
}

/// Identifies one budget ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum LedgerId {
    /// The ledger of one grant in the chain. Its ceilings are the grant's.
    Grant(GrantId),
    /// The ledger of the session the call acts in.
    Session(SessionId),
    /// The ledger of the acting tenant.
    Tenant(TenantId),
}

/// Budget ledgers.
pub trait LedgerView {
    /// The amount debited from ledger `id`: settled consumption plus
    /// reservations not yet settled. Zero on every dimension for a ledger
    /// with no record.
    ///
    /// # Errors
    ///
    /// Any failure of the underlying read.
    fn used(&self, id: LedgerId) -> Result<Cost, ViewError>;

    /// The ceilings on session `id`'s ledger.
    ///
    /// # Errors
    ///
    /// Any failure of the underlying read.
    fn session_ceilings(&self, id: SessionId) -> Result<Ceilings, ViewError>;

    /// The ceilings on tenant `id`'s ledger.
    ///
    /// # Errors
    ///
    /// Any failure of the underlying read.
    fn tenant_ceilings(&self, id: TenantId) -> Result<Ceilings, ViewError>;
}

/// A read-only snapshot: grants and ledgers read at one consistent point.
///
/// Implemented for every type that implements both views.
pub trait Snapshot: GrantView + LedgerView {}

impl<T: GrantView + LedgerView + ?Sized> Snapshot for T {}
