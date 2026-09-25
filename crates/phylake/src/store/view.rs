//! Read views: epitrope's [`GrantView`] and [`LedgerView`] over a
//! snapshot or an open write transaction, and the tenant directory the
//! wire layer consults at the handshake.

use epitrope::{Grant, GrantView, LedgerId, LedgerView, Revocation, ViewError};
use fjall::Readable;
use snafu::OptionExt as _;
use syntheke::{Ceilings, Cost, GrantId, SessionId, TenantClass, TenantId};

use super::Store;
use super::record_key::store as keys;
use super::records::{
    GrantRecord, LedgerRecord, LedgerRef, RevocationRecord, SessionRecord, TenantRecord,
};
use super::slot;
use crate::Result;
use crate::error::InconsistentSnafu;

/// Store reads through one reader: a snapshot or a write transaction.
pub(crate) struct View<'a, R> {
    pub(crate) store: &'a Store,
    pub(crate) reader: &'a R,
}

impl<R: Readable> View<'_, R> {
    /// The grant record `id`.
    pub(crate) fn grant_record(&self, id: GrantId) -> Result<Option<GrantRecord>> {
        let key = keys::grant(self.store.keys.index(), id)?;
        self.store.get_global(self.reader, slot::GRANT, &key)
    }

    /// The revocation record of grant `id`.
    pub(crate) fn revocation_record(&self, id: GrantId) -> Result<Option<RevocationRecord>> {
        let key = keys::revocation(self.store.keys.index(), id)?;
        self.store.get_global(self.reader, slot::REVOCATION, &key)
    }

    /// The session record `id`.
    pub(crate) fn session_record(&self, id: SessionId) -> Result<Option<SessionRecord>> {
        let key = keys::session(self.store.keys.index(), id)?;
        self.store.get_global(self.reader, slot::SESSION, &key)
    }

    /// The tenant record `id`.
    pub(crate) fn tenant_record(&self, id: TenantId) -> Result<Option<TenantRecord>> {
        self.store.tenant_record(self.reader, id)
    }

    /// The ledger `id`; zero on every dimension when it has no record.
    pub(crate) fn ledger(&self, id: LedgerRef) -> Result<Cost> {
        let key = keys::ledger(self.store.keys.index(), id)?;
        Ok(self
            .store
            .get_global::<LedgerRecord, _>(self.reader, slot::LEDGER, &key)?
            .map_or_else(Cost::default, |record| record.used))
    }
}

impl<R: Readable> GrantView for View<'_, R> {
    fn grant(&self, id: GrantId) -> Result<Option<Grant>, ViewError> {
        self.grant_record(id)
            .and_then(|record| record.map(|record| record.to_grant()).transpose())
            .map_err(ViewError::new)
    }

    fn revocation(&self, id: GrantId) -> Result<Option<Revocation>, ViewError> {
        self.revocation_record(id)
            .map(|record| record.as_ref().map(RevocationRecord::to_revocation))
            .map_err(ViewError::new)
    }

    fn session_owner(&self, id: SessionId) -> Result<Option<TenantId>, ViewError> {
        self.session_record(id)
            .map(|record| record.map(|record| record.owner))
            .map_err(ViewError::new)
    }

    fn tenant_parent(&self, id: TenantId) -> Result<Option<TenantId>, ViewError> {
        self.tenant_record(id)
            .map(|record| record.and_then(|record| record.parent))
            .map_err(ViewError::new)
    }
}

impl<R: Readable> LedgerView for View<'_, R> {
    fn used(&self, id: LedgerId) -> Result<Cost, ViewError> {
        LedgerRef::from_ledger_id(id)
            .context(InconsistentSnafu {
                what: "ledger kind has no stored form",
            })
            .and_then(|ledger| self.ledger(ledger))
            .map_err(ViewError::new)
    }

    fn session_ceilings(&self, id: SessionId) -> Result<Ceilings, ViewError> {
        self.session_record(id)
            .map(|record| record.map_or_else(Ceilings::default, |record| record.ceilings))
            .map_err(ViewError::new)
    }

    fn tenant_ceilings(&self, id: TenantId) -> Result<Ceilings, ViewError> {
        self.tenant_record(id)
            .map(|record| record.map_or_else(Ceilings::default, |record| record.ceilings))
            .map_err(ViewError::new)
    }
}

/// What the wire layer needs to admit a tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TenantEntry {
    /// The tenant.
    pub id: TenantId,
    /// Its class.
    pub class: TenantClass,
    /// The Ed25519 verifying key its handshake signature must verify under.
    pub verifying_key: [u8; 32],
    /// The local user ids a connection for this tenant may come from.
    pub bound_uids: Vec<u32>,
    /// Its parent tenant.
    pub parent: Option<TenantId>,
}

impl From<TenantRecord> for TenantEntry {
    fn from(record: TenantRecord) -> Self {
        Self {
            id: record.id,
            class: record.class,
            verifying_key: record.verifying_key,
            bound_uids: record.bound_uids,
            parent: record.parent,
        }
    }
}

/// Tenant lookup for the handshake.
pub trait TenantDirectory {
    /// The tenant `id`, or `None` when it is not registered.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure.
    fn tenant(&self, id: TenantId) -> Result<Option<TenantEntry>>;
}

/// A consistent read-only view of the store: the snapshot the dry-run
/// planner and every read decision consult. It implements epitrope's
/// read traits and has no write method.
pub struct StoreSnapshot<'a> {
    store: &'a Store,
    snapshot: fjall::Snapshot,
}

impl core::fmt::Debug for StoreSnapshot<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreSnapshot").finish_non_exhaustive()
    }
}

impl<'a> StoreSnapshot<'a> {
    /// Wraps a fjall snapshot of `store`.
    pub(crate) const fn new(store: &'a Store, snapshot: fjall::Snapshot) -> Self {
        Self { store, snapshot }
    }

    /// The view over this snapshot.
    pub(crate) const fn view(&self) -> View<'_, fjall::Snapshot> {
        View {
            store: self.store,
            reader: &self.snapshot,
        }
    }
}

impl GrantView for StoreSnapshot<'_> {
    fn grant(&self, id: GrantId) -> Result<Option<Grant>, ViewError> {
        self.view().grant(id)
    }

    fn revocation(&self, id: GrantId) -> Result<Option<Revocation>, ViewError> {
        self.view().revocation(id)
    }

    fn session_owner(&self, id: SessionId) -> Result<Option<TenantId>, ViewError> {
        self.view().session_owner(id)
    }

    fn tenant_parent(&self, id: TenantId) -> Result<Option<TenantId>, ViewError> {
        self.view().tenant_parent(id)
    }
}

impl LedgerView for StoreSnapshot<'_> {
    fn used(&self, id: LedgerId) -> Result<Cost, ViewError> {
        self.view().used(id)
    }

    fn session_ceilings(&self, id: SessionId) -> Result<Ceilings, ViewError> {
        self.view().session_ceilings(id)
    }

    fn tenant_ceilings(&self, id: TenantId) -> Result<Ceilings, ViewError> {
        self.view().tenant_ceilings(id)
    }
}

impl TenantDirectory for StoreSnapshot<'_> {
    fn tenant(&self, id: TenantId) -> Result<Option<TenantEntry>> {
        Ok(self.view().tenant_record(id)?.map(TenantEntry::from))
    }
}

impl TenantDirectory for Store {
    fn tenant(&self, id: TenantId) -> Result<Option<TenantEntry>> {
        self.snapshot().tenant(id)
    }
}
