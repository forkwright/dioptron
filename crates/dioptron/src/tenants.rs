//! The server's tenant directory over the custody store.

use std::sync::Arc;

use phylake::Store;
use phylake::store::TenantDirectory as _;
use syntheke::TenantId;
use tracing::warn;

use crate::server::{TenantAuth, TenantDirectory};

/// Looks tenants up in the custody store for the handshake.
#[derive(Clone, Debug)]
pub struct StoreTenants(Arc<Store>);

impl StoreTenants {
    /// A directory over `store`.
    #[must_use]
    pub const fn new(store: Arc<Store>) -> Self {
        Self(store)
    }
}

impl TenantDirectory for StoreTenants {
    fn lookup(&self, tenant: TenantId) -> Option<TenantAuth> {
        match self.0.tenant(tenant) {
            Ok(entry) => entry.map(|entry| TenantAuth {
                verifying_key: entry.verifying_key,
                bound_uids: entry.bound_uids,
            }),
            Err(error) => {
                // WHY fail closed: an unreadable record is answered with the
                // same AuthFailed as an unknown tenant.
                warn!(%error, "tenant record unreadable");
                None
            }
        }
    }
}
