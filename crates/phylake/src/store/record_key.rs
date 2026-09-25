//! Physical record keys.
//!
//! Every key that holds a tenant, session, grant, invocation, artifact, or
//! idempotency component is a keyed HMAC-SHA256, so a raw key reveals none
//! of them. Keys for records sealed under the store keys hash under the
//! store index subkey; keys for records sealed under a tenant's keys hash
//! under that tenant's index subkey and always include the tenant id,
//! because a tenant-sealed record is bound to its tenant only through its
//! record key (the seal's key id is per tenant, not global).
//!
//! The hash input is a domain label followed by length-prefixed parts, so
//! two different part lists never produce the same input.
//!
//! Two keys carry an unhashed suffix after a hashed prefix: an audit entry
//! ends in its big-endian sequence number, and a session index entry ends
//! in the artifact id, so each range scans in order. Neither suffix holds a
//! tenant, session, or idempotency component. The artifact id is the
//! capturing invocation's id ([`super::artifact_ref`]), a ULID that leaks
//! only its creation time, as the design accepts; the invocation record's
//! own key is hashed, so the suffix links to nothing else on disk. The
//! global `audit_stub` key is the bare sequence number.

use syntheke::{
    ArtifactRef, Capability, GrantId, IdempotencyKey, InvocationId, SessionId, TenantId,
};
use zeroize::Zeroizing;

use super::records::LedgerRef;
use crate::Result;
use crate::crypto::{BlobAddress, KeyId, SubKey};

/// Length of every hashed key.
pub(crate) const HASHED_KEY_LEN: usize = 32;

/// Length of the sequence suffix on audit keys.
pub(crate) const SEQ_LEN: usize = 8;

/// A hashed record key.
pub(crate) type HashedKey = [u8; HASHED_KEY_LEN];

/// HMAC-SHA256 under `key` over `domain` and length-prefixed `parts`.
fn keyed(key: &SubKey, domain: &[u8], parts: &[&[u8]]) -> Result<HashedKey> {
    let mut input = Zeroizing::new(Vec::with_capacity(64));
    input.extend_from_slice(b"dioptron/v1/key/");
    input.extend_from_slice(domain);
    for part in parts {
        // WHY u32: every part is an id, a key of at most 64 bytes, or a
        // 32-byte address, so the prefix never truncates.
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        input.extend_from_slice(&len.to_le_bytes());
        input.extend_from_slice(part);
    }
    key.keyed_hash(&input)
}

/// Store-level keys: records sealed under the store keys.
pub(crate) mod store {
    use super::{
        ArtifactRef, GrantId, HashedKey, InvocationId, KeyId, LedgerRef, Result, SessionId, SubKey,
        TenantId, keyed,
    };

    /// A tenant record.
    pub(crate) fn tenant(index: &SubKey, tenant: TenantId) -> Result<HashedKey> {
        keyed(index, b"tenant", &[&tenant.to_bytes()])
    }

    /// A tenant's wrapped data key `key_id`.
    pub(crate) fn data_key(index: &SubKey, tenant: TenantId, key_id: KeyId) -> Result<HashedKey> {
        keyed(
            index,
            b"data-key",
            &[&tenant.to_bytes(), &key_id.get().to_le_bytes()],
        )
    }

    /// A tenant's wrapped addressing subkeys, present once its data key
    /// has rotated.
    pub(crate) fn address_keys(index: &SubKey, tenant: TenantId) -> Result<HashedKey> {
        keyed(index, b"address-keys", &[&tenant.to_bytes()])
    }

    /// A tenant's data-key rotation record.
    pub(crate) fn rekey(index: &SubKey, tenant: TenantId) -> Result<HashedKey> {
        keyed(index, b"rekey", &[&tenant.to_bytes()])
    }

    /// A crypto-shredded tenant's tombstone.
    pub(crate) fn tombstone(index: &SubKey, tenant: TenantId) -> Result<HashedKey> {
        keyed(index, b"tombstone", &[&tenant.to_bytes()])
    }

    /// A grant record.
    pub(crate) fn grant(index: &SubKey, grant: GrantId) -> Result<HashedKey> {
        keyed(index, b"grant", &[&grant.to_bytes()])
    }

    /// A revocation record.
    pub(crate) fn revocation(index: &SubKey, grant: GrantId) -> Result<HashedKey> {
        keyed(index, b"revocation", &[&grant.to_bytes()])
    }

    /// A session record.
    pub(crate) fn session(index: &SubKey, session: SessionId) -> Result<HashedKey> {
        keyed(index, b"session", &[&session.to_bytes()])
    }

    /// An invocation record.
    pub(crate) fn invocation(index: &SubKey, invocation: InvocationId) -> Result<HashedKey> {
        keyed(index, b"invocation", &[&invocation.to_bytes()])
    }

    /// A ledger.
    pub(crate) fn ledger(index: &SubKey, ledger: LedgerRef) -> Result<HashedKey> {
        match ledger {
            LedgerRef::Grant(id) => keyed(index, b"ledger/grant", &[&id.to_bytes()]),
            LedgerRef::Session(id) => keyed(index, b"ledger/session", &[&id.to_bytes()]),
            LedgerRef::Tenant(id) => keyed(index, b"ledger/tenant", &[&id.to_bytes()]),
        }
    }

    /// An artifact locator.
    pub(crate) fn locator(index: &SubKey, artifact: ArtifactRef) -> Result<HashedKey> {
        keyed(index, b"locator", &[&artifact.to_bytes()])
    }
}

/// Tenant-level keys: records sealed under one tenant's keys. Each takes
/// the tenant's index subkey and the tenant id.
pub(crate) mod tenant {
    use super::{
        ArtifactRef, BlobAddress, Capability, HashedKey, IdempotencyKey, InvocationId, Result,
        SessionId, SubKey, TenantId, keyed,
    };

    /// An idempotency entry for `key` under `capability`.
    pub(crate) fn idem(
        index: &SubKey,
        tenant: TenantId,
        capability: Capability,
        key: &IdempotencyKey,
    ) -> Result<HashedKey> {
        keyed(
            index,
            b"idem",
            &[
                &tenant.to_bytes(),
                capability.name().as_bytes(),
                key.as_bytes(),
            ],
        )
    }

    /// A published artifact side record.
    pub(crate) fn artifact(
        index: &SubKey,
        tenant: TenantId,
        artifact: ArtifactRef,
    ) -> Result<HashedKey> {
        keyed(
            index,
            b"artifact",
            &[&tenant.to_bytes(), &artifact.to_bytes()],
        )
    }

    /// The pending (B3) side record of `invocation`.
    pub(crate) fn pending(
        index: &SubKey,
        tenant: TenantId,
        invocation: InvocationId,
    ) -> Result<HashedKey> {
        keyed(
            index,
            b"pending",
            &[&tenant.to_bytes(), &invocation.to_bytes()],
        )
    }

    /// A blob at `address`.
    pub(crate) fn blob(
        index: &SubKey,
        tenant: TenantId,
        address: &BlobAddress,
    ) -> Result<HashedKey> {
        keyed(index, b"blob", &[&tenant.to_bytes(), address.as_bytes()])
    }

    /// The prefix of session `session`'s index entries; `owner` is the
    /// session's owner, whose keys seal the entries.
    pub(crate) fn session_index(
        index: &SubKey,
        owner: TenantId,
        session: SessionId,
    ) -> Result<HashedKey> {
        keyed(
            index,
            b"session-index",
            &[&owner.to_bytes(), &session.to_bytes()],
        )
    }

    /// The prefix of `tenant`'s audit entries.
    pub(crate) fn audit(index: &SubKey, tenant: TenantId) -> Result<HashedKey> {
        keyed(index, b"audit", &[&tenant.to_bytes()])
    }
}

/// `prefix` followed by `suffix`.
pub(crate) fn join(prefix: &HashedKey, suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(HASHED_KEY_LEN.saturating_add(suffix.len()));
    key.extend_from_slice(prefix);
    key.extend_from_slice(suffix);
    key
}
