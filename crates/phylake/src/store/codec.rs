//! Record encoding: rkyv, read back only through validated access.
//!
//! WHY rkyv: the wire contract already uses rkyv with bytecheck
//! validation, so the store adds no second serializer. A stored record is
//! opened (authenticated) before it is decoded, and then validated as a
//! whole archive before any field is read.

use rkyv::rancor;
use rkyv::util::AlignedVec;
use snafu::ResultExt as _;
use zeroize::Zeroize as _;

use super::records::{
    ArtifactRecord, AuditEntryRecord, AuditStubRecord, GrantRecord, IdemRecord, InvocationRecord,
    LedgerRecord, LocatorRecord, RekeyRecord, RevocationRecord, SessionIndexRecord, SessionRecord,
    TenantRecord, TombstoneRecord,
};
use crate::Result;
use crate::error::{DecodeSnafu, EncodeSnafu};

/// A type the store persists as an rkyv archive.
pub(crate) trait StoredRecord: Sized {
    /// Serializes the record.
    fn encode(&self) -> Result<AlignedVec>;

    /// Validates and deserializes a record read from `keyspace`.
    fn decode(bytes: &[u8], keyspace: &'static str) -> Result<Self>;
}

/// Implements [`StoredRecord`] for each listed record type.
macro_rules! stored_record {
    ($($name:ty),+ $(,)?) => {
        $(impl StoredRecord for $name {
            fn encode(&self) -> Result<AlignedVec> {
                rkyv::to_bytes::<rancor::Error>(self).context(EncodeSnafu)
            }

            fn decode(bytes: &[u8], keyspace: &'static str) -> Result<Self> {
                let mut aligned = AlignedVec::<16>::with_capacity(bytes.len());
                aligned.extend_from_slice(bytes);
                let decoded = rkyv::access::<<$name as rkyv::Archive>::Archived, rancor::Error>(
                    &aligned,
                )
                .and_then(rkyv::deserialize::<$name, rancor::Error>)
                .context(DecodeSnafu { keyspace });
                // WHY: the aligned copy holds opened plaintext.
                let copy: &mut [u8] = &mut aligned;
                copy.zeroize();
                decoded
            }
        })+
    };
}

stored_record! {
    TenantRecord,
    GrantRecord,
    RevocationRecord,
    SessionRecord,
    InvocationRecord,
    IdemRecord,
    LedgerRecord,
    ArtifactRecord,
    LocatorRecord,
    SessionIndexRecord,
    AuditEntryRecord,
    AuditStubRecord,
    RekeyRecord,
    TombstoneRecord,
}
