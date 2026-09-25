//! Artifact reads and session queries.
//!
//! The caller authorizes before it reads: these operations answer for any
//! artifact or session, and return `None` for one that does not exist or
//! is not yet published. They never return an error that distinguishes a
//! missing record from a present one, so the caller can map `None` and a
//! refusal to the same `NotFoundOrDenied` reply. Only published artifacts
//! are reachable: a B3 blob and its pending record have no locator and no
//! session index entry.

use fjall::Readable as _;
use snafu::{OptionExt as _, ResultExt as _};
use syntheke::{
    ArtifactRef, GrantId, QueryPage, ReadChunk, SessionId, SourceRef, TenantId, Timestamp,
};

use super::codec::StoredRecord as _;
use super::record_key::{self, HASHED_KEY_LEN};
use super::records::{ArtifactRecord, LocatorRecord, SessionIndexRecord};
use super::view::View;
use super::{Store, slot};
use crate::Result;
use crate::crypto::{BlobAddress, TenantKeys};
use crate::error::{DatabaseSnafu, InconsistentSnafu};

/// A published artifact's side record, without its envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactInfo {
    /// The artifact.
    pub artifact: ArtifactRef,
    /// The tenant that captured it.
    pub owner: TenantId,
    /// The session it belongs to.
    pub session: Option<SessionId>,
    /// The chain it was captured under, leaf first.
    pub grant_chain: Vec<GrantId>,
    /// Its evidence identity.
    pub source: SourceRef,
    /// The derived text view.
    pub text_view: Option<String>,
    /// Whether the text view was cut to the output bound.
    pub truncated: bool,
    /// Length of the text view in bytes.
    pub output_bytes: u64,
    /// Length of the verbatim envelope in bytes.
    pub envelope_len: u64,
    /// Whether the authorizing grant was revoked after the effect started.
    pub revoked_after_effect: bool,
    /// When it was published.
    pub published_at: Timestamp,
}

impl Store {
    /// The published artifact `artifact`, or `None`.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure.
    pub fn artifact(&self, artifact: ArtifactRef) -> Result<Option<ArtifactInfo>> {
        let snapshot = self.db.read_tx();
        let Some((record, _)) = self.published(&snapshot, artifact)? else {
            return Ok(None);
        };
        let published_at = record.published_at.context(InconsistentSnafu {
            what: "published side record has no publish time",
        })?;
        Ok(Some(ArtifactInfo {
            artifact: record.artifact,
            owner: record.tenant,
            session: record.session,
            grant_chain: record.grant_chain,
            source: record.source,
            text_view: record.text_view,
            truncated: record.truncated,
            output_bytes: record.output_bytes,
            envelope_len: record.blob_len,
            revoked_after_effect: record.revoked_after_effect,
            published_at,
        }))
    }

    /// Up to `len` bytes of the published artifact's verbatim envelope
    /// from `offset`, or `None` when the artifact is not published. A
    /// chunk past the end is empty.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure.
    pub fn read_artifact(
        &self,
        artifact: ArtifactRef,
        offset: u64,
        len: u32,
    ) -> Result<Option<ReadChunk>> {
        let snapshot = self.db.read_tx();
        let Some((record, keys)) = self.published(&snapshot, artifact)? else {
            return Ok(None);
        };
        let address = BlobAddress::from_bytes(record.blob_address);
        let blob_key = record_key::tenant::blob(keys.index(), record.tenant, &address)?;
        let sealed = snapshot
            .get(self.ks.get(slot::BLOB.keyspace)?, blob_key)
            .context(DatabaseSnafu)?
            .context(InconsistentSnafu {
                what: "published artifact has no blob",
            })?;
        let envelope = Self::open_bytes(&[keys.blob()], slot::BLOB, &blob_key, &sealed)?;
        let total = envelope.len();
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(total);
        let end = start
            .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
            .min(total);
        let bytes = envelope.get(start..end).unwrap_or_default().to_vec();
        Ok(Some(ReadChunk {
            offset,
            bytes,
            total_len: u64::try_from(total).unwrap_or(u64::MAX),
        }))
    }

    /// The published artifacts of `session` after `after`, at most
    /// `limit`, in artifact id order; `None` when the session does not
    /// exist.
    ///
    /// # Errors
    ///
    /// A storage, decryption, or decoding failure.
    pub fn session_artifacts(
        &self,
        session: SessionId,
        after: Option<ArtifactRef>,
        limit: u32,
    ) -> Result<Option<QueryPage>> {
        let snapshot = self.db.read_tx();
        let view = View {
            store: self,
            reader: &snapshot,
        };
        let Some(record) = view.session_record(session)? else {
            return Ok(None);
        };
        let keys = self.tenant_keys(&snapshot, record.owner)?;
        let prefix = record_key::tenant::session_index(keys.index(), record.owner, session)?;
        let from = after.map_or_else(
            || prefix.to_vec(),
            |artifact| {
                // WHY append a byte: the range starts strictly after
                // `artifact`, whose key is the prefix plus its 16 bytes.
                let mut key = record_key::join(&prefix, &artifact.to_bytes());
                key.push(0);
                key
            },
        );
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut result_refs = Vec::new();
        let mut more = false;
        for guard in snapshot.range(self.ks.get(slot::SESSION_INDEX.keyspace)?, from..) {
            let (key, sealed) = guard.into_inner().context(DatabaseSnafu)?;
            if key.get(..HASHED_KEY_LEN) != Some(&prefix[..]) {
                break;
            }
            if result_refs.len() >= limit {
                more = true;
                break;
            }
            let plain = Self::open_bytes(&[keys.meta()], slot::SESSION_INDEX, &key, &sealed)?;
            let entry = SessionIndexRecord::decode(&plain, slot::SESSION_INDEX.keyspace.name())?;
            result_refs.push(entry.artifact);
        }
        Ok(Some(QueryPage { result_refs, more }))
    }

    /// The published side record of `artifact` and its owner's keys.
    fn published<R: fjall::Readable>(
        &self,
        reader: &R,
        artifact: ArtifactRef,
    ) -> Result<Option<(ArtifactRecord, std::sync::Arc<TenantKeys>)>> {
        let locator_key = record_key::store::locator(self.keys.index(), artifact)?;
        let Some(locator) =
            self.get_global::<LocatorRecord, _>(reader, slot::LOCATOR, &locator_key)?
        else {
            return Ok(None);
        };
        let keys = self.tenant_keys(reader, locator.owner)?;
        let side_key = record_key::tenant::artifact(keys.index(), locator.owner, artifact)?;
        let record = self
            .get::<ArtifactRecord, _>(reader, slot::ARTIFACT, &side_key, &[keys.meta()])?
            .context(InconsistentSnafu {
                what: "artifact locator has no side record",
            })?;
        Ok(Some((record, keys)))
    }
}
