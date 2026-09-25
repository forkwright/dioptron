//! The plaintext `meta` keyspace: schema version, format, active root key
//! id, key-derivation salt, and key-check value.
//!
//! These fields are read before the store is unlocked, so they are stored
//! unsealed; none of them is secret. Tampering with them cannot open a
//! record: the schema version and key id are bound into every seal, and
//! the salt and key check gate the key derivation.
//!
//! Schema versioning: the store writes [`SCHEMA_VERSION`]. A store with a
//! newer version is refused ([`crate::Error::SchemaTooNew`]); a store with
//! an older one is refused with [`crate::Error::MigrationRequired`] until
//! the `migrate` command, which lands with the first schema change, has
//! upgraded it. Version 1 is the first schema, so no older store exists
//! yet.

use std::path::Path;

use fjall::{Readable, SingleWriterTxKeyspace};
use snafu::{OptionExt as _, ResultExt as _, ensure};

use super::WriteTx;
use crate::Result;
use crate::crypto::{KeyId, SchemaVersion, StoreSalt};
use crate::error::{
    DatabaseSnafu, MetaMalformedSnafu, MigrationRequiredSnafu, SchemaTooNewSnafu, StoreMissingSnafu,
};

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1);

/// The store format tag: the substrate and its layout generation.
const FORMAT: &[u8] = b"dioptron-custody/fjall3";

/// Field names in `meta`.
pub(crate) mod field {
    pub(crate) const SCHEMA_VERSION: &str = "schema_version";
    pub(super) const FORMAT: &str = "format";
    pub(super) const ROOT_KEY_ID: &str = "active_root_key_id";
    pub(super) const KDF_SALT: &str = "kdf_salt";
    pub(super) const KEY_CHECK: &str = "key_check";
}

/// The unlocking fields of `meta`.
pub(crate) struct Meta {
    root_key_id: KeyId,
    salt: StoreSalt,
    check: [u8; 32],
}

impl Meta {
    /// The fields of a new store.
    pub(crate) const fn new(root_key_id: KeyId, salt: StoreSalt, check: [u8; 32]) -> Self {
        Self {
            root_key_id,
            salt,
            check,
        }
    }

    /// The active root key id.
    pub(crate) const fn root_key_id(&self) -> KeyId {
        self.root_key_id
    }

    /// The key-derivation salt.
    pub(crate) const fn salt(&self) -> &StoreSalt {
        &self.salt
    }

    /// The stored key-check value.
    pub(crate) const fn check(&self) -> &[u8; 32] {
        &self.check
    }
}

/// Stages every `meta` field of a new store.
pub(crate) fn write(tx: &mut WriteTx<'_>, keyspace: &SingleWriterTxKeyspace, meta: &Meta) {
    tx.insert(
        keyspace,
        field::SCHEMA_VERSION,
        SCHEMA_VERSION.get().to_le_bytes().to_vec(),
    );
    tx.insert(keyspace, field::FORMAT, FORMAT.to_vec());
    tx.insert(
        keyspace,
        field::ROOT_KEY_ID,
        meta.root_key_id.get().to_le_bytes().to_vec(),
    );
    tx.insert(keyspace, field::KDF_SALT, meta.salt.as_bytes().to_vec());
    tx.insert(keyspace, field::KEY_CHECK, meta.check.to_vec());
}

/// Reads and checks `meta`: format, then schema version, then the
/// unlocking fields. Writes nothing.
pub(crate) fn read<R: Readable>(
    reader: &R,
    keyspace: &SingleWriterTxKeyspace,
    path: &Path,
) -> Result<Meta> {
    let format = field_bytes(reader, keyspace, field::FORMAT, path)?;
    ensure!(
        format == FORMAT,
        MetaMalformedSnafu {
            field: field::FORMAT
        }
    );
    let found = u32::from_le_bytes(fixed(reader, keyspace, field::SCHEMA_VERSION, path)?);
    let supported = SCHEMA_VERSION.get();
    ensure!(found <= supported, SchemaTooNewSnafu { found, supported });
    ensure!(
        found == supported,
        MigrationRequiredSnafu { found, supported }
    );
    Ok(Meta {
        root_key_id: KeyId::new(u32::from_le_bytes(fixed(
            reader,
            keyspace,
            field::ROOT_KEY_ID,
            path,
        )?)),
        salt: StoreSalt::from_bytes(fixed(reader, keyspace, field::KDF_SALT, path)?),
        check: fixed(reader, keyspace, field::KEY_CHECK, path)?,
    })
}

/// The bytes of `name`; a missing field means no complete store.
fn field_bytes<R: Readable>(
    reader: &R,
    keyspace: &SingleWriterTxKeyspace,
    name: &'static str,
    path: &Path,
) -> Result<Vec<u8>> {
    let value = reader
        .get(keyspace, name)
        .context(DatabaseSnafu)?
        .context(StoreMissingSnafu {
            path: path.to_path_buf(),
            missing: name,
        })?;
    Ok(value.to_vec())
}

/// The bytes of `name` as a fixed-length array.
fn fixed<const N: usize, R: Readable>(
    reader: &R,
    keyspace: &SingleWriterTxKeyspace,
    name: &'static str,
    path: &Path,
) -> Result<[u8; N]> {
    let bytes = field_bytes(reader, keyspace, name, path)?;
    <[u8; N]>::try_from(bytes.as_slice())
        .ok()
        .context(MetaMalformedSnafu { field: name })
}
