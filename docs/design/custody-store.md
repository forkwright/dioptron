# Custody store

This document freezes the D5 durable-storage decision for Phase 01: the substrate
choice and its migration exception, the keyspace schema, the atomic publish
point, the failure-injection specification, encryption at rest, schema
versioning, the rekey protocol, backup and restore, and crypto-shredding. The
custody crate (proposed `phylake`, `docs/lexicon.md`) is the only executable form
of this decision.

The store keeps what the runtime acquires and keeps it sealed. It is the record
of truth for tenants, grants, revocations, sessions, invocations, budgets,
artifacts, and audit. Any search or retrieval index built over it is a
rebuildable projection, not the record, and can be dropped and recomputed
without loss.

## Storage decision

The first durable D5 store is built directly on fjall 3 transactional keyspaces.
This is the fjall storage decision (D17.14), recorded as a named STORAGE-TIERS
migration exception per `kanon/crates/basanos/standards/STORAGE-TIERS.md`.

No qualified fleet tier fits the need yet:

- **Not pinax 0.0.4.** The relational tier has no multi-row transaction, no
  schema migration, and no encryption. The invocation lifecycle needs a
  multi-record transaction per state transition, the store needs schema
  versioning with a migration path, and every sensitive record must be encrypted
  at rest. Pinax 0.0.4 provides none of these.
- **Not koina.** The append and blob tier exposes no public content-addressed
  blob API. The store needs content-addressed blob storage with tenant-scoped
  addressing under its own encryption; koina offers no public surface to build
  that on.

Raw fjall is therefore the sanctioned substrate under the migration exception.
The owning crate names pinax and koina as the target tiers in its roadmap.
Removal of the direct fjall dependency will be tracked in a STORAGE-TIERS
exception issue, to be filed when the custody crate lands; its number is not yet
assigned.
Retirement condition: the exception is retired when pinax ships a multi-row
transaction with schema migration and encryption, and koina exposes a public
content-addressed blob API. Until both exist, this store uses fjall directly and
does not reach for any other raw upstream store.

## Keyspace schema

The store is a set of fjall keyspaces, each committed with a durable sync per
transaction. Plaintext holds only non-sensitive metadata; every other keyspace
holds sealed records.

| Keyspace | Contents | Sealed |
|---|---|---|
| `meta` | schema version, format, active root key id, key-derivation salt, and a key-check value | no (non-sensitive) |
| `keys` | per-tenant random data keys, each wrapped by a root-derived key-encryption key; a rotated tenant's addressing subkeys, wrapped the same way | yes (wrapped) |
| `tenants` | tenant records: class, verifying key, bound user ids, parent; tombstones of shredded tenants | yes |
| `grants` | grant records | yes |
| `revocations` | revocation records: grant id, effect sequence, effect time | yes |
| `sessions` | session records | yes |
| `invocations` | invocation intent and lifecycle state | yes |
| `idem` | idempotency index: keyed hash to invocation id and request binding | yes |
| `ledgers` | per-dimension budget ledgers | yes |
| `artifacts` | side records: tenant, grant chain, session, reservation, classification, lineage, provenance digest, blob address; pending side records; artifact locators (see below) | yes |
| `blobs` | verbatim producer envelopes, addressed by content | yes |
| `session_index` | per-session artifact index | yes |
| `audit` | per-tenant sequenced audit records | yes |
| `audit_stub` | global minimal record: id, capability, outcome kind, time | yes |
| `rekey` | tenant data-key rotation records: key ids, cursor, progress, done flag | yes |

Keys that contain a tenant, session, or idempotency component are keyed hashes
under an index subkey, so a raw key does not reveal the plaintext component.
ULIDs used as identifiers do leak their creation time by construction; this is
documented and accepted, not hidden. Two keys carry an unhashed suffix after a
keyed prefix so their ranges scan in order: a per-tenant audit entry ends in
its big-endian sequence number, and a session index entry ends in the artifact
id. The global `audit_stub` key is the bare sequence number.

### Sealing scope

Two sealing scopes exist, and this table is normative: a record not listed
here is sealed under the root-derived keys only if it carries no acquired
content.

| Scope | Sealed under | Keyspaces and record kinds |
|---|---|---|
| plaintext | nothing | `meta` |
| wrapped | the root-derived key-encryption subkey | `keys` (tenant data keys and addressing subkeys) |
| store | the root-derived metadata subkey; record keys hashed under the root-derived index subkey | `tenants` (records and tombstones), `grants`, `revocations`, `sessions`, `invocations`, `ledgers`, artifact locators in `artifacts`, `audit_stub`, `rekey` |
| tenant | the tenant's data key: its blob subkey for `blobs`, its audit subkey for `audit`, its metadata subkey for the rest; record keys hashed under the tenant's index subkey and always including the tenant id | `blobs`, published and pending side records in `artifacts`, `session_index`, `idem`, `audit` |

Directory and lifecycle records are store-sealed because authorization walks
grant chains across tenants and restart recovery scans every invocation, so
these records must open before any tenant is known. They carry identifiers,
amounts, lineage, and timestamps, never acquired content. Tenant data keys seal
acquired content and everything derived from a tenant's requests: envelopes,
text views, source references, provenance digests, blob addresses, idempotency
bindings, and the per-tenant audit trail. A tenant-sealed record is bound to its
tenant only through its record key, because the seal's key id is per tenant,
not global; every tenant-scoped record key therefore hashes the tenant id in.
A session index entry is sealed under the session owner's keys, which may
differ from the capturing tenant's.

No record holds a capture's target URL: the target is authorized at B1 and
passed to the producer, and only the producer's envelope, which may contain
it, is stored, tenant-sealed. The artifact side record's classification is
always empty in Phase 01; it is filled when knowledge classification (D7)
lands.

### The `artifacts` keyspace

The `artifacts` keyspace holds three record kinds, each bound to its kind by
the seal's additional data so one cannot be read as another:

- a **pending side record** (tenant-sealed), written at B3 under a key hashed
  from the tenant and the invocation, and removed at B4;
- a **published side record** (tenant-sealed), written at B4 under a key hashed
  from the tenant and the artifact id;
- an **artifact locator** (store-sealed), written at B4 under a key hashed from
  the artifact id alone, naming the owning tenant and session so a reader can
  find the owner's keys.

The locator is the only way to reach a published side record, and a pending
record has none, so a pending capture is unreachable by artifact id. The store
assigns the artifact id: it is the invocation's own id. Invocation ids are
unique in the store, so two invocations never claim one artifact and a
roll-forward publish never collides with another.

### Directory writes

Tenant registration, root grant installation, grant issue, session create, and
session fork are idempotent by the caller-chosen id. A repeat with identical
content returns the stored result and writes nothing, including no audit
entry; the same id with different content is refused as a conflict. A repeated
grant issue is matched against the stored child before any authorization
decision, because the parent's remaining budget or validity may have moved
since the child was issued; a stored grant is not re-decided. Revoking a
revoked grant returns the first revocation record.

## Atomic publish point

A capture becomes visible at exactly one transaction: the publish transaction
commits the artifact side record, the session index entry, and the invocation
state together. Before that transaction, the blob may be written but no index or
record points at it, so no reader can reach it. This is B4 in the invocation
lifecycle (`docs/design/capability-contract.md`). Immutability of the published
artifact satisfies R4.4: once published, the artifact record and its blob are not
rewritten; a correction is a new artifact with lineage, not a mutation.

## Failure-injection specification

The store proves its crash-safety by injection, not by inspection. A failpoint
trait, a no-op by default, exposes a `before_commit` and an `after_commit` hook
at each lifecycle boundary B1 through B5 and at each rekey commit: the
rotation's begin, each batch, its retire, and a root rotation. A test
sets one failpoint, drives the invocation or rekey to it, simulates a crash,
reopens the store, runs the recovery scan, and asserts the recovered state and
the producer call count.

| Injection point | Expected post-recovery state | Producer call count |
|---|---|---|
| before B1 commit | No invocation, no reservation. | 0 |
| after B1 commit | `Released(Abandoned)`; reservation released. | 0 |
| before B2 commit | `Released(Abandoned)`; producer never dispatched. | 0 |
| after B2 commit | `UnknownEffect`; the whole reservation is charged on every dimension; never re-dispatched. | at most 1, never increased by recovery |
| before B3 commit | B2 is the last committed state, so the B2 rule applies: `UnknownEffect`, the whole reservation charged; the uncommitted blob write is discarded with its transaction. | unchanged by recovery |
| after B3 commit | Roll forward: publish then settle; artifact becomes visible. | unchanged by recovery |
| before B4 commit | Capture not visible; roll forward to publish and settle. | unchanged by recovery |
| after B4 commit | Visible; roll forward to settle. | unchanged by recovery |
| before B5 commit | Visible; roll forward to settle. | unchanged by recovery |
| after B5 commit | Terminal; no change. | unchanged by recovery |
| before the rekey begin commit | No rotation; every record under the old key. | not applicable |
| after the rekey begin commit | New key active; rotation resumes from the start of the walk. | not applicable |
| before or after a rekey batch commit | Rekey resumes from the last committed cursor; each record opens under exactly one of the two keys. | not applicable |
| before the rekey retire commit | Walk complete; the retire transaction runs again. | not applicable |
| after the rekey retire commit | Rotation done; old key deleted. | not applicable |
| before a root rotation commit | The old root key opens the store; the new one is refused. | not applicable |
| after a root rotation commit | The new root key opens the store; the old one is refused. | not applicable |

Every recovered terminal is recorded exactly: `Released(Abandoned)` is stored
as that reason in the invocation record and its audit entry, never as a
cancellation, even though an idempotent replay of it replies `Cancelled`.

The invariant across every row: recovery never increases the producer call
count. Recovery may release, settle, or publish already-transferred bytes, but it
never dispatches a producer call, because a possibly-live external effect is
resolved to `UnknownEffect` rather than repeated. This is the durable expression
of the failure-recovery requirement R9.5: a long-running invocation is resumable
across a restart, to a single known state.

The same specification runs at two levels: in-process, by injecting a crash and
reopening the store in one test; and at the process level, by a daemon built with
a failpoints feature that aborts on a configured environment variable, after
which the independent client reconnects and observes the recovered state.

## Encryption at rest

The store encrypts every sensitive record at rest. This is encryption at rest
(D17.15) and satisfies the R11 encryption-at-rest requirement in the first
durable store rather than deferring it.

### Key hierarchy

A single root key is a 32-byte file. The store refuses to open if the file's
group or other permission bits are set. The root key lives in a secret container
that zeroes on drop. From the root key the store derives per-purpose subkeys with
HKDF-SHA256: a blob subkey, a metadata subkey, an audit subkey, an index subkey,
a key-encryption subkey, and a key-check subkey. Each tenant has a random data
key, stored wrapped by the key-encryption subkey; from a tenant data key the
store derives that tenant's blob, blob-address, metadata, audit, and index
subkeys. A tenant's plaintext data keys never touch disk unwrapped.

The index and blob-address subkeys are the tenant's addressing subkeys: every
tenant record key and blob address is computed under them. They come from the
tenant's first data key and do not rotate with it (see the rekey protocol). At
the tenant's first data-key rotation they are stored wrapped under the
key-encryption subkey, with a label distinct from a wrapped data key's, so the
first data key can be deleted without losing them.

### Sealing and additional authenticated data

A sealed value is a record version, a key id, a 24-byte nonce, and the
ciphertext with its authentication tag, sealed with XChaCha20-Poly1305. The
additional authenticated data binds a fixed protocol label, the schema version,
the record kind, the key id, the keyspace, and the record key. Binding all of
these means a sealed value cannot be moved to another keyspace, another record
key, another schema version, or another key id and still open: the seal is valid
only in the exact place it was written.

### Keyed blob addressing

A blob address is a keyed hash over the plaintext under the tenant's
blob-address key. Addressing is therefore tenant-scoped: the same bytes acquired
by two tenants get two addresses, so there is no cross-tenant deduplication and
no address that a foreign tenant could compute to test for another tenant's
content. A plaintext content digest is sealed inside the record as provenance;
the on-disk address never exposes it.

The address itself is not the physical key. A blob is stored under
HMAC-SHA256(tenant index subkey, tenant id ‖ address), with the same domain
label and length prefixes as every other record key, so the physical key binds
the tenant as every tenant-sealed key does, and the address appears on disk
only inside the sealed side record. Identical envelopes captured by one tenant
share one blob, which is never rewritten once written.

### Tenant key cache

The store caches each tenant's unwrapped, derived subkeys in memory, and only
when the key ids the caller read match the latest committed tenant and rekey
records, checked under the cache lock; a rolled-back registration therefore
never leaves a cached key, and a reader holding an older snapshot cannot put
back keys that a rotation or shred evicted. The cache holds the keys in zeroizing containers. An entry
is keyed by the active and retiring data-key ids that the caller's own
transaction or snapshot reads from the tenant and rekey records, and is used
only when they match; a writer therefore always seals under the key its
transaction names as active, never under one a concurrent rotation replaced.
Data-key rotation and crypto-shredding also evict the entry once the commit
that replaces, retires, or deletes a key is durable, so retired key material is
wiped when the last operation holding it ends.

### Locked start and fail-closed

The store opens locked and fails closed. A missing root key, a root key with
loose permissions, or a key-check mismatch (the stored key-check value does not
match the value derived from the presented root key) aborts the open with no
partial write. The store has no degraded read-only or plaintext mode. A raw-disk
inspection test scans every file under the store directory for any fixture
plaintext, URL, tenant string, or plain content digest and asserts zero hits, so
the encryption claim is tested against the bytes, not asserted.

## Schema versioning, upgrade, and rollback

The store records its schema version in `meta` and checks it before any write. A
version newer than the running binary understands is refused, never opened
optimistically. A version older than the binary is upgraded by an explicit
`migrate` command that takes a backup path, runs resumable per-step
transactions, and writes the new version with the migrated data; an interrupted
migration resumes from its last committed step. Version 1 is the first schema,
so no older store exists and this build has no `migrate` command: it refuses
an older version with a migration-required error, and `migrate` lands with the
first schema change. Rollback is restoring the backup;
the store never downgrades a version in place. The wire version and the schema
version are independent: a wire change does not force a schema migration, and a
schema migration does not change the wire.

## Rekey protocol

Rekey rotates keys without losing data and survives a crash mid-rotation.

- **Root rotation.** Rotating the root key moves the whole store scope to keys
  derived from the new root key and a fresh salt, in one transaction: every
  tenant data key (a retiring one included) and every stored set of addressing
  subkeys is rewrapped under the new key-encryption subkey, every store-sealed
  record is re-sealed under the new metadata subkey, and every record keyed
  under the store index subkey moves to its key under the new one. The same
  transaction writes the new active root key id, salt, and key check to `meta`,
  so a crash leaves exactly one of the two root keys able to open the store.
  The operation requires the current root key and refuses one that fails the
  key check. A ledger record does not name its owner, so ledgers are found
  from the grants, sessions, and tenants that can own one; a ledger or wrapped
  key with no owner fails the rotation rather than be lost. One transaction
  holds the whole store scope in memory, which Phase 01 volumes allow; the
  store scope carries identifiers and amounts, not acquired content. A batched
  root rotation, with readers that try two root keys and two index subkeys,
  lands if that scope outgrows one transaction.
- **Tenant data-key rotation.** A begin transaction draws the new data key,
  wraps it, makes it the tenant's active key, and writes a rekey record naming
  the tenant, the from-key id, the to-key id, the keyspace, a cursor, a done
  flag, and a total. From that commit on every writer seals the tenant's new
  records under the new key. Batch transactions walk the tenant-sealed
  keyspaces in a fixed order (`idem`, `artifacts`, `blobs`, `session_index`,
  `audit`), re-sealing in place, under the new key, each record of the tenant
  still sealed under the old one, a bounded number of records per batch, and
  advance the cursor in the same transaction. A record is recognised as the
  tenant's by its header naming the old key id and by opening under the old
  key; another tenant's record with the same key id fails authentication and
  is left alone. During rotation, readers accept records sealed under either
  the from-key id or the to-key id, so reads never fail mid-rotation. On
  restart, rotation resumes from the committed cursor. The final transaction
  deletes the old wrapped key and marks the record done; because every record
  under the old key was re-sealed by the walk and no writer seals under it
  after the begin commit, no record is left under a retired key. The rekey
  status operation reports progress from the record.
- **Scope for Phase 01.** The addressing subkeys (blob address and index) do
  not rotate in this phase, because rotating them would re-address every blob
  and re-key every tenant record; this is documented and deferred. Record keys
  and blob keys therefore stay where they are through a data-key rotation.

Crash recovery for rekey is the rekey rows of the failure-injection table: a
crash before or after any rekey commit resumes from the last committed state,
and the producer is not involved. Old wrapped keys and values sealed under a
rotated-out key stay in the database's files until the compaction described
under crypto-shredding rewrites them away; until then the old root key file
must stay in custody or be destroyed.

## Backup and restore

A backup is a directory copy of the stopped store. The root key is held in
separate custody from the store directory, so a stolen backup without the root
key yields only sealed bytes. Restore verifies the key-check value and the schema
version before the store accepts writes: a backup whose root key does not match,
or whose schema version the binary cannot open, is refused rather than opened.
The restore check also refuses a copy missing any keyspace. It opens the
database, which runs the database's own journal recovery, and writes no store
record.

A backup keeps what the store held when it was copied, sealed under the root
key of that moment. Two consequences follow. A backup taken before a root
rotation opens only with the old root key, so destroying that key file also
retires every such backup. A backup taken before a crypto-shred still holds
the shredded tenant's wrapped data key, and restoring it with its root key
brings the tenant's data back; a shred reaches backups only when those copies
are destroyed, or when the root key they were sealed under is rotated out and
destroyed.

## Crypto-shredding

A tenant's durable data is shredded by deleting that tenant's wrapped data key
and writing a tombstone. One transaction deletes every wrapped key of the
tenant (the active data key, a retiring one mid-rotation, and its addressing
subkeys) and its rekey record, and replaces its tenant record with a
tombstone. The tombstone keeps the id reserved: it cannot be registered again,
operations on it fail as shredded rather than as a missing tenant, reads of its
artifacts and sessions answer not found, and scans across tenant partitions,
such as a scoped audit read, skip it. A new call into a session the tenant
owned is refused as `NotFoundOrDenied`, because its session index entry would
be sealed under the deleted keys. A shred is refused while an invocation
of the tenant, or in a session it owns, is not terminal, because recovery
would need the tenant's keys to settle it. Once the wrapped data key is gone, every record sealed
under that tenant's derived subkeys is unrecoverable, because the plaintext data
key existed only wrapped. The global `audit_stub` records survive a shred: they
carry only an id, a capability, an outcome kind, and a time, no tenant content,
so the fact that calls happened remains auditable while the tenant's content is
irrecoverable.

After a shred, the holder of the root key can still read every store-sealed
record (see the sealing scope above): identifiers (tenant, grant, session,
invocation, artifact), amounts (reservations, settled debits, ledger totals,
ceilings), lineage (grant chains, parent grants, parent tenants, session forks,
artifact owners and sessions), states, and timestamps, plus the tenant's
verifying key and bound user ids. Nothing acquired stays readable: no envelope,
text view, source reference, provenance digest, blob address, or idempotency
binding. The per-tenant audit trail is gone with the key; only the global stubs
remain. The shred evicts the tenant from the tenant key cache.

Because fjall deletes by tombstone, the old wrapped-key bytes persist in journal
or table files until compaction removes them; a shred is complete only once the
store has compacted past the deletion. fjall's own major compaction is not
enough: it drops the deleted value from table files, but the value also sits in
the write-ahead journal, which fjall 3.1 seals and deletes only after it grows
past 64 MB, and no public call rotates it, so the bytes survive flush, major
compaction, and reopen. Compaction therefore rewrites the store: it copies
every live entry into a fresh database in a sibling staging directory, closes
both, swaps the two directories with one atomic exchange rename, and removes
the old one. The store path holds a complete store at every instant, and a
staging directory an interrupted compaction leaves is removed at the next open.
From closing the databases until the old directory is removed, compaction holds
the database lock file of both directories, so a process that opened either one
in the meantime fails the compaction instead of having its database renamed
away. A filesystem without the atomic exchange fails the compaction with a
distinct error, and nothing is swapped: two plain renames would leave an instant
with no store at the path, so there is no fallback.
The raw-disk inspection test asserts the shredded tenant's wrapped-key bytes,
retired data keys included, are present before compaction and absent after it.
Removal unlinks files and does not overwrite the blocks they used; erasure
below the filesystem is out of scope for Phase 01.

## Audit reads

A tenant's audit entries are sequenced globally and stored in that tenant's
partition. The store serves the two audit scopes of the contract across
partitions: `All` merges every partition in sequence order, and
`OwnAndOwnedSessions` returns the actor's own entries plus entries any tenant
wrote in a session the actor owns. An optional session narrows either scope,
and reads page by sequence. Which scope an actor's grant allows is decided by
the lifecycle before the store is asked. A released invocation's audit entry
carries its release reason beside the reply kind the contract's audit record
has room for.

Schema version 1 also stores two authority fields in each audit entry. The
designated grant is recorded on every entry written with it in hand: a
`Denied` refusal, an audit read, a grant issue, and a capture's terminal
entry. The applied audit scope is recorded on every `AuditQuery` read, so
each audit read records the grant and scope it used, as the contract's audit
partitions require. Both fields are tenant-sealed with the rest of the entry.

## Retrieval is a projection

Full-text and semantic retrieval over stored content are rebuildable projections
of the record of truth, not the record itself. The custody keyspaces above are
authoritative; a retrieval index is derived from them and can be dropped and
rebuilt from the sealed records without any loss of the record of truth. This
keeps the encryption and custody guarantees on the authoritative store and out
of the index, and it lets the retrieval layer change tier under the fjall
storage decision (D17.14) without touching the record of truth.
