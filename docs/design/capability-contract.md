# Capability contract

Contract version: 1.

This document freezes the capability and wire contract for the Dioptron
capability surface at Phase 01. It is the agreement that every tenant and every
consumer speaks before it acts: the capability vocabulary, the grant and budget
rules, the invocation lifecycle, the outcome taxonomy, and the wire protocol.
The contract crate (proposed `syntheke`, `docs/lexicon.md`) is the only
executable form of this document; where the two disagree, this document states
the intent and the crate is corrected to match.

The contract is versioned as a whole. Version 1 is the surface described here.
A later version may add capabilities, outcome kinds, or budget dimensions
without renumbering, because the additive types below are marked non-exhaustive;
a change that removes or reinterprets an existing field increments the contract
version and the wire version together.

## Scope and non-goals

In scope: how a tenant authenticates, what capabilities exist, how grants
attenuate and expire, how budgets are reserved and settled, how an invocation
progresses through durable states and recovers from a crash, what outcomes and
errors a caller can observe, and how bytes cross the local socket.

Out of scope, owned elsewhere:

- **Static acquisition.** Consumer-neutral anonymous static GET acquisition is
  owned by Zetesis, per `docs/design/zetesis-acquisition-boundary.md`. Dioptron
  owns the invocation, authorization, custody, and audit around it; it does not
  own the fetch, redirect validation, decompression, or static extraction, and
  it adds no second fetch stack. The daemon reaches acquisition through a
  producer seam (below); the only Phase 01 producer is a fixture producer.
- **Rendered and scripted browsing** (D3, D4) and knowledge classification
  (D7 ingest) are separate surfaces. This contract carries their captures as
  opaque artifacts with provenance; it does not define their internals.
- **Rules evaluation** (D8) authors grants and reads facts. This contract
  consumes grant and budget state; it does not define the rule language.

The contract holds one invariant across every scope boundary: there is exactly
one fetch stack, and it is Zetesis behind the producer seam. An unsupported or
incompatible producer result is a producer failure, never permission to fetch
locally.

## Tenants and identity binding

A tenant is one of three classes (`docs/design/tenancy.md`): operator, agent,
sub-agent. The classes share one capability surface; they differ only in the
grants they hold. Each tenant has a stable identifier, an Ed25519 verifying key,
a set of bound local user ids, and an optional parent tenant.

Identity is bound to the connection, not carried in each request. At accept the
server reads the peer credential of the local socket and learns the connecting
user id. The tenant then proves the private half of its registered key over a
challenge that includes both sides' nonces (see the wire protocol). The server
admits the connection only when the signature verifies against the registered
key and the peer user id is in that tenant's bound set. After the handshake,
every request on that connection is attributed to that tenant by the connection
alone; requests carry no tenant field to forge. Authority is named, never
inferred: each request designates the one grant it acts under (see grant
designation below). Every persisted invocation and
audit record names the acting tenant, satisfying the attribution requirement
R2.4.

## Capabilities and mode

A capability is a verb the surface offers. The capability set is non-exhaustive;
version 1 defines:

| Capability | Meaning |
|---|---|
| `SessionCreate` | Open a new session owned by the acting tenant. |
| `SessionFork` | Branch an existing readable session into a new lineage with provenance (R4.10). |
| `Capture` | Acquire a target through the producer seam and store it as an immutable artifact with provenance (R4.4). |
| `Ingest` | Submit a stored artifact into the knowledge pipeline (D7). |
| `Read` | Read a stored artifact or record the tenant is authorized to see. |
| `Query` | Query indexed or knowledge state within the tenant's read scope. |
| `GrantIssue` | Issue a child grant that attenuates one the tenant holds. |
| `GrantRevoke` | Revoke a grant the tenant issued, and its descendants. |
| `AuditQuery` | Read audit records within the tenant's audit scope. |

Every request also carries a mode: `Execute` or `DryRun`. Dry-run answers the
capability-discovery and cost questions R9.2 asks, returning the facts, the cost
estimate, and the grant and rule chain that a real call would use, and it writes
nothing durable, including no audit record. A dry-run invocation ends in the
in-memory `Planned` state and never advances to a persisted state (D17.16). Its
only product is the returned plan; two identical dry-runs leave the store byte
for byte unchanged and call the producer zero times.

## Grants

A grant is a standing permission held by a tenant. It names its issuer and
holder, the capability set it confers, the session scope it applies to (the
holder's own sessions, or an explicit set), the target scope (origin patterns
for `Capture`), per-dimension budget ceilings, a validity window
(`not_before`, `expires_at`), and, when it is a child grant, its parent grant,
its depth, and the maximum depth the chain permits.

### Grant designation

Every capability request, in `Execute` and `DryRun` mode alike, carries a
`grant` field naming the one grant it acts under. The daemon authorizes the
request against that grant and its chain only. It never searches the tenant's
other grants for one that would allow the call, so a request holds no authority
its caller did not name, and a tenant holding several grants cannot be steered
into acting under one it did not choose. Identity stays bound to the
connection; the `grant` field names authority, not identity.

The designated grant must be held by the connection's tenant. A designated
grant that does not exist and a grant held by another tenant return the
identical `NotFoundOrDenied` response, so a request cannot probe for another
tenant's grant. A designated grant the tenant holds that cannot authorize the
call returns the `Denied` code the check reaches: `CapabilityNotGranted`,
`ScopeViolation`, `GrantNotYetValid`, `GrantExpired`, or `GrantRevoked`. A
dry-run reports the same refusal in its plan, and a plan's grant chain starts at
the designated grant.

### Delegation attenuation

A child grant is valid only if it attenuates its parent on every axis at once:

- its capability set is a subset of the parent's;
- its session and target scopes are subsets of the parent's;
- each budget ceiling is at most the parent's remaining ceiling on that
  dimension at issue time;
- its `expires_at` is at or before the parent's;
- its depth is less than the chain's maximum depth;
- the parent is the grant the issuing request designates, and it confers
  `GrantIssue`.

A `GrantIssue` request names its parent only through its designated grant; its
body carries no second parent field that could disagree with it.

A child can never be broader than its parent on any axis. The contract defines
no widening operation.

### Expiry and validity

A grant is usable at a moment only if the whole chain from that grant to its
root is usable at that moment: every link satisfies `not_before <= now` and
`now < expires_at`, and no link appears in the revocation set. Validity is
re-checked at dispatch and again at settlement, using an injected clock so the
check is deterministic in tests. A grant that expires mid-invocation is handled
by the revocation and lifecycle rules below, not by a separate path.

### Revocation epochs

Revocation is recorded, not erased. A revocation record names the revoked grant,
the audit sequence at which it took effect, and the wall time of the effect.
Revoking a grant invalidates that grant and every descendant with no fan-out
write: chain-walk validity fails at the first revoked link, so a parent's
revocation invalidates its whole subtree the next time any descendant is
checked. The sequence on the revocation record is the revocation epoch: a call
authorized before the epoch and a call authorized after it are distinguishable
in audit by comparing sequences, without mutating any descendant grant.

### Read scopes

`Read`, `Query`, and `AuditQuery` are bounded by scope, not only by capability.
Read and query see artifacts and records within the tenant's granted session
scope. Audit scope is either all records (the operator's default) or the
tenant's own records plus records from sessions it owns; this encodes the
audit-partition access decision (D17.7) as a default grant rather than a second
mechanism. A grant confers read on what it names and nothing adjacent; a
capability without a matching scope reads nothing.

## Budgets

Budget is accounted per dimension, and each dimension is a separate ceiling. A
ceiling on one dimension never substitutes for another. The dimensions are
non-exhaustive; version 1 defines wall-time milliseconds, fetch count, bytes
transferred, and output bytes, with reserved room for token count and an
operations-band dimension. This satisfies the cost-accounting requirement R9.4:
every invocation declares cost across time, fetches, and bytes, the token and
operations-band dimensions are reserved for the verbs that spend them, and a
tenant can read remaining budget at any time.

### Reservation and settlement

Budget moves in two steps, each a single store transaction.

1. **Reserve.** Before dispatch, the invocation debits its declared maximum on
   every dimension against every ledger in the grant chain, plus the session
   ledger and the tenant ledger, in one transaction. If any ledger cannot cover
   the declared maximum, the reservation fails and nothing is debited. A
   successful reservation is durable before the producer is contacted.
2. **Settle.** After the outcome is known, the invocation debits the actual
   consumption, which is at most the reserved maximum, and releases the
   remainder back to every ledger in one transaction. A call that consumed
   nothing releases the whole reservation.

Reservation before dispatch is what makes budget enforcement honest under crash:
the authority is spent before the effect, so a crash can only leave budget
over-reserved, never over-spent. Settlement reconciles the estimate to the fact.

## Invocation lifecycle

An invocation is the unit of one capability call. It moves through in-memory and
durable states. Each durable transition B1 through B5 is exactly one store
transaction, and the store checks the current state inside that transaction, so
settlement or release runs exactly once even across a retry (D17.16).

| State | Kind | What is true | Recovery action after a crash in this state |
|---|---|---|---|
| `Planned` | memory | Authorized, cost computed. Dry-run ends here. Nothing durable, including no audit. | Nothing persisted; nothing to recover. Caller re-issues. |
| `Denied` | durable, terminal | Authorization of an `Execute` request failed; an audit record is the only write. A dry-run that would be denied reports the denial in its plan and writes nothing. | Terminal. No effect, no reservation held. |
| B1 `IntentPersisted` | durable | Reservation, invocation intent, and idempotency index committed in one transaction. Producer not yet contacted. | Release the reservation as `Released(Abandoned)`. The producer was never called. |
| B2 `Dispatched` | durable | Dispatch recorded before the producer call, so the call is known to have possibly started. | Settle conservatively at the reserved fetch count as `UnknownEffect`; never re-dispatch. The effect may or may not have happened; the contract refuses to repeat a possibly-live external action. |
| B3 `TransferComplete` | durable | The producer returned; the blob is written but not yet visible. | Roll forward: publish, then settle. The bytes exist; completing publish is safe and idempotent. |
| B4 `Published` | durable | Atomic publish point: the artifact record, session index, and state committed in one transaction. The capture is now visible. | Roll forward: settle. The effect is durable and visible; only reconciliation remains. |
| B5 `Settled{outcome}` / `Released{reason}` / `UnknownEffect` | durable, terminal | Actual budget settled and remainder released, the whole reservation released with a reason, or the reserved cost charged because the effect cannot be proven. | Terminal. |

`Settled{outcome}` carries the reply kind the caller observed (`Success`,
`TransferFailed`, `ExtractionFailed`, and so on). Version 1 `Released` reasons,
non-exhaustive: `Abandoned` (restart recovery at B1), `Revoked` (revocation
before any effect), `Cancelled` and `DeadlineExceeded` (the producer reports it
had not started), and `ProducerUnavailable` (the producer reports it was never
contacted).

The atomic publish point is B4: before it, a partial capture is invisible and
recoverable to a released or unknown-effect terminal; at it, the capture becomes
visible and its budget is reconciled. No state lets a caller observe a
half-written capture.

`UnknownEffect` is a first-class terminal, not an error swallowed silently. It
records that an external action may have taken effect, at most once, and the
runtime cannot prove whether it did, and it charges the reserved cost rather than
under-charging. A caller that needs to retry after `UnknownEffect` must issue a
new idempotency key; the same key replays the `UnknownEffect` outcome and never
re-dispatches.

## Idempotency

Every state-changing request carries a caller-supplied idempotency key of 16 to
64 bytes. The store holds an idempotency index keyed by a keyed hash over the
tenant, the capability, and the key, mapping to the invocation id and a digest
of the request. The digest covers the designated grant, so the same key sent
under a different grant is an `IdempotencyConflict`.

- Same key, same request digest: the current or terminal outcome of the
  existing invocation is returned. If it is still running, the caller observes
  `InProgress`. The call is never dispatched twice.
- Same key, different request digest: `IdempotencyConflict`. The key is already
  bound to a different request and the contract refuses to reuse it.
- A replay of an invocation that ended in `UnknownEffect` returns
  `UnknownEffect`; retrying requires a new key.

Idempotency is asserted at B1: the index entry is written in the same
transaction as the reservation and the intent, so two concurrent calls with the
same key cannot both reserve.

## Revocation of queued and running calls

Revocation interacts with the lifecycle by state, following the killable default
of R2.7 while respecting the drain-only exception:

- A call still at B1 (`IntentPersisted`, not yet dispatched) is released as
  `Released(Revoked)`. No external effect occurred.
- A call at B2 (`Dispatched`) receives a cancel signal that propagates to the
  producer. If the producer reports it had not started, the reservation is
  released. Otherwise the call settles the actual cost and publishes with a
  `revoked_after_effect` marker, because the external action already happened
  and the honest record is that it happened. Reading the resulting artifact
  still requires a live grant; the audit record notes the effect regardless.
- A completed call is not un-done; its audit record stands.
- A verb that the rules mark drain-only (R2.7) is not cancelled; it runs to
  completion and settles normally, and reading its artifact still requires a
  live grant.

Revocation never fabricates a clean state. A call whose effect has left the
runtime is recorded as having left, even when the authorizing grant is gone.

## Outcome and error taxonomy

Outcomes are separated so a caller can tell one failure class from another, and
so no class leaks information across a tenant boundary. A reply that is not a
failure is one of three kinds: `Success` (the capability's result fields),
`Plan` (the dry-run result: facts, cost, and grant and rule chain), and
`InProgress` (an idempotent replay of an invocation that has not reached a
terminal state). The failure outcome kinds are non-exhaustive; version 1
defines:

| Kind | Class | Meaning |
|---|---|---|
| `ProtocolError` | protocol | The frame or sequence violated the wire contract. |
| `AuthFailed` | protocol | The handshake did not establish an admitted identity. One kind for every cause. |
| `Denied{code}` | denial | Authorization failed for a stated policy reason on a resource the caller may know exists. |
| `NotFoundOrDenied` | denial | The resource is missing, or it exists but the caller may not see it. One response, byte-identical for both. |
| `BudgetExceeded{dimension}` | denial | A ceiling on one of the caller's own ledgers was reached. Reported only for the caller's own ledgers. |
| `ProducerUnavailable` | unavailable producer | The producer could not be contacted. |
| `TransferFailed{class}` | failed transfer | The producer began but the transfer failed, with a coarse class. |
| `ExtractionFailed{class}` | failed extraction | The transfer completed but extraction failed, with a coarse class. |
| `DeadlineExceeded` | availability | The deadline elapsed before completion. |
| `Cancelled` | availability | The call was cancelled. |
| `UnknownEffect` | availability | An effect may have occurred, at most once, and cannot be proven either way. |
| `IdempotencyConflict` | protocol | The idempotency key is bound to a different request. |

The five classes the contract keeps distinct are protocol errors, denials,
unavailable producer, failed transfer, and failed extraction. Protocol errors
are the caller's frame; denials are authorization; the last three separate a
producer that could not be reached from one that reached the origin but failed
to transfer, and both from a transfer that succeeded but could not be extracted.
A caller can act differently on each: retry, re-authorize, or report.

Version 1 `Denied` codes, non-exhaustive: `CapabilityNotGranted`,
`ScopeViolation` (a target outside the grant's target scope),
`GrantNotYetValid`, `GrantExpired`, `GrantRevoked` (the grant or any link in its
chain), and `NarrowingViolation` (a child grant that does not attenuate its
parent). Transfer and extraction classes are coarse and non-exhaustive, for
example `Reset` or `Timeout` for a transfer and `Malformed` or `Unsupported` for
extraction; a class never carries origin content or a URL.

### The non-leak rule

A missing resource and a resource the caller may not see return the identical
`NotFoundOrDenied` response, with identical bytes, so a foreign tenant cannot
use the reply to probe for the existence of another tenant's artifacts,
sessions, or records. Both cases are answered through the same code path; the
contract promises byte-identical replies, not constant-time handling, and makes
no timing claim beyond that. `Denied{code}` is used only where the caller is
already entitled to know the resource exists. The rule covers grants too: a
designated grant that does not exist and a grant held by another tenant return
the identical `NotFoundOrDenied`. `BudgetExceeded` names a dimension only on
the caller's own ledgers, never a parent's or another tenant's. No outcome ever
echoes a target, artifact reference, or URL the caller did not itself supply.

## Source envelope reference

A capture stores the producer's output verbatim. The stored evidence is the
producer's bytes exactly as returned, together with the evidence's schema
identity, the producer revision that produced it, and the acquisition
fingerprint. These four are the acquisition evidence, per
`docs/design/zetesis-acquisition-boundary.md`; a derived Dioptron index may
reference them but never replaces them.

The adapter attaches Dioptron's references beside the envelope rather than
rewriting it: the invocation id, acting tenant, session, grant chain,
reservation, classification, lineage, and a provenance digest live in a side
record that points at the envelope's stored bytes. Reading a capture returns the
verbatim envelope; the side record answers who acquired it, under what
authority, and where it sits in the knowledge lineage.

## Query and read results

`Read` returns stored bytes in bounded chunks by offset and length, so a large
artifact does not force a single oversized frame. `Query` returns records within
the caller's read scope only. Both are shaped by scope before capability: a
result set never includes a record outside the caller's session or audit scope,
and a query that would match a foreign record returns as if that record did not
exist, consistent with the non-leak rule. Read of an artifact produced under a
grant that has since been revoked still requires a live grant to read, even
though the acquisition audit record stands.

## Audit partitions

Audit is read through the `AuditQuery` capability, the `audit.query`
capability of the audit-partition access decision (D17.7). It sits on the common
surface and is scoped by grant like any other verb; no tenant class has a
separate audit path. The default grants encode D17.7: the operator's default
audit scope is `All`, and an agent's or sub-agent's is `OwnAndOwnedSessions`
(its own records plus records from sessions it owns). The rule evaluator's view
type carries no audit access, so a rule cannot read audit during evaluation.
Every audit read is itself audited, recording the grant and scope used. Any
system-only audit authority would be an explicit non-delegable capability, never
a tenant-class exception; version 1 defines none.

Every `Execute` invocation that reaches a durable state, including each
`AuditQuery` read and each `Denied` refusal, writes its audit record in the same
transaction that commits its terminal state. A dry-run writes none.

## Wire protocol

The wire protocol carries the contract over a local unix stream. It is the
canonical programmatic interface of the tenancy plane (D12); the desktop UI and
every agent are clients of it with no privileged path.

### Framing

Every message is a frame with a 12-byte header: a 4-byte magic (`DPT1`), a
1-byte kind, a 1-byte flags field, a 2-byte reserved field that must be zero, and
a 4-byte little-endian length. Unknown flag bits are rejected. The length is
checked against the current bound before any buffer is allocated, and the body is
read into an aligned buffer. Zero-copy access applies only after the archive
validator has accepted the whole body; it never replaces validation. Wire types
are non-recursive, so validation cannot be driven into unbounded depth.

Version 1 defines eight frame kinds; any other kind byte is rejected.

| Kind byte | Frame | Direction | Body |
|---|---|---|---|
| 1 | `ClientHello` | client to server | Supported version range, tenant identifier, client nonce. |
| 2 | `ServerHello` | server to client | Chosen version or `Incompatible`, server nonce, negotiated maximum body. |
| 3 | `Auth` | client to server | Ed25519 signature over the authentication transcript. |
| 4 | `Admitted` | server to client | No fields. The handshake succeeded; requests may follow. |
| 5 | `Request` | client to server | One capability request (see request fields). |
| 6 | `Cancel` | client to server | The request id to cancel. |
| 7 | `Response` | server to client | The request id, the invocation id when the call persisted one, and the reply. |
| 8 | `Fault` | server to client | `ProtocolError` or `AuthFailed` only, sent once before the server closes. |

A failure that answers one request travels in a `Response`; `Fault` carries
only the two connection-level kinds, and a receiver rejects a `Fault` carrying
any other.

### Bounds

Until the server sends `Admitted`, every frame body in either direction is
capped at 4 KiB, including `Auth`, `Admitted`, and a handshake `Fault`. After
`Admitted`, both directions use the negotiated maximum, which is at most 1 MiB
by default and never exceeds a hard ceiling of 4 MiB. A partial header or body
times out. A handshake must complete within 5 seconds. A global connection
semaphore bounds concurrent connections, and each connection bounds its in-flight
requests. A frame that violates any bound yields a single `ProtocolError` frame
where possible, and then the connection closes.

### Handshake and version negotiation

The server reads the peer credential at accept. The client sends a hello naming
its supported version range, its tenant identifier, and a client nonce. The
server replies with either a chosen version or the `Incompatible` marker, its own
nonce, and the negotiated maximum frame size. The chosen version is the highest
version inside both ranges, so it always lies inside the range the client
offered, and a client treats a chosen version outside that range as a protocol
error. An `Incompatible` reply still carries a valid maximum frame size, between
4 KiB and 4 MiB. The client then sends an auth
frame carrying an Ed25519 signature over a fixed label, the chosen version, the
tenant identifier, and both nonces. The server admits the connection only when
the signature verifies against the tenant's registered key and the peer user id
is in the tenant's bound set, and answers an admitted connection with
`Admitted`.

The signed transcript is 66 bytes of fixed-width fields concatenated in this
order with no separators: the 16-byte ASCII label `dioptron-auth-v1`, the chosen
version as a 2-byte little-endian integer, the 16-byte tenant identifier, the
16-byte client nonce, and the 16-byte server nonce. Every field has a fixed
width, so two different inputs never produce the same transcript.

An incompatible version range ends the handshake before authentication. Every
authentication failure returns the identical `AuthFailed`: a wrong key, a
replayed signature, a peer user id one off from the bound set, a request frame
sent before authentication, and an unknown tenant are indistinguishable to the
client.

### Peer identity binding

After the handshake, identity comes from the connection alone. Requests carry no
tenant field, so there is nothing to forge; a request acts as the connection's
admitted tenant, under the grant it designates, which that tenant must hold.
This is the same binding described under tenants and identity, enforced at the
wire.

### Request fields and units

A `Request` frame carries a caller-chosen request id, unique among the
connection's in-flight requests; the designated `grant`; an idempotency key,
required on an executed state-changing request (`SessionCreate`,
`SessionFork`, `Capture`, `Ingest`, `GrantIssue`, `GrantRevoke`); the mode; a
relative deadline; and the capability body.

Identifiers travel as their 16 raw bytes and display as 26-character ULIDs.
Wall-clock times on the wire (grant validity bounds, revocation effect times,
audit record times) are signed 64-bit milliseconds since the Unix epoch, UTC.
Durations (the request deadline, the wall-time budget dimension) are unsigned
milliseconds.

### Cancellation and deadline

A request carries a deadline in milliseconds, clamped to a bound and converted
to the server's monotonic clock on receipt, so a client cannot set an unbounded
or backward deadline. A `Cancel` frame naming a request id signals cancellation,
which propagates to the producer through the cancel signal in the producer seam.
Deadline expiry and cancellation map to the `DeadlineExceeded` and `Cancelled`
outcomes, and interact with the lifecycle exactly as revocation does at B2.

### Validation before access and fail-closed

A received body is validated with the archive validator before any field is
read; a body that fails validation is a `ProtocolError` and is never accessed as
a typed value. A body is accepted only if it is the canonical encoding of the
decoded value, meaning re-encoding that value reproduces the received body byte
for byte, so trailing, leading, or unreferenced bytes are a `ProtocolError`.
Every ambiguous condition fails closed: an unknown flag, an over-bound length, a
validation failure, a non-canonical body, a pre-auth request, or a missing key
ends in refusal and, where the connection is still coherent, a single error
frame before close. The protocol never proceeds on a frame it could not fully
validate.

## First consumer mapping

The first consumer is a web-fetch tool exposed to an agent. It takes a required
`url` and an optional maximum output length in characters, and it carries caller
context: an agent identifier, a session identifier, a turn identifier, and a
tool-call identifier. This contract maps that tool onto `Capture`: the tool's
url becomes the capture target, its maximum length becomes the output-bytes
limit, and its tool-call identifier derives the idempotency key so a retried
tool call replays rather than re-fetches. The reply carries the artifact
reference, the source reference (fingerprint, schema identity, producer
revision), the extracted text view, and an explicit truncation flag.

The first consumer today has two gaps this contract closes:

- **Silent truncation.** The consumer truncates output with a suffix and no
  signal that truncation happened, so a caller cannot tell a short page from a
  cut one. The contract makes truncation explicit: the capture reply carries a
  truncation flag, and the output-bytes budget dimension is a stated ceiling
  rather than an accident of a downstream cap.
- **No cancellation token.** The consumer can only abandon a fetch by dropping
  the future, leaving the external effect and its cost unaccounted. The contract
  gives cancellation a `Cancel` frame and a cancel signal that reaches the
  producer, and settles the cost of a cancelled call through the lifecycle, so a
  cancelled fetch is recorded and charged, not lost.

The consumer's other needs, extracted text with stable source and capture
references, a preserved caller egress policy passed through to the producer,
output bounds, a deadline, and distinct outcome kinds, are the fields named
above. The mapping is described generically here; no consumer-internal path is
part of this contract.

## Dependency graph

The Phase 01 crates form a directed acyclic graph with no consumer cycle. The
contract crate is the root and depends on no fleet crate; the authorization
crate depends on the contract; the custody crate depends on both; the daemon
depends on all three; the independent client depends only on the contract and is
a development dependency of the daemon for process-level tests.

```
syntheke <- epitrope <- phylake <- dioptron
xenos -> syntheke        (dioptron dev-dep: xenos)
```

Only crate consumers link the contract crate. The future Zetesis
static-acquisition adapter is a separate crate that does not exist yet and lands
only behind the dioptron#66 dependency-and-compatibility gate in
`docs/design/zetesis-acquisition-boundary.md`; it introduces no cycle because it
sits behind the producer seam, which the daemon owns. No crate in this graph
carries a fetch, redirect, DNS, or extraction implementation; that code is
Zetesis's alone.

## Fixture schema

The request and response fixtures under `docs/contract/fixtures/*.toml` are the
machine-checkable statement of this contract. The contract crate's tests read
every file in that directory, so the schema is regular: one scenario per file,
each file self-describing.

Every fixture file has three tables:

- `[meta]` with `name` (the scenario name, equal to the file stem), `kind`
  (`"positive"` or `"negative"`; negative files are prefixed `neg_`), and
  `clause` (the acceptance clause this scenario proves, quoted from this
  document).
- `[request]` describing the inbound call and the state the scenario starts
  from. Synthetic data only: `example.com` targets, `192.0.2.0/24` addresses,
  and fixed lowercase ULIDs.
- `[expected]` describing what the contract requires: the reply kind and its
  fields, plus observations a test makes of the store, the producer, and the
  socket.

### Fixture keys

Keys fall into four roles. A key in `[request]` is either a wire field or
scenario setup; a key in `[expected]` is either a reply field or an
observation.

- **Wire fields** carried by the request or handshake frame: `capability`,
  `mode`, `grant` (the grant the request designates; in a `GrantIssue`, the
  parent), `idempotency_key` (hex-encoded bytes), `session` (the session the
  request acts in), `target`, `max_output_bytes`, `max_transfer_bytes`,
  `artifact_ref`, `offset`, `len`, `predicate`, `session_scope`,
  `parent_session`, `holder`, `capabilities`, `target_scope`,
  `ceiling_<dimension>` (for example `ceiling_fetches`,
  `ceiling_bytes_transferred`), `expires_at`, `target_grant` (the grant a
  `GrantRevoke` names), `audit_scope`; for handshake frames `frame`,
  `version_min`, `version_max`, `client_nonce`, `signature`, and `tenant` (the
  tenant identifier in a `ClientHello`).
- **Scenario setup**, which the test arranges and the wire never carries:
  `tenant` in a capability request (the tenant the connection authenticated as;
  requests carry no tenant field), `clock_now`, `grant_expires_at`,
  `parent_grant` (the designated grant's parent in its chain),
  `parent_capabilities`,
  `parent_revoked_at_sequence`, `prior_request_digest`, `producer_fault`,
  `peer_uid`, `bound_uids`, `cause` (one of `wrong_key`, `replayed_signature`,
  `uid_not_bound`, `pre_auth_request`, `unknown_tenant`), `declared_len`,
  `pre_auth`, and `negotiated_max`.
- **Reply fields**: `outcome` (a reply kind or outcome kind from the taxonomy,
  or `Incompatible` from the handshake), `code`, `class`, `axis`,
  `artifact_ref`, `source_fingerprint`, `source_schema_id`, `producer_revision`,
  `text_view`, `truncated`, `output_bytes`, `session`, `owner`,
  `parent_session`, `grant`, `parent_grant`, `revoked_grant`,
  `effect_sequence`, `offset`, `len`, `result_refs`, `scope_applied`,
  `plan_cost_fetches`, and `plan_grant_chain`.
- **Observations** a test checks outside the reply: `final_state` and
  `released_reason` (the invocation's durable terminal state), `producer_calls`,
  `durable_writes`, `dispatched`, `narrowed`, `descendants_invalidated`,
  `failing_link` (the first revoked link the chain walk reached),
  `indistinguishable` (the reply bytes equal the reply for the paired case),
  `echoes_ref`, `authenticated`, `allocated`, `connection`,
  `envelope_verbatim`, `scoped_to_caller`, `records_outside_scope`, and
  `read_audited`.

Fixtures share one synthetic cast so the scenarios agree with each other. The
operator (id ending `tnt0a`) holds root grant `grn0a`. Agent `tnt0b` holds
`grn0b`, a child of `grn0a`, and owns session `ses0a`. Sub-agent `tnt0c` holds
`grn0c`, a child of `grn0b` issued by `tnt0b`. Tenant `tnt0f` holds `grn0f`,
which names none of `tnt0b`'s sessions.

A positive fixture asserts a successful path (a capture, a truncated capture, a
read, a query, an audit query, a session create or fork, a valid narrowing
grant, a revoke, or a dry-run). A negative fixture asserts a refusal with a
specific outcome kind (an incompatible version, an oversized frame, a
cross-tenant read, a foreign designated grant, an expired grant, a narrowing
violation, a revoked parent, an idempotency conflict, an unavailable producer,
a failed transfer, a failed extraction, or a forged identity). A test that finds
a declared fixture missing fails loudly rather than skipping.
