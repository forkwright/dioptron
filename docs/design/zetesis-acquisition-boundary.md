# Zetesis static acquisition boundary

Dioptron presents static acquisition through its tenant capability surface, but
it does not own the consumer-neutral acquisition mechanism. This boundary
covers anonymous static GET acquisition and the evidence handoff into
Dioptron. Sessionful browsing, rendered pages, scripts, and browser actions
remain Dioptron behavior.

This is a design contract. It does not add a dependency, define adapter code,
or satisfy the implementation and compatibility conditions in
[dioptron#66](https://github.com/forkwright/dioptron/issues/66).

## Ownership

Dioptron owns the invocation and product context:

- authorization under the acting tenant, session, grant, and delegation chain
- budget reservations and credential scope or lease context
- capture lifecycle, storage, query, replay, and knowledge ingestion
- rendered and scripted browsing plus browser actions
- attribution and the immutable audit record

Zetesis owns the consumer-neutral static acquisition state machine:

- an immutable target after validation
- proof for target validation and every redirect hop
- bounded HTTP transfer and decompression
- static document extraction
- the evidence fingerprint and versioned evidence envelope

Zetesis does not interpret Dioptron tenants, grants, sessions, or storage tiers.
Dioptron does not reproduce the acquisition rules inside its adapter.

## Adapter protocol

The Dioptron adapter follows one ordered protocol:

1. Plan the invocation and authorize it against the Dioptron tenant, session,
   grant, budget, and credential context.
2. In one Dioptron transaction, reserve the approved authority and persist the
   invocation intent. The external call cannot begin before that transaction
   commits.
3. Invoke the acquirer from the exact pinned Zetesis revision. Pass the target
   and acquisition limits without replacing Zetesis validation or policy.
4. Store the returned Zetesis evidence envelope verbatim as the acquisition
   payload. Attach Dioptron invocation, tenant, session, grant, budget, and
   credential-context references beside that payload rather than rewriting it.
5. Settle the reservation from the recorded outcome. Release it when no charge
   or authority consumption occurred, and audit either result.

Derived Dioptron indexes may reference the envelope. They cannot replace its
bytes, schema identity, producer revision, or fingerprint as acquisition
evidence.

## Adapter exclusion

The adapter contains no fallback or second implementation for:

- raw HTTP transfer or decompression
- target, redirect, DNS, or SSRF validation
- static document extraction
- acquisition fingerprints or evidence-envelope construction

An unsupported or incompatible Zetesis result is an adapter failure. It is not
permission to route through a Dioptron-local static fetch stack.

## Budget boundary

Anonymous static GET does not use a paid search or research provider. Its
adapter can therefore precede the paid-provider ledger correction tracked in
[zetesis#47](https://github.com/forkwright/zetesis/issues/47). Dioptron still
reserves its own invocation resources and records the authority used.

A paid-provider route remains subject to the identity-bound, atomic provider
budget contract in zetesis#47. The anonymous route does not weaken or bypass
that contract.

## Dependency and compatibility gate

Dioptron can add the dependency and adapter only when all of these facts exist:

- the producer revision is a merged, immutable Zetesis commit SHA
- Kanon registers or derives that exact SHA for the Dioptron dependency
- a real consumer compatibility test binds the Zetesis SHA to the Dioptron
  revision
- boundary tests cover unsafe targets, redirect chains, cancellation and
  budgets, extraction identity, Dioptron attribution, and reservation
  settlement or release
- dependency-graph validation proves that the repositories do not form a cycle

Until those gates pass, issue dioptron#66 remains an implementation tracker.
This design record is not evidence that its Done-when conditions are complete.
