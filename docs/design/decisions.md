# Resolved Technical Decisions

## D17.1 Operations band sandboxing
Each verb runs in a dedicated process under landlock+seccomp with a verb-specific profile. Exploit-runner gets a dedicated network namespace with controlled egress through dioptron-net. MITM verb gets raw socket access scoped to operator-declared target interfaces only, rules engine evaluating every bind. Credential-test verb receives material as ephemeral handles from credential vault, never cleartext crossing process boundaries; handles auto-revoke on completion or revocation.

## D17.2 Knowledge tier read defaults
Default nous query posture: tier 1 first, tier 2 if insufficient confidence, tier 3 only on explicit request. Contradiction detection across tiers 1 and 2 by default; tier 3 cross-checking opt-in (raw captures produce contradiction floods). Source reputation weighted by tier.

## D17.3 Identity layer distribution sourcing
Initial corpus from public fingerprint datasets (Mozilla, EFF Panopticlick, academic crawls). Refresh via akroasis passive observation when integrated. Distributions versioned and auditable. Unknown fingerprint properties: rules engine surfaces request, falls back to synthesized plausible value with audit flag.

Anonymity-set floor (R5.2/D17.13) is recomputed against this corpus at every refresh, not set independently — see `docs/design/fingerprint-unlinkability.md`.

## D17.4 Pure-Rust rendering lock
Dioptron does not use Chromium, headless browsers, or C++ rendering fallbacks. Native Rust rendering through the D3 render band is the only supported render path. Origins that fail to render are tracked as native-rendering coverage gaps and native parity work, not fallback candidates.

## D17.5 Standing query economics
Standing queries declare fetch budget and schedule. Rules engine and cost accounting enforce both. Fetches jittered across plausible browsing patterns. Akroasis posture gates when integrated. Warning when pattern crosses fingerprinting threshold.

## D17.6 Plegma session sync
Sessions sync across plegma peers in operator's device set. CRDT conflict resolution: both forks persist on rejoin, operator chooses merge or separate. Forking-while-synced creates new lineage with provenance.

## D17.7 Audit partition access
Audit partition read-restricted: operator has full read via desktop UI. Agents/sub-agents read only their own facts or facts from owned sessions. Rules cannot read audit during evaluation (prevents side channel). Audit reads through explicit operator-initiated query path.

## D17.8 Update mechanism
Engine band: slow cadence, reproducible builds, operator-initiated. Operations band: faster cadence (CT rules, fingerprint distributions, tracker rulesets, verb patches), same signing infrastructure, applied without engine restart. Rollback per-band and atomic.

## D17.9 Rendering completeness floor
v1: renders operator's top-1000 most-visited origins without operator-visible breakage. Measurable, testable, operator-specific.

Measurement contract: `docs/design/rendering-completeness.md`.

## D17.10 Capability grant ceremony
Grants authored as rules. First-contact requests surface as notification with pre-drafted rule. Desktop UI has dedicated grants surface. No modal prompts.

## D17.11 Credential vault interim
Proton Pass bridge is interim (acknowledged sovereignty leak). Clean-room vault prioritized. Until then: audit logging on every access, per-origin grant requirement.

## D17.12 Multi-operator scope
Single-operator. Family members get own instances. Peer-tenant model is for human + agents, not multiple humans.

## D17.13 Fingerprint unlinkability floor
v1: cross-session joint fingerprint (egress, DNS, TLS, HTTP, JavaScript surface, fonts, locale, clock, storage) for a stated web-origin adversary sits in a measured anonymity set no smaller than the current floor, recomputed against the D17.3 distribution corpus at every refresh. Measurable, testable, adversary-scoped.

Measurement contract: `docs/design/fingerprint-unlinkability.md`.

## D17.14 D5 storage substrate: fjall with a STORAGE-TIERS migration exception
The first durable D5 store is built on fjall 3 transactional keyspaces directly. No qualified fleet tier fits yet: pinax 0.0.4 has no multi-row transaction, no schema migration, and no encryption, and koina exposes no public content-addressed blob API. Per `kanon/crates/basanos/standards/STORAGE-TIERS.md`, this is a named migration exception: the owning crate declares pinax and koina as the target tiers in its roadmap and tracks removal of the direct fjall dependency in a STORAGE-TIERS exception issue. Retirement condition: pinax ships a multi-row transaction with schema migration and encryption, and koina exposes a public content-addressed blob API. Until both exist, raw fjall is the sanctioned substrate. Detail in `docs/design/custody-store.md`.

## D17.15 Encryption at rest in the first durable store
The first durable D5 store encrypts every sensitive record at rest, satisfying the R11 encryption-at-rest requirement in the first store rather than deferring it. A 0600 root key derives per-purpose subkeys and per-tenant wrapped data keys; sealed records bind version, record kind, key id, keyspace, and record key as additional authenticated data; blob addresses are tenant-keyed so no cross-tenant address oracle exists; the store fails closed on a missing key, wrong permissions, or a key-check mismatch. Key hierarchy, rekey, and crypto-shred detail in `docs/design/custody-store.md`. Closes dioptron#35.

## D17.16 Dry-run writes nothing durable and every invocation is one transaction
A dry-run invocation writes nothing durable, including no audit record: it ends in memory at the Planned state and its only product is the returned plan (facts, cost, rule chain) per R9.2. Each committed invocation state transition is one store transaction, state-checked so reservation settlement or release happens exactly once. This resolves the dioptron#34 ambiguity about whether dry-run and multi-step invocation leave partial durable state: dry-run leaves none, and a crash between transactions recovers to a single known state. Lifecycle table in `docs/design/capability-contract.md`.

## D17.17 Implementation kickoff for the capability and custody stack
Phase 01 S2 (the first Rust workspace: contract, authorization, custody, daemon, client) is authorized by operator decision on 2026-09-25, which serves as the crate-creation kickoff that `AGENTS.md` requires. S3 (the Zetesis static-acquisition adapter) stays gated on `docs/design/zetesis-acquisition-boundary.md` and the dioptron#66 dependency-and-compatibility conditions; it is not authorized by this record.
