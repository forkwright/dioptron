# Requirements — Dioptron

## R1. Purpose

The runtime is a local web substrate that:
1. Transforms the open web into structured, persistent, queryable knowledge inside the operator's cognitive ecosystem.
2. Presents a zero-friction, unlinkable, sovereign interface to origins.
3. Provides full active observation, defense, and offense capability over the operator's web surface.
4. Generates the largest single source of behavioral training data for the forkwright stack.
5. Hosts human and agent tenants as peer users on a single canonical capability surface.

These five functions are co-equal. The operator is the policy authority on every capability. The runtime obeys; the rules engine enforces; the operator governs.

## R2. Tenancy model — peer users

R2.1 Multi-tenant by design. Tenant classes: **operator** (the human), **agent** (long-lived autonomous, e.g. nous), **sub-agent** (short-lived, dispatched by an agent or by the operator via kanon).

R2.2 Every capability available to every tenant class. No capability implemented twice. Differences between tenant classes expressed as grants and presentation, not capability.

R2.3 Canonical interface: Rust trait surface over local unix socket and plegma-quic to authorized remote tenants. Desktop UI is a client, no more privileged than any agent client.

R2.4 Every event attributed to its acting tenant. Tenant identity recorded as fact alongside session, time, and content.

R2.5 Sessions have an owning tenant. Ownership transferable via handoff. Multiple tenants may hold concurrent read access; write access exclusive to owner unless shared by rule. Operator and agent can co-tenant in real time.

R2.6 Capability grants are per-tenant standing permissions. Sessions inherit owner grants, narrowable by rule. Sub-agents inherit narrowed grants from parent; delegation chains recorded as facts.

R2.7 Grant revocation behavior rule-defined per verb. Default: killable (in-flight invocations terminate, partial state preserved as audit fact). Exception: drain-only for verbs whose mid-operation termination would corrupt state or leak more than completion.

## R3. Operating modes

Three composable peer integrations, independently optional, runtime-discovered: standalone, integrated-aletheia, integrated-akroasis. Mode transitions non-destructive in both directions. Plegma is ambient transport, not a peer integration.

## R4. Functional requirements (instrument & ingestion)

R4.1 Fetch any URL with full TLS, cookie, and header control.
R4.2 Parse and extract structured content from HTML, PDF, and common document formats.
R4.3 Execute JavaScript in a sandboxed engine for dynamic content extraction.
R4.4 Store fetched content as immutable artifacts with provenance metadata.
R4.5 Ingest artifacts into a tiered knowledge store: raw captures (tier 3), extracted facts (tier 2), verified knowledge (tier 1).
R4.6 Detect contradictions between new and existing knowledge across tiers.
R4.7 Support standing queries: recurring fetch-and-ingest on a schedule with budget controls.
R4.8 Full-text search and semantic search across the knowledge store.
R4.9 Session-scoped browsing: each session maintains its own cookie jar, history, and working set.
R4.10 Fork sessions: create a branch of an existing session with shared history and independent future state.

## R5. Privacy & anti-tracking requirements

R5.1 Per-session fingerprint identity synthesized from real browser population distributions.
R5.2 No cross-session fingerprint linkability unless the operator explicitly enables it per origin.
R5.3 Cookie isolation per session with operator-visible cookie jar.
R5.4 Referrer policy enforcement: strict-origin by default, configurable per rule.
R5.5 Canvas/WebGL/AudioContext fingerprint defense via noise injection calibrated to real distributions.
R5.6 Font enumeration defense.
R5.7 Timing attack defense on network and rendering paths.
R5.8 TLS fingerprint (JA3/JA4) rotation from real client populations.
R5.9 All privacy defenses auditable: the operator can inspect exactly what identity is presented to each origin.
R5.10 Operator controls override all defaults. No hardcoded "safe" behavior that cannot be disabled.

## R6. Web-adjacent capabilities

R6.1 Form submissions as first-class artifacts with before/after state capture.
R6.2 Outbound composition capture: email, chat, post drafts preserved as facts.
R6.3 Archive verification: compare current page against Wayback Machine or local prior capture.
R6.4 Feed graph: RSS/Atom discovery, subscription management, ingestion.

## R7. Operations capabilities

R7.1 Tor as an optional transport layer for any fetch operation.
R7.2 TLS introspection: certificate chain analysis, CT log monitoring, pinning verification.
R7.3 Active probing: port scanning, service fingerprinting, banner grabbing (operator-authorized targets only).
R7.4 SRI tracking: subresource integrity monitoring for script supply-chain changes.
R7.5 Canary monitoring: detect changes to warrant canary pages.
R7.6 Full active capability surface: MITM (operator-declared targets), credential testing, exploit runner. Operator is the safety; rules engine enforces; runtime obeys.
R7.7 Cover traffic generation: plausible browsing patterns to mask operational activity.
R7.8 Operations audit: every active operation logged with full provenance, never deletable by the acting tenant.
R7.9 Certificate Transparency monitoring for operator-owned domains.

## R8. Training data requirements

R8.1 Every operator-relevant and agent-relevant event emitted in a format directly consumable by local fine-tuning pipelines. Event taxonomy: captures with attention scores, contradiction events with resolutions, rule overrides, tier-promotion outcomes, form submissions with follow-up, query-to-selection pairs, active-capability invocations with outcomes, agent strategy traces, operator-overrides-agent events.

R8.2 Every event records acting tenant identity, grant chain, session, and rule outcome. Datasets filterable by tenant class, individual tenant, delegation depth, or grant scope.

R8.3 Cross-system contribution via `forkwright-corpus` workspace crate. The runtime is the largest contributor.

R8.4 Dataset taxonomy enumerated and versioned. Each type declares: source events, label structure, downstream model class, privacy class, default retention.

## R9. Agent tooling requirements

R9.1 Capability discovery: any tenant can query available verbs given current grants.
R9.2 Dry-run mode: every verb supports dry-run returning facts, cost, and rule chain without committing.
R9.3 Streaming results: ingestion, fetch, and query operations stream partial results.
R9.4 Cost accounting: every invocation declares cost in time, fetches, tokens, and operations budget.
R9.5 Failure recovery: every long-running operation resumable across restarts.
R9.6 Rules introspection: tenant can ask "which rules would fire if I attempted X."
R9.7 Rule proposal: agents can propose rule additions/modifications. Proposals enter operator review queue.
R9.8 Observability bus: tenants subscribe to events from sessions they have read access to.
R9.9 Inter-tenant handoff protocol: explicit ownership transfer, recorded as audit fact.

## R10. Competitive frame

R10.1 Exceed every LLM-native browser on their best dimensions AND on dimensions they architecturally cannot match (sovereignty, custom rules, full audit, active ops, agent co-tenancy, knowledge graph integration).

R10.2 Operator-facing graphical interface is a competitive daily-driver browser by absolute standards. Theatron-or-equivalent desktop surface is v1. Ratatui secondary.

R10.3 Agent-facing interface exceeds every existing agent browser tooling on capability completeness, observability, cost accounting, and reasoning substrate integration.

## R11. Non-functional requirements

- Sovereignty: runs entirely locally, no cloud dependency beyond operator's LLM API key
- Encryption at rest for all stored artifacts and knowledge
- Sandboxing: every untrusted operation in landlock+seccomp
- Zero unsafe in application code (vendor exceptions permitted with audit)
- Deterministic rendering where possible
- Capability security model (not ambient authority)
- Offline operation: full functionality with cached content when network unavailable
- Update sovereignty: operator controls when and what updates are applied

## R12. Explicit non-requirements

- No multi-human operator support (single operator, agents are the other tenants)
- No hardcoded ethics policy on the active capability surface (operator is the policy authority)
- No cloud sync (plegma handles device-to-device sync)
- No mobile v1 (desktop first)
