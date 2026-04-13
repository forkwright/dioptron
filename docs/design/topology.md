# Layer Topology

Three bands across eleven layers, plus a cross-cutting tenancy plane.

## Engine Band

Core web engine capabilities. These layers do the hard work of interacting with the web.

### D2. Net
Network stack: HTTP/1.1, HTTP/2, HTTP/3 (QUIC). TLS with configurable fingerprinting (JA3/JA4 rotation). Cookie jar per session. Proxy support (SOCKS5, HTTP CONNECT, Tor). DNS resolution with DoH/DoT. Connection pooling with session isolation.

### D3. Render
HTML/CSS rendering engine. The rendering completeness floor (R10.2): operator's top-1000 sites without breakage. Layout, painting, compositing. Image decode. Font shaping. Accessibility tree.

### D4. Script
JavaScript execution in sandboxed engine. DOM interaction for dynamic content extraction. Web API surface sufficient for modern sites. Resource budgets per execution context.

### D5. Store
Persistent storage for all runtime state. Tiered knowledge store: artifacts (tier 3, raw captures), facts (tier 2, extracted), verified (tier 1, confirmed). Tenants partition for identities, grants, delegation chains, budget ledgers. Audit partition for immutable event log.

### D6. Identity
Per-session fingerprint identity synthesized from real browser populations. Canvas/WebGL/Audio noise injection. Font enumeration defense. Timing attack mitigation. TLS fingerprint rotation. All defenses auditable.

## Instrument Band

Knowledge acquisition and interaction management. These layers transform raw web interaction into structured knowledge.

### D7. Ingest
Content extraction pipeline: HTML → structured data, PDF → text, feeds → items. Contradiction detection against existing knowledge. Tier assignment and promotion. Metadata extraction (author, date, source, provenance).

### D8. Rules
Policy engine governing all runtime behavior. Rules scope to tenant class, individual tenant, delegation depth. Rule facts include tenant identity, grant evaluations, delegation events, proposals, handoffs. Standing query budgets. Operations band authorization.

### D9. Session
Session lifecycle: create, fork, transfer, archive. Owning tenant with concurrent read access. Co-tenancy coordination (operator watches agent work in real time). Session state: cookie jar, history, working set, knowledge scope.

### D10. UI
Desktop surface (theatron-or-equivalent) and terminal surface (ratatui). Both are clients of the canonical programmatic interface (D12). No privileged access — same trait surface as agents. Tab/session management, grants surface, rule editor, knowledge browser.

## Operations Band

Active capability surface. Sharp-end operations requiring explicit operator authorization.

### D11. Ops
Per-verb sandboxing (landlock+seccomp). Verb categories: TLS introspection, CT monitoring, active probing, SRI tracking, canary monitoring, MITM (operator-declared targets), credential testing, exploit runner, cover traffic. Each verb declares revocation behavior (killable or drain-only). Credential material as ephemeral handles from vault.

## Cross-Cutting

### D12. Tenancy Plane — `forkwright-tenancy`

Not a layer in the request path. Cross-cutting service owning:

- **Tenant registry**: identities for operator, agents, sub-agents. Public identifier, signing key, standing grants, budget ledger.
- **Grant evaluator**: given (tenant, verb, target, session) → authorize/deny with rule chain. Called by every verb.
- **Delegation chain manager**: parent-child relationships, grant narrowing on dispatch, revocation propagation.
- **Canonical programmatic interface**: Rust trait surface over unix socket (local) and plegma-quic (remote). Wire format: rkyv. All operations — fetch, ingest, query, invoke verb, fork session, hand off, propose rule, query grants, query budget, dry-run — are methods on this surface.
- **Co-tenancy coordinator**: concurrent read, single-writer, real-time event streams, atomic ownership handoff.

## Peer Integration Surface — `forkwright-cognition`

Six traits for peer system integration:
- `KnowledgeSink` — push knowledge to/from aletheia
- `MemoryGraph` — query aletheia's knowledge graph
- `RulesBackend` — share rules with aletheia's policy engine
- `SignalEnvironment` — receive akroasis network posture
- `SignalEmitter` — emit events to akroasis
- `CredentialVault` — credential storage (proton-pass interim, clean-room vault planned)

## MCP Surface

Outward-only. Exposes query operations to external agents that can't speak the canonical Rust interface. Read-only by default; write operations require explicit grant.
