<!--
scope: dioptron repo conventions (sovereign web runtime with agent co-tenancy; 11-layer topology + tenancy plane)
defers_to: ~/menos-ops/CLAUDE.md for machine topology; ~/.claude/CLAUDE.md for operator principles; kanon standards for universal engineering policy
tightens: peer-tenancy capability model, per-verb landlock+seccomp sandboxing, rendering-floor requirements
-->

# CLAUDE.md: Dioptron

## Repository

Dioptron (δίοπτρον): sovereign web runtime with agent co-tenancy. The instrument through which operator and agents see through the web.

Local web substrate that transforms the open web into structured, persistent, queryable knowledge inside the operator's cognitive ecosystem. Zero-friction, unlinkable, sovereign interface to origins. Full active observation, defense, and offense capability. Largest single source of behavioral training data for the forkwright stack. Human and agent tenants as peer users on a single canonical capability surface.

```
dioptron/
├── crates/                 # Rust workspace crates
│   └── (TBD  -  see design/topology.md for the 11-layer + tenancy plane)
├── standards/              # Coding standards (kanon-synced)
├── docs/
│   ├── design/             # Architecture and design docs
│   │   ├── topology.md         # 3-band, 11-layer + tenancy plane
│   │   ├── tenancy.md          # Multi-tenant peer user model
│   │   ├── training-data.md    # Behavioral emission taxonomy
│   │   └── decisions.md        # Resolved technical decisions (D17.*)
│   ├── requirements.md     # R1-R12 requirements
│   ├── lexicon.md          # Project name registry
│   └── gnomon.md           # Naming methodology
├── planning/
│   └── open-questions.md   # Q1-Q5 deferred decisions
├── .github/                # CI workflows
├── CLAUDE.md               # This file
└── NOTICE                  # AI training prohibition
```

## Standards

Follow kanon standards (canonical source: `kanon/crates/basanos/standards/`). Key docs: `RUST.md`, `TESTING.md`, `SECURITY.md`, `ARCHITECTURE.md`, `WRITING.md`.

## Key decisions (locked)

- **Peer tenancy**: operator, agents, sub-agents are all tenant classes with the same capability surface. Differences are grants, not capabilities.
- **Canonical interface**: Rust trait surface over unix socket + plegma-quic. Desktop UI is just another client.
- **Three bands**: engine (net, render, script, store, identity), instrument (ingest, rules, session, ui), operations (ops). Tenancy is cross-cutting.
- **Ops sandboxing**: per-verb landlock+seccomp. Exploit-runner in dedicated network namespace. Credentials as ephemeral handles.
- **Pure Rust**: same as aletheia  -  no C++ in the brain
- **Single operator**: multi-tenant for human+agents, not for multiple humans
- **Rendering floor**: operator's top-1000 sites without breakage (v1)
- **Fallback browser**: chromium-based fallback for sites that defeat native rendering, quarantined with provenance

## Architecture

Three bands across eleven layers + cross-cutting tenancy plane:

| Band | Layers | Purpose |
|------|--------|---------|
| Engine | D2 net, D3 render, D4 script, D5 store, D6 identity | Core web engine |
| Instrument | D7 ingest, D8 rules, D9 session, D10 ui | Knowledge acquisition |
| Operations | D11 ops | Active capability surface |
| Cross-cutting | D12 tenancy | Tenant identity, grants, delegation, programmatic interface |

## Peer integrations

Three composable, independently optional, runtime-discovered:
- **Standalone**: full runtime, local knowledge store
- **Integrated-aletheia**: shared knowledge via forkwright-cognition traits
- **Integrated-akroasis**: network defense posture, passive fingerprint observation

Plegma/hamma is ambient transport, not a peer integration.

## Branch strategy

- **Single branch:** `main`. No develop branch.
- PRs target `main`. Squash merge.
- Branch naming: `feat/`, `fix/`, `docs/`, `refactor/`, `test/`, `cleanup/`

## Commit format

`category(scope): description`

Categories: feat, fix, docs, refactor, test, chore, style
Scopes: crate name or `docs`, `infra`, `design`

## Build & test

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## What not to do

- Don't add dependencies without justification
- Don't modify CI workflows without understanding the full pipeline
- No filler words: comprehensive, robust, leverage, streamline, modernize, strategic, enhance
