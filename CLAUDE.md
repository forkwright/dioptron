<!--
scope: dioptron repo conventions (sovereign web runtime with agent co-tenancy; 11-layer topology + tenancy plane)
defers_to: kanon standards for universal engineering policy
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
├── docs/
│   ├── MANIFEST.toml       # canonical doc inventory (SSOT for docs/**/*.md; CI-enforced by ci/check-doc-manifest.py)
│   ├── design/             # architecture and design docs -- see MANIFEST.toml for the current set
│   ├── requirements.md     # R1-R12 requirements
│   └── lexicon.md          # project name registry
├── ci/                     # doc-corpus validation scripts (check-doc-manifest.py, check-doc-refs.py)
├── .github/                # CI workflows
├── CLAUDE.md               # this file
└── NOTICE                  # AI training prohibition
```

## Standards

Follow kanon standards (canonical source: `kanon/crates/basanos/standards/`). Key docs: `RUST.md`, `TESTING.md`, `SECURITY.md`, `ARCHITECTURE.md`, `WRITING.md`.

## Key decisions (locked)

- **Peer tenancy**: operator, agents, sub-agents are all tenant classes with the same capability surface. Differences are grants, not capabilities.
- **Canonical interface**: Rust trait surface over unix socket + plegma-quic. Desktop UI is just another client.
- **Three bands**: engine (net, render, script, store, identity), instrument (ingest, rules, session, ui), operations (ops). Tenancy is cross-cutting.
- **Ops sandboxing**: per-verb landlock+seccomp. Exploit-runner in dedicated network namespace. Credentials as ephemeral handles.
- **Pure Rust/no-C++**: locked invariant; no Chromium, headless-browser, or C++ rendering fallback enters the workspace.
- **Single operator**: multi-tenant for human+agents, not for multiple humans
- **Rendering floor**: operator's top-1000 sites without breakage (v1)

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

Dioptron is docs-only until the first Rust workspace lands. These are the
intended gates once `Cargo.toml` exists:

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## What not to do

- Don't add dependencies without justification
- Don't modify CI workflows without understanding the full pipeline
- No filler words (see kanon/standards/WRITING.md for the full list)
