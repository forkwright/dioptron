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
├── crates/                 # Rust workspace (Phase 01)
│   ├── syntheke/           # capability contract: wire schema, ids, capabilities, outcomes
│   ├── epitrope/           # authorization: grant narrowing, validity, budgets (pure, no IO)
│   ├── phylake/            # D5 custody store: encrypted transactional persistence
│   ├── dioptron/           # daemon: orchestrator, producer seam, socket server (bin + lib)
│   └── xenos/              # independent wire client for process-level tests (publish = false)
├── docs/
│   ├── MANIFEST.toml       # canonical doc inventory (SSOT for docs/**/*.md; CI-enforced by ci/check-doc-manifest.py)
│   ├── design/             # architecture and design docs -- see MANIFEST.toml for the current set
│   ├── requirements.md     # R1-R12 requirements
│   └── lexicon.md          # project name registry
├── ci/                     # doc-corpus validation scripts (check-doc-manifest.py, check-doc-refs.py)
├── .github/                # CI workflows (gate, docs, security, CodeQL, release)
├── Cargo.toml              # workspace manifest, shared lints
├── deny.toml               # cargo-deny policy (licenses, bans, sources, advisories)
├── rust-toolchain.toml     # pinned toolchain (1.97.1)
├── CLAUDE.md               # this file
└── NOTICE                  # AI training prohibition
```

## Standards

Follow kanon standards (canonical source: `kanon/crates/basanos/standards/`). Key docs: `RUST.md`, `TESTING.md`, `SECURITY.md`, `ARCHITECTURE.md`, `WRITING.md`.

Test layout: test modules live in `tests.rs` files (`#[cfg(test)] mod tests;`) or `tests/` directories, never inline, and test-only helpers live in `test_support.rs`; CodeQL skips those paths (`.github/codeql/codeql-config.yml`).

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

Categories: feat, fix, docs, refactor, test, chore, style, ci
Scopes: crate name or `docs`, `infra`, `design`

## Build & test

The implementation phase started on 2026-09-25 by operator decision; see
AGENTS.md for the crate scope. Dependency direction: syntheke <- epitrope
<- phylake <- dioptron; xenos links only syntheke.

Local gate (the same commands as the hosted `gate / gate`, `docs`, and cargo-deny checks):

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo test --workspace --doc --all-features
cargo deny check
python3 ci/check-doc-refs.py .
python3 ci/check-doc-manifest.py --structure-only .
python3 ci/check-doc-manifest.py --self-test --structure-only
```

## What not to do

- Don't add dependencies without justification
- Don't modify CI workflows without understanding the full pipeline
- No filler words (see kanon/standards/WRITING.md for the full list)
