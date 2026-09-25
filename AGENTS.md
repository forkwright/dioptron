<!--
scope: dioptron agent dispatch conventions (sovereign web runtime, Phase 01 implementation)
defers_to: kanon standards for universal engineering policy
tightens: crates limited to the Phase 01 plan; no new crates without operator decision
-->

# AGENTS.md: Dioptron

## Repo context

Dioptron entered its implementation phase on 2026-09-25 by operator decision. The Rust workspace under `crates/` holds the Phase 01 crates: `syntheke` (capability contract), `epitrope` (authorization), `phylake` (custody store), `dioptron` (daemon), and `xenos` (independent test client). The specification corpus stays authoritative: requirements, topology, tenancy model, technical decisions, and the structured `_llm/` corpus.

## Entry points

- [README.md](README.md) - overview and documentation index
- [CLAUDE.md](CLAUDE.md) - locked decisions and repo conventions
- [llms.txt](llms.txt) - structured corpus index
- [docs/design/topology.md](docs/design/topology.md) - 3-band, 11-layer architecture
- [docs/design/tenancy.md](docs/design/tenancy.md) - peer tenant model
- [docs/design/decisions.md](docs/design/decisions.md) - resolved technical decisions (D17.*)
- [docs/requirements.md](docs/requirements.md) - R1-R12 requirements
- [docs/design/vision.md](docs/design/vision.md) - pointer to kanon-canonical vision + open questions (Q2-Q5)

## Dispatch rules

- Branch naming: `feat/`, `fix/`, `docs/`, `refactor/`, `cleanup/`
- Squash merge to `main`. No develop branch.
- Commit format: `category(scope): description`  -  scopes are `docs`, `infra`, `design`, or a crate name.
- Every PR needs the terminal `gate / gate` context. A genuine `Gate-Passed:`
  trailer from the full Kanon gate is a fast-path receipt; an untrailed PR runs
  the public deterministic projection in GitHub Actions instead.

## What agents do here

- Implement the Phase 01 crates within the scope of the approved Phase 01 plan (S2: authorization and durable capture custody).
- Add or update design docs, refine requirements, record decisions, maintain the `_llm/` corpus, fix lint violations, add fleet-structure files.
- Run the local gate before pushing: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features`, `cargo test --workspace --doc --all-features`, `cargo deny check`, and the doc checks in `ci/`.

## What agents do not do here

- Do not add crates beyond the five Phase 01 crates, or implementation work outside the Phase 01 plan, without an explicit operator decision.
- Do not add HTTP, DNS, or content-extraction code: static acquisition belongs to Zetesis (see `docs/design/zetesis-acquisition-boundary.md`).
- Do not merge release-please PRs  -  operator decides each release cut.
- Do not modify `.github/workflows/` without understanding the full gate pipeline.
- No filler words (see kanon/standards/WRITING.md for the list).
