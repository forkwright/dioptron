<!--
scope: dioptron agent dispatch conventions (design-phase sovereign web runtime)
defers_to: kanon standards for universal engineering policy
tightens: design-phase-only dispatch; no implementation crates without operator decision
-->

# AGENTS.md: Dioptron

## Repo context

Dioptron is in the design phase. No Rust crates have landed. All work is documentation and specification: requirements, topology, tenancy model, technical decisions, and the structured `_llm/` corpus.

## Entry points

- [README.md](README.md) - overview and documentation index
- [CLAUDE.md](CLAUDE.md) - locked decisions and repo conventions
- [llms.txt](llms.txt) - structured corpus index
- [docs/design/topology.md](docs/design/topology.md) - 3-band, 11-layer architecture
- [docs/design/tenancy.md](docs/design/tenancy.md) - peer tenant model
- [docs/design/decisions.md](docs/design/decisions.md) - resolved technical decisions (D17.*)
- [docs/requirements.md](docs/requirements.md) - R1-R12 requirements
- [planning/open-questions.md](planning/open-questions.md) - deferred decisions (Q2-Q5)

## Dispatch rules

- Branch naming: `feat/`, `fix/`, `docs/`, `refactor/`, `cleanup/`
- Squash merge to `main`. No develop branch.
- Commit format: `category(scope): description`  -  scopes are `docs`, `infra`, `design`, or a crate name once crates land.
- Every PR needs a `Gate-Passed:` trailer from a passing local gate run.

## What agents do here

Design-phase tasks only: add or update design docs, refine requirements, record decisions, maintain the `_llm/` corpus, fix lint violations, add fleet-structure files.

## What agents do not do here

- Do not add Rust crates without an explicit operator decision to start the implementation phase.
- Do not merge release-please PRs  -  operator decides each release cut.
- Do not modify `.github/workflows/` without understanding the full gate pipeline.
- No filler words (see kanon/standards/WRITING.md for the list).
