# Contributing to Dioptron

GitHub is Dioptron's authoritative repository, pull-request, review, CI, and
merge surface.

## Push a branch

Create a feature branch using one of the prefixes in `CLAUDE.md`, then push it
to the GitHub `origin`:

```bash
git push -u origin HEAD
```

Do not push changes directly to `main`.

## Open a pull request

Open a GitHub pull request against `main`, either in the GitHub UI or with the
CLI:

```bash
gh pr create --base main --title "..." --body-file path/to/pr-body.md
```

Keep the pull request body explicit about the affected contract and the
verification that applies to the exact head SHA.

## Review and CI

GitHub Actions is the active pull-request verifier. Every pull request must
receive a successful terminal `gate / gate` result for its exact head before it
merges. A genuine `Gate-Passed: kanon <version>` trailer takes the hybrid
workflow's fast path on a pull request; an untrailed pull request runs the
repository's public deterministic checks. A push to `main` always runs those
checks against the landed tree.

Repository authority and required status contexts are operator-controlled. If
branch protection does not require the exact `gate / gate` context, that is a
configuration defect; it does not turn an absent, pending, or failed gate into
merge evidence.

`.kanon-ci.toml` is a local Kanon recipe. It records additional checks available
when the private Kanon binary is installed, including workflow and writing
lint. The current GitHub workflow does not execute those private stages, and no
forge or independent verifier reports their result as a merge requirement.
Only an observed run is evidence that the local recipe passed; it does not
replace the exact-head GitHub result.

## Merge

Use GitHub's squash merge after review and exact-head CI is complete. A GitHub
merge does not manufacture a `Gate-Passed` trailer on the landed commit, so do
not describe the resulting `main` commit as locally attested unless a separate
receipt proves that claim.

## CI configuration

`.github/workflows/gate-attestation.yml` is the active hosted verifier. Dioptron
is docs-only today, so its command slots run Python syntax, document-reference,
manifest-completeness, and structural negative checks rather than Cargo jobs.
The optional doctest slot remains empty until an executable Rust doctest corpus
exists.

The private Kanon lints retained in `.kanon-ci.toml` are a supplementary local
recipe, not a hidden hosted stage. Do not replace missing private tooling with a
no-op or claim that GitHub ran checks it cannot run.

## Branch naming and commit format

Per `CLAUDE.md`, branch names use `feat/`, `fix/`, `docs/`, `refactor/`, `test/`,
or `cleanup/`. Commit messages use `category(scope): description`. Squash merges
keep `main` linear.
