# Contributing to Dioptron

Dioptron uses the self-hosted kanon forge as the authoritative PR surface. GitHub stays bidirectionally mirrored for external discoverability, but PRs live on the forge.

## Push target

```
origin = http://kanon.lan/forkwright/dioptron.git   (authoritative)
github = git@github.com:forkwright/dioptron.git     (mirror)
```

Push to `origin`. The forge post-receive hook runs CI (`.kanon-ci.toml`) and mirrors merge commits to GitHub via the pr-sync worker.

## Opening a PR

Two paths, same effect:

**Stoa UI.** Open `http://kanon.lan/prs/forkwright/dioptron`, click "New PR", pick base + head refs, review diff, submit.

**CLI.**

```bash
git push origin HEAD:refs/heads/<branch>
kanon pr open <branch> --title "..." --body "..."
```

`kanon pr open` prints the new PR number and its forge URL.

## Review

Comments and approvals land through stoa. The merge button activates when all gates report green:

- CI status `Pass` (every stage in `.kanon-ci.toml` exits zero, or the stage's `fail_on` predicate reports success).
- Independent verifier `Ok` (03f-e reproduces the headline claims from a fresh checkout of the head sha).
- A `Gate-Passed: kanon <version>` trailer is present on the tip commit of the PR branch, or the merge will append one.

## Merging

```bash
kanon pr merge <pr_number>
```

or the forge merge button. Default strategy is `squash`; `--strategy ff` or `--strategy rebase` are supported. The merge commit carries the `Gate-Passed` trailer.

Do not merge via GitHub. The GitHub mirror is read-only from the contributor's perspective: any merge performed there races the forge pr-sync worker and drops the trailer.

## External contributors

The GitHub mirror at `github.com/forkwright/dioptron` works as before. A PR opened on GitHub is ingested into the forge via the 05d bidirectional sync and then follows the normal review path above. The merge still happens on the forge; GitHub closes when the mirror sync observes the merge commit on `main`.

## Fallback

If the forge is unreachable, push to `github` and open a GitHub PR. When the forge is back, its pr-sync worker picks up the PR and continues from there. This is an escape hatch, not a preferred path - use it only when kanon.lan is actually down.

## CI configuration

`.kanon-ci.toml` at the repo root defines the pipeline. Dioptron is docs-only today, so the pipeline is a single sentinel stage that confirms the checkout landed. When dioptron grows a crates workspace, expand the pipeline to the full Rust gate (fmt, check, clippy, nextest, kanon lint) - no CI-side changes needed.

## Branch naming and commit format

Per `CLAUDE.md`: `feat/`, `fix/`, `docs/`, `refactor/`, `test/`, `cleanup/`. Commit messages are `category(scope): description`. Squash merges keep main linear.
