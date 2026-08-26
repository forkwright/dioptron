#!/usr/bin/env python3
"""check-doc-manifest — make docs/MANIFEST.toml the authoritative CI input set.

Usage:
    ci/check-doc-manifest.py [repo-root]
    ci/check-doc-manifest.py --self-test
    ci/check-doc-manifest.py --structure-only [repo-root]
    ci/check-doc-manifest.py --self-test --structure-only

Dioptron's product at this phase is its specification corpus, so the corpus is
what CI has to hold. The manifest already inventories every canonical document;
this script makes that inventory load-bearing instead of decorative by deriving
the validation set from it rather than from a second hand-maintained list in
`.kanon-ci.toml`.

Three checks, in order:

1. Missing — every path the manifest declares exists on disk. Catches a
   document that was renamed or deleted while its manifest entry survived.
2. Unlisted — every canonical document on disk appears in the manifest. This
   is the check that keeps the manifest authoritative: without it, adding a
   spec document and omitting it from the manifest silently exempts it from
   validation, which is the exact failure mode a manifest is supposed to
   prevent.
3. Writing — `kanon lint --writing` passes for every manifest document.
   Validation itself belongs to kanon lint; this script only decides what gets
   validated.

`--structure-only` runs the missing/unlisted checks without invoking Kanon. It
is the honest public-CI projection: GitHub can execute this repository's Python
mechanism, but it cannot install the private Kanon binary. The default remains
the full forge gate, including writing validation.

WHY the canonical scope is `docs/**/*.md` and not the whole tree: the
repository root carries operational documents (README, CHANGELOG, CONTRIBUTING,
LICENSE, SECURITY, NOTICE, AGENTS, CLAUDE) whose owner is the fleet repo
convention, not this repository's specification. README already has its own
pipeline stage.

Output:
    One line per problem, prefixed `missing:`, `unlisted:`, or `writing:`, to
    stderr, followed by kanon lint's own findings for the writing failures.

Exit codes:
    0 — the manifest and the corpus agree, and every document passes
    1 — at least one problem
    2 — invocation error (bad root, unreadable or malformed manifest)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

MANIFEST_REL = "docs/MANIFEST.toml"

# WHY: the canonical corpus is everything under docs/, minus the manifest
# itself — it is the index, not an indexed document.
CANONICAL_ROOT = "docs"
CANONICAL_GLOB = "*.md"


def load_manifest(root: Path) -> list[str]:
    """Return the manifest's declared document paths, repo-relative."""
    path = root / MANIFEST_REL
    if not path.is_file():
        raise FileNotFoundError(f"missing manifest {MANIFEST_REL}")
    data = tomllib.loads(path.read_text())
    entries = data.get("doc")
    if not entries:
        raise ValueError(f"{MANIFEST_REL} declares no [[doc]] entries")
    paths = []
    for entry in entries:
        declared = entry.get("path")
        if not declared:
            raise ValueError(f"{MANIFEST_REL} has a [[doc]] entry with no `path`")
        paths.append(declared)
    return paths


def canonical_on_disk(root: Path) -> list[str]:
    """Return every canonical document present on disk, repo-relative."""
    base = root / CANONICAL_ROOT
    if not base.is_dir():
        return []
    return sorted(
        str(p.relative_to(root))
        for p in base.rglob(CANONICAL_GLOB)
        if ".git" not in p.parts
    )


def writing_findings(root: Path, rel: str) -> str | None:
    """Return kanon lint's output for `rel`, or None when it passes."""
    result = subprocess.run(
        ["kanon", "lint", "--writing", rel],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return None
    return (result.stdout + result.stderr).strip()


def check(root: Path, *, include_writing: bool = True) -> list[str]:
    """Run manifest checks against `root` and return the problems found."""
    declared = load_manifest(root)
    problems: list[str] = []

    for rel in declared:
        if not (root / rel).is_file():
            problems.append(f"missing: {rel} is declared in {MANIFEST_REL} but absent on disk")

    declared_set = set(declared)
    for rel in canonical_on_disk(root):
        if rel == MANIFEST_REL:
            continue
        if rel not in declared_set:
            problems.append(
                f"unlisted: {rel} is a canonical document but is absent from "
                f"{MANIFEST_REL}, so no CI stage validates it"
            )

    if include_writing:
        for rel in declared:
            if not (root / rel).is_file():
                continue  # already reported as missing
            findings = writing_findings(root, rel)
            if findings:
                problems.append(f"writing: {rel} fails `kanon lint --writing`\n{findings}")

    return problems


def _self_test(*, include_writing: bool = True) -> int:
    """Prove each check fires on a corpus that violates it.

    WHY this exists: every manifest document passes today, so a green run is
    not by itself evidence that the checks can fail. Each case below mutates a
    throwaway copy of the corpus in the one way the corresponding check exists
    to catch, and asserts the check reports it.
    """
    root = Path(__file__).resolve().parent.parent
    cases = []

    # WHY mkdtemp rather than a fixed /tmp path: a fixed path is owned by
    # whichever account creates it first, and every other account then fails
    # in ways that look like defects in this script.
    workdir = Path(tempfile.mkdtemp(prefix="check-doc-manifest-selftest-"))
    try:
        baseline = workdir / "baseline"
        shutil.copytree(root, baseline, ignore=shutil.ignore_patterns(".git"))

        if check(baseline, include_writing=include_writing):
            print("self-test: baseline corpus does not pass; fix that first", file=sys.stderr)
            return 1
        cases.append(("baseline passes", True))

        # Case 1: a canonical document on disk that the manifest never lists.
        unlisted = workdir / "unlisted"
        shutil.copytree(baseline, unlisted)
        (unlisted / "docs" / "design" / "smuggled.md").write_text("# Smuggled\n\nUnlisted.\n")
        fired = any(
            p.startswith("unlisted:")
            for p in check(unlisted, include_writing=include_writing)
        )
        cases.append(("unlisted document is caught", fired))

        # Case 2: a manifest entry whose document has been removed.
        missing = workdir / "missing"
        shutil.copytree(baseline, missing)
        (missing / "docs" / "lexicon.md").unlink()
        fired = any(
            p.startswith("missing:")
            for p in check(missing, include_writing=include_writing)
        )
        cases.append(("missing document is caught", fired))

        if include_writing:
            # Case 3: an invalid change to a canonical requirement. This is
            # deliberately absent from --structure-only because Kanon owns the
            # writing judgment and is unavailable on public hosted runners.
            bad = workdir / "writing"
            shutil.copytree(baseline, bad)
            target = bad / "docs" / "requirements.md"
            target.write_text(
                target.read_text()
                + "\nIt is very important to note that this is basically quite simple.\n"
            )
            fired = any(
                p.startswith("writing:")
                for p in check(bad, include_writing=include_writing)
            )
            cases.append(("invalid requirement change fails CI", fired))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    for name, ok in cases:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    failed = [name for name, ok in cases if not ok]
    if failed:
        print(f"self-test: {len(failed)} case(s) did not fire.", file=sys.stderr)
        return 1
    mode = "" if include_writing else " structural"
    print(f"check-doc-manifest{mode} self-test: ok ({len(cases)} cases).")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    structure_only = "--structure-only" in argv
    argv = [arg for arg in argv if arg != "--structure-only"]
    if argv and argv[0] == "--self-test":
        if len(argv) != 1:
            print("error: --self-test accepts no repo root", file=sys.stderr)
            return 2
        return _self_test(include_writing=not structure_only)

    if len(argv) > 1:
        print("error: expected at most one repo root", file=sys.stderr)
        return 2

    root = Path(argv[0]) if argv else Path.cwd()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    try:
        problems = check(root, include_writing=not structure_only)
    except (FileNotFoundError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"\ncheck-doc-manifest: {len(problems)} problem(s).", file=sys.stderr)
        return 1

    declared = load_manifest(root)
    verb = "accounted for" if structure_only else "validated"
    print(f"check-doc-manifest: ok ({len(declared)} canonical documents {verb}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
