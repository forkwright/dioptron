#!/usr/bin/env python3
"""check-doc-refs — verify R<n>/D<n> cross-references resolve to a matching subject.

Usage:
    ci/check-doc-refs.py [repo-root]

Dioptron's docs carry a numbered-identifier scheme: R<n>[.<m>] requirements
(docs/requirements.md), D17.<n> resolved decisions (docs/design/decisions.md),
and bare D<n> topology layers (docs/design/topology.md). Every other doc cites
these by number. A citation can go stale two ways: the number stops existing
(typo, or the section was removed/renumbered), or the number still exists but
now names something else (a sibling section absorbed it, or the citing prose
was never correct to begin with — see docs/design/rendering-completeness.md's
former "R10.2" citations, which pointed at the operator-facing-GUI requirement
while describing the rendering floor).

This script builds the canonical identifier -> subject map from the three
source-of-truth docs, then scans every tracked Markdown file for identifier
occurrences and checks two things:

1. Existence: the cited identifier is actually defined somewhere.
2. Subject match: when the citation carries its own descriptive gloss (the
   common patterns in this repo are "<phrase> (R10.2)" and "R9.7 <phrase>"),
   the gloss shares at least one non-stopword with the identifier's real
   subject. A zero-overlap citation is exactly the class of bug this script
   exists to catch — the gloss and the definition are talking about two
   different things.

Output:
    One line per problem, prefixed `dangling:` or `mismatch:`, to stderr.

Exit codes:
    0 — every citation resolves and matches
    1 — at least one dangling reference or subject mismatch
    2 — invocation error (bad root, missing source docs)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

STOPWORDS = {
    "a", "an", "and", "any", "are", "as", "at", "be", "by", "can", "do",
    "does", "for", "from", "has", "have", "in", "is", "it", "its", "no",
    "not", "of", "on", "or", "over", "per", "so", "than", "that", "the",
    "their", "this", "to", "v1", "was", "were", "when", "which", "with",
    "without",
}

# WHY: these three files are the single source of truth for what each
# identifier means; every other doc only cites them.
SOURCE_FILES = {
    "R": "docs/requirements.md",
    "D17": "docs/design/decisions.md",
    "DLAYER": "docs/design/topology.md",
}

R_HEADER_RE = re.compile(r"^##\s+R(\d+)\.\s+(.+)$")
R_ITEM_RE = re.compile(r"^R(\d+\.\d+)\s+(.+)$")
D17_HEADER_RE = re.compile(r"^##\s+D17\.(\d+)\s+(.+)$")
DLAYER_HEADER_RE = re.compile(r"^###\s+D(\d+)\.\s+(.+)$")

# Citation patterns worth subject-checking: a descriptive gloss immediately
# adjacent to the identifier. Bare identifiers with no adjacent prose (plain
# ranges like "R1-R12", glob refs like "D17.*") are existence-checked only.
GLOSS_BEFORE_RE = re.compile(r"([A-Za-z][A-Za-z '\-]{3,80})\(\s*(R\d+(?:\.\d+)?|D\d+(?:\.\d+)?)\s*\)")
GLOSS_AFTER_RE = re.compile(r"(?:^|\n)\s*(R\d+\.\d+|D\d+\.\d+)\s+([A-Za-z][A-Za-z '\-]{3,120}?)[.\n]")

BARE_REF_RE = re.compile(r"\bR\d+(?:\.\d+)?\b|\bD\d+(?:\.\d+)?\b")

# WHY: covers "R10.2 and D17.9" / "R10.2/D17.9" — a requirement cited
# alongside its resolving decision, sharing the sentence as their joint
# gloss. Deliberately scoped to R+D17 pairs only: D-layer-to-D-layer
# enumerations ("D2/D5/D7", "D3, D4, and D7") are pervasive, benign
# architecture cross-references in this repo that rarely restate either
# layer's subject, and would swamp this check with false positives.
JOINED_IDS_RE = re.compile(
    r"\b(R\d+\.\d+)\s*(?:/|,?\s+and\s+)\s*(D17\.\d+)\b"
    r"|\b(D17\.\d+)\s*(?:/|,?\s+and\s+)\s*(R\d+\.\d+)\b"
)

# WHY: a literal period followed by whitespace/EOF is always a true sentence
# boundary in this corpus — identifier-internal periods (R10.2, D17.9) are
# always digit-adjacent with no following whitespace, so they never trigger
# a false split.
SENTENCE_END_RE = re.compile(r"\.(?=\s|$)")

# WHY: ranges ("R1-R12", "Q2-Q5") and glob refs ("D17.*") name a whole
# document/section, not one identifier — never subject-checked, and only
# existence-checked at the endpoints via the normal single-token scan
# elsewhere in the same file.
RANGE_CONTEXT_RE = re.compile(r"\b[RD]\d+(?:\.\d+)?\s*-\s*[RD]?\d+(?:\.\d+)?\b|\bD\d+\.\*")


def tokenize(text: str) -> set[str]:
    words = re.findall(r"[a-z]+", text.lower())
    return {w for w in words if w not in STOPWORDS and len(w) > 2}


SECTION_HEADER_RE = re.compile(r"^#{1,6}\s+")


def load_r_subjects(root: Path) -> dict[str, str]:
    # WHY: full line text (not truncated at the first period) so a subject
    # like R2.5's trailing "co-tenant in real time" clause is matchable.
    path = root / SOURCE_FILES["R"]
    subjects: dict[str, str] = {}
    current_top: str | None = None
    current_top_body: list[str] = []
    for line in path.read_text().splitlines():
        m = R_HEADER_RE.match(line)
        if m:
            if current_top is not None:
                subjects[f"R{current_top}"] += " " + " ".join(current_top_body)
            current_top = m.group(1)
            subjects[f"R{current_top}"] = m.group(2)
            current_top_body = []
            continue
        m = R_ITEM_RE.match(line)
        if m:
            subjects[f"R{m.group(1)}"] = m.group(2)
            current_top_body.append(m.group(2))
        elif current_top is not None and line.strip() and not SECTION_HEADER_RE.match(line):
            current_top_body.append(line.strip())
    if current_top is not None:
        subjects[f"R{current_top}"] += " " + " ".join(current_top_body)
    return subjects


def _load_headed_subjects(path: Path, header_re: re.Pattern, prefix: str) -> dict[str, str]:
    # WHY: subject = heading title plus every body line until the next
    # heading, so a body-only mention (e.g. D12's "canonical programmatic
    # interface" bullet) still counts toward the match.
    subjects: dict[str, str] = {}
    current_key: str | None = None
    for line in path.read_text().splitlines():
        m = header_re.match(line)
        if m:
            current_key = f"{prefix}{m.group(1)}"
            subjects[current_key] = m.group(2)
            continue
        if SECTION_HEADER_RE.match(line):
            # WHY: an unrelated heading (e.g. topology.md's band headers
            # between layer sections) ends the current section's body span.
            current_key = None
            continue
        if current_key is not None and line.strip():
            subjects[current_key] += " " + line.strip()
    return subjects


def load_d17_subjects(root: Path) -> dict[str, str]:
    return _load_headed_subjects(root / SOURCE_FILES["D17"], D17_HEADER_RE, "D17.")


def load_dlayer_subjects(root: Path) -> dict[str, str]:
    return _load_headed_subjects(root / SOURCE_FILES["DLAYER"], DLAYER_HEADER_RE, "D")


def resolve(identifier: str, r_subjects: dict, d17_subjects: dict, dlayer_subjects: dict) -> str | None:
    if identifier.startswith("R"):
        if identifier in r_subjects:
            return r_subjects[identifier]
        # WHY: an R<n>.<m> item not individually headered still belongs to
        # its top-level R<n> section (e.g. R2.1 lives under "## R2").
        top = identifier.split(".")[0]
        return r_subjects.get(top)
    if identifier.startswith("D17."):
        return d17_subjects.get(identifier)
    if re.fullmatch(r"D\d+", identifier):
        return dlayer_subjects.get(identifier)
    return None


def sentence_at(text: str, pos: int) -> str:
    """Return the sentence containing `pos` (see SENTENCE_END_RE for the boundary rule)."""
    start = 0
    for m in SENTENCE_END_RE.finditer(text, 0, pos):
        start = m.end()
    end_match = SENTENCE_END_RE.search(text, pos)
    end = end_match.end() if end_match else len(text)
    return text[start:end]


def find_citations(text: str) -> list[tuple[str, str, int]]:
    """Return (identifier, gloss, position) triples for citations carrying adjacent prose."""
    found = []
    for m in GLOSS_BEFORE_RE.finditer(text):
        gloss, ident = m.group(1), m.group(2)
        found.append((ident, gloss, m.start()))
    for m in GLOSS_AFTER_RE.finditer(text):
        ident, gloss = m.group(1), m.group(2)
        found.append((ident, gloss, m.start()))
    for m in JOINED_IDS_RE.finditer(text):
        gloss = sentence_at(text, m.start())
        for ident in m.groups():
            if ident is not None:
                found.append((ident, gloss, m.start()))
    return found


def enclosing_heading(text: str, pos: int) -> str:
    """Return the nearest Markdown heading text at or before `pos`."""
    heading = ""
    for m in re.finditer(r"^#{1,6}\s+(.+)$", text, flags=re.MULTILINE):
        if m.start() > pos:
            break
        heading = m.group(1)
    return heading


def all_bare_refs(text: str) -> list[str]:
    # WHY: strip range/glob spans first so their endpoints aren't treated as
    # single-identifier citations requiring subject match.
    stripped = RANGE_CONTEXT_RE.sub(" ", text)
    return BARE_REF_RE.findall(stripped)


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    for rel in SOURCE_FILES.values():
        if not (root / rel).is_file():
            print(f"error: missing source doc {rel}", file=sys.stderr)
            return 2

    r_subjects = load_r_subjects(root)
    d17_subjects = load_d17_subjects(root)
    dlayer_subjects = load_dlayer_subjects(root)

    problems: list[str] = []
    md_files = sorted(root.rglob("*.md"))
    md_files = [p for p in md_files if ".git" not in p.parts]

    for path in md_files:
        rel = path.relative_to(root)
        text = path.read_text()

        for ident in sorted(set(all_bare_refs(text))):
            if resolve(ident, r_subjects, d17_subjects, dlayer_subjects) is None:
                problems.append(f"dangling: {rel}: {ident} has no matching definition")

        for ident, gloss, pos in find_citations(text):
            subject = resolve(ident, r_subjects, d17_subjects, dlayer_subjects)
            if subject is None:
                continue  # already reported as dangling above
            # WHY: a citation's gloss is often deictic ("requires the
            # capability") rather than a restatement — the enclosing
            # heading usually carries the actual subject the prose is
            # elaborating, so it is always in play alongside the gloss
            # itself, not just as a fallback for empty glosses.
            gloss_tokens = tokenize(gloss) | tokenize(enclosing_heading(text, pos))
            subject_tokens = tokenize(subject)
            if gloss_tokens and subject_tokens and gloss_tokens.isdisjoint(subject_tokens):
                problems.append(
                    f"mismatch: {rel}: {ident} cited as '{gloss.strip()}' "
                    f"but is defined as '{subject.strip()}'"
                )

    if problems:
        for p in sorted(set(problems)):
            print(p, file=sys.stderr)
        print(f"\ncheck-doc-refs: {len(set(problems))} problem(s).", file=sys.stderr)
        return 1

    print(f"check-doc-refs: ok ({len(md_files)} files scanned).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
