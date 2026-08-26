# D7/D8 ingest and rules taxonomy

This note consolidates the D7 ingest and D8 rules design input into one
Rust-native taxonomy and implementation plan. External JavaScript or Playwright
material is design evidence only; Dioptron owns the taxonomy, classifiers,
provenance records, and tests.

## Design boundary

D7 converts captures into structured knowledge candidates. D8 decides whether
runtime behavior is authorized and records rule facts that explain those
decisions. The boundary between them is evidence: D7 emits typed evidence
records; D8 consumes evidence records when rules need page, tenant, grant,
budget, or drift context.

For anonymous static acquisition, the source capture is the verbatim Zetesis
evidence envelope defined by the
[static acquisition boundary](zetesis-acquisition-boundary.md). D7 owns
Dioptron classification and knowledge semantics after that handoff. It does not
repeat target validation, redirects, HTTP, decompression, static extraction, or
envelope construction.

D7 and D8 must not share ad hoc strings. Classifiers emit typed labels with
confidence, provenance, source artifact references, and contradiction links.
Rules consume those typed labels through schema-versioned facts.

## D7 taxonomy

D7 emits these first-class record families:

| Family | Purpose |
| --- | --- |
| Visual property artifact | Captures layout, visibility, prominence, viewport position, media state, and accessibility summary for page regions. |
| Page intent | Classifies the page as article, product, search result, dashboard, login, checkout, feed, documentation, forum, error page, or unknown. |
| Section role | Labels regions such as navigation, main content, sidebar, comments, related links, form, modal, paywall, and advertisement. |
| Component anatomy | Describes repeated components: card, table, list item, result row, product tile, form field, button, media block, and chart. |
| Content claim | Extracted text or structured data with source span, timestamp, author/date metadata, and confidence. |
| Contradiction evidence | Links a new claim to an existing fact or claim with the conflict field, comparison basis, and proposed resolution path. |
| Promotion event | Records movement between tier 3 raw capture, tier 2 extracted fact, and tier 1 verified knowledge. |
| Standing-query observation | Records scheduled fetch outcome, changed fields, missing fields, and drift against the standing query's expected shape. |

Every record references the immutable source artifact and capture protocol. No
classifier output may be promoted without a provenance chain back to source
bytes, visual evidence, or both.

## Classifier contract

Each classifier declares:

- Input artifact types and required preprocessing.
- Output record family and schema version.
- Confidence scale and abstain behavior.
- Evidence pointers needed to reproduce or inspect the label.
- Contradiction behavior when a new label conflicts with an older label.
- Privacy class and retention default for emitted training data.

Classifiers must be able to say "unknown" without fabricating a label. An
unknown label is retained when it changes rule behavior, extraction quality, or
standing-query drift detection.

## Evidence patterns

D7 and D8 share these evidence patterns:

- Evidence-as-output fingerprint: every extraction emits a compact fingerprint
  of the source fields and classifier path so later runs can detect silent
  changes.
- Demote when overshadowed: a fact loses promotion priority when a newer,
  higher-confidence, or operator-verified fact contradicts it.
- Multi-route consistency diff: the same fact reached through fetch, feed,
  archive, or repeated route is compared before promotion.
- Standing-query drift: recurring queries compare expected page intent, section
  roles, and content-claim fields over time.
- Operator correction loop: operator edits, overrides, and rule decisions become
  labeled evidence for classifier calibration.

## D8 fact schemas

D8 rules consume typed facts in these groups:

| Fact group | Examples |
| --- | --- |
| Tenant | tenant class, tenant id, delegation depth, session owner, read/write role |
| Grant | allowed verb, target scope, expiration, revocation behavior, rule chain |
| Budget | fetch count, standing-query cadence, CPU, memory, network, token budget |
| Page evidence | page intent, section role, component anatomy, contradiction state, drift state |
| Proposal | requested rule, proposing tenant, evidence bundle, operator decision |
| Handoff | source tenant, destination tenant, session lineage, granted scope |
| Operation | verb, target, sandbox profile, credential handle use, audit reference |

Rules must record both the facts they consumed and the decision they produced.
That trace becomes part of the audit partition and the training-data taxonomy.

## Implementation plan

Phase 1 establishes schemas before classifier complexity:

- Define Rust enums and serialized schema versions for D7 record families and
  D8 fact groups.
- Add fixture captures that prove provenance, contradiction links, and unknown
  classifier behavior.
- Add golden tests for page-intent and section-role records on hand-authored
  HTML fixtures.
- Add rule-fact tests showing tenant/grant/budget/page evidence consumption.

Phase 2 adds extraction breadth:

- Implement component anatomy records for lists, tables, forms, cards, and
  result rows.
- Add standing-query observation records and drift diffs.
- Add tier-promotion events and demotion on contradiction.

Phase 3 connects v1 intelligence:

- Feed content claims, standing-query drift, and operator corrections into the
  first-order sentiment and trend scoring layer.
- Emit training-data records matching the schema governance rules in
  `docs/design/training-data.md`.
- Keep raw corpus output and scored output separately consumable for akroasis
  hand-off.
