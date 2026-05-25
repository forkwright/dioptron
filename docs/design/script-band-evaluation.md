# Script-band evaluation

This note records the D4 evaluation contract and v1 scope decision. D4 is the
script band: sandboxed JavaScript execution, DOM interaction for dynamic content
extraction, a modern Web API surface, and resource budgets per execution
context.

## Scope decision

D4 is in v1 scope for dynamic extraction, but not as a prerequisite for the
first D2/D5/D7 implementation slices. The 2026-05-25 v1 product decision is
world-monitor plus first-order intelligence, so ingestion must eventually handle
scripted pages well enough to support scraping, aggregation, basic sentiment,
trend scoring, and akroasis hand-off.

The first v1 milestone can ship limited extraction for static HTML, PDFs, feeds,
and non-scripted pages. The v1 completion gate must include a D4 answer for
scripted content instead of treating no-JS extraction as the final state.

## Candidate classes

The engine evaluation compares three classes:

- `mozjs`: SpiderMonkey bindings in Rust.
- `rusty_v8`: V8 bindings in Rust.
- Limited/no-JS: static extraction plus declared dynamic-content gaps.

The limited/no-JS path is a phase option, not a complete D4 implementation. It
must emit evidence when content is missing because script execution was absent
or intentionally disabled.

## Evaluation criteria

Each candidate is scored against project requirements instead of generic engine
popularity:

| Criterion | Requirement pressure |
| --- | --- |
| Sovereignty | Runs locally, does not require cloud execution, and has reproducible build inputs. |
| Build surface | Fits the Rust workspace without taking over release cadence or forcing broad toolchain exceptions. |
| Sandboxability | Can run under per-context limits and process sandbox profiles compatible with landlock and seccomp. |
| Memory isolation | Supports hard budget exits and failure containment for untrusted origin code. |
| DOM binding cost | Can bind to Dioptron-owned DOM/render state without making D3 depend on a browser shell. |
| Web API coverage | Covers the APIs needed for common dynamic extraction paths before broad compatibility work. |
| Unsafe/vendor audit | Keeps unsafe and vendored code inside an auditable boundary with explicit update policy. |
| Maintenance cost | Has active maintenance, security update path, and realistic ownership for local patching. |

Chromium, headless browsers, and C++ rendering fallbacks are not candidates for
D4. A quarantined external browser may be used only as evidence to identify what
Dioptron failed to extract.

## Rejection criteria

A candidate is rejected for v1 if any of these are true:

- It requires an accepted runtime rendering fallback outside D3 native Rust.
- It cannot be sandboxed with deterministic termination for runaway script.
- It cannot preserve origin/session isolation at the same boundary as fetch,
  store, and rules evaluation.
- It makes dynamic extraction opaque to D7 provenance records.
- It requires unauditable remote execution or update flow.

## V1 output

The v1 D4 implementation decision must produce:

- Chosen candidate class and reasoned rejection of the others.
- Minimal Web API set required for scraping and aggregation.
- DOM interaction boundary between D3, D4, and D7.
- Per-context budgets and failure evidence schema.
- Tests that prove timeout, memory exit, session isolation, and missing-script
  evidence behavior.

Until that decision lands, D4 remains a tracked open design choice, but its
phase is v1, not post-v1.
