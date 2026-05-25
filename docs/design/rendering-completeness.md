# Rendering completeness floor

This note defines the measurement contract for R10.2 and D17.9. It does not
change the pure-Rust rendering lock in D17.4: Chromium, headless browsers, and
C++ rendering fallbacks are not accepted runtime paths. Origins that fail native
rendering are native parity gaps.

## Corpus

Use the operator's top 1000 most-visited origins for the v1 corpus, measured by
session history after bot, test, and one-off redirected origins are removed.
Store the operator-specific, versioned list as an origin manifest, not shareable
browsing history.

Each corpus snapshot records:

- Snapshot identifier and capture date.
- Ranked origin list with visit count bucket, not exact raw history.
- Inclusion source: history, standing query, explicit operator pin, or prior
  regression case.
- Exclusion reason for filtered origins.
- Known-gap status when an origin is retained but not yet expected to pass.

The corpus refreshes before every release candidate and at least monthly during
active render-band work. Prior passing origins remain in the regression set even
if they fall out of the current top 1000.

## Capture protocol

Every origin run uses a deterministic protocol so failures are comparable across
time:

- Fresh session unless the test case explicitly declares stored state.
- Fixed viewport set: desktop default, narrow desktop, and reduced-height
  desktop.
- Fixed font pack, image decode support, locale, timezone, and color-scheme
  fixture.
- Network cache disabled for first capture; warm-cache rerun allowed only as
  secondary evidence.
- Per-origin wall-clock, request-count, memory, and CPU budgets.
- Script mode recorded as disabled, limited, or full D4 when that band exists.
- Capture timeout and final readiness signal recorded for every artifact.

External browser captures can be retained as comparison evidence, but they do
not create an accepted fallback path.

## Evidence artifacts

Each origin produces a structured evidence bundle:

- Run manifest: corpus snapshot, Dioptron build, capture protocol version, and
  resource budgets.
- Visual artifacts: screenshots for each viewport and any paint/compositing
  error overlays emitted by D3.
- Structural artifacts: parsed DOM summary, accessibility tree summary, and
  extracted text blocks when available.
- Network artifacts: request status summary, blocked request reasons, redirect
  chain, TLS errors, and resource timing.
- Script artifacts: console errors, unhandled exceptions, and D4 budget exits
  when script execution is enabled.
- Operator-visible notes: exact symptom, severity, reproduction steps, and
  whether the issue is native-rendering parity, D4 script coverage, network
  behavior, or site policy.

Evidence bundles are immutable once attached to a release-candidate run. New
runs supersede old bundles by reference instead of mutating them.

## Breakage severity

Score each rendering failure by operator-visible impact:

| Severity | Definition | Gate effect |
| --- | --- | --- |
| Blocker | Primary content, login, navigation, or critical interaction is unusable. | Fails v1 floor. |
| Major | Primary content is readable but a common task or a large page region is broken. | Fails v1 floor unless explicitly waived as a known gap. |
| Minor | Non-critical content, spacing, media, or secondary controls are wrong. | Tracked; does not fail alone. |
| Cosmetic | Small visual mismatch with no task impact. | Tracked only. |
| Known gap | Explicitly accepted native parity gap with owner and review date. | Excluded only for the named release gate. |

Unsupported origins must still keep evidence. They are not removed from the
corpus unless the origin itself is no longer in operator scope.

## V1 acceptance

Dioptron claims the R10.2/D17.9 v1 rendering floor only when:

- The current top-1000 corpus has a complete evidence run.
- No blocker breakage remains outside documented known gaps.
- No major breakage remains outside documented known gaps.
- Every known gap has a classification, owner, and next review date.
- Any prior passing origin that regresses to blocker or major fails the gate
  until fixed or explicitly waived.

Before release-candidate status, render-band branches can use a smaller
top-ranked smoke subset, but that subset is only a development gate. It cannot
be used to claim the v1 floor.
