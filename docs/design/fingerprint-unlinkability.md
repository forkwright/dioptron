# Fingerprint unlinkability floor

This note defines the measurement contract for R5.2 and D17.13. Independent
marginal-distribution synthesis (D17.3) and optional Tor routing (R7.1) are
necessary but not sufficient on their own: an adversary correlating joint
behavior across layers can form a globally rare, or internally implausible,
combination even when every individual attribute is independently
population-plausible. The floor below is scoped, versioned, and measured
rather than asserted as an absolute guarantee.

## Adversary and scope

The claim is scoped to a **web-origin observer**: a site, or a third party it
shares data with, observing one client through standard web APIs and passive
network metadata for that origin's own traffic. In scope for this observer:

- User-Agent/OS surface and HTTP header ordering and values.
- TLS and HTTP handshake signatures (JA3/JA4, ALPN, header-frame ordering).
- JavaScript-exposed surfaces: canvas/WebGL/AudioContext, font enumeration,
  screen/viewport, timezone, locale, hardware concurrency, storage APIs.
- Clock and timing behavior observable from script execution and network
  round-trips.
- DNS and egress IP/ASN for that origin's own resolution and connections.

Linkers outside this observer's reach are handled separately — see
"Explicitly out of scope" below.

## Baseline and metric

The floor is an anonymity-set size, not a binary linkable/unlinkable
verdict:

    min anonymity-set size >= N, measured against the current D17.3
    distribution corpus

A captured session's full joint fingerprint (every in-scope layer combined)
is linkable under this adversary when it falls outside every other member's
anonymity set of size >= N in the same measurement run.

N is not a fixed constant chosen in advance: it is the largest k for which
the current D17.3 distribution corpus has at least k plausible population
members sharing the synthesized joint profile's bucket. N is recomputed at
every corpus refresh (D17.8's fingerprint-distribution channel) and versioned
alongside the corpus it was measured against, so the declared floor and the
generation mechanism share one ground truth.

## Versioned whole-client profiles

Per-session identity is generated as one coherent profile, not sampled
independently per layer: egress/ASN posture, DNS resolver behavior,
TLS/JA3-4, HTTP header set, JavaScript-exposed surfaces, font list, locale,
clock skew, and storage posture are drawn together from the same
population-cluster sample, so the joint combination stays population-
plausible and not merely each marginal in isolation. Profiles carry the
distribution-corpus version (D17.3) they were sampled from.

## Measurement protocol

- **Repeated-session experiment.** Synthesize N sessions against the current
  population corpus, submit them through the full capture path (D2 net, D3
  render, D6 identity), and collect fingerprints the way an external
  web-origin adversary would observe them — not read back from internal
  state.
- **Cross-layer consistency check.** Flag any generated profile whose layers
  are individually plausible but jointly rare (e.g., a UA/OS pairing with a
  TLS stack the population data never pairs with it).
- **Anonymity-set measurement.** For each captured joint fingerprint, compute
  set size against the reference population plus the batch's own synthesized
  sessions; record the run's minimum.
- **Regression gate.** A release whose measured minimum anonymity-set size
  drops below the declared floor fails the acceptance gate the same way a
  rendering-floor regression fails D17.9's gate (`rendering-completeness.md`).

## Explicitly out of scope

These linkers are not addressed by this floor. Each is mitigated, if at all,
by a separate, named mechanism:

- **Account identity.** Logging into an origin-recognized account links
  sessions by design; no fingerprint defense claims to prevent this.
- **IP/network reuse without Tor.** R7.1 makes Tor optional. When disabled,
  egress IP reuse across sessions is a linker this floor does not cover.
- **Behavioral linkage.** Typing cadence, navigation pattern, and content
  interaction are not measured here; cover-traffic generation (R7.7) is a
  separate, partial mitigation, not a guarantee.
- **External storage/state linkage.** Cookies, cache, and local storage are
  session-isolated per R5.3, but an origin colluding with a third party that
  holds cross-session state outside dioptron's control is out of scope.
- **Global passive network adversary.** An adversary correlating traffic
  across many origins or ASes at once — not just the origin being visited —
  is out of scope for this floor. Tor (R7.1), when enabled, is the mitigation
  path for that threat class; this measurement does not claim to cover it.

## V1 acceptance

Dioptron claims the R5.2/D17.13 v1 unlinkability floor only when:

- The measurement protocol has run against the current D17.3 distribution
  corpus and the N it produced.
- The measured minimum anonymity-set size meets or exceeds the declared
  floor N for that release.
- Every out-of-scope linker above is stated in operator-facing privacy copy,
  not silently implied as covered.
- Any prior passing measurement run that regresses below N fails the gate
  until fixed, or the floor is explicitly revised with a corpus-backed
  rationale.
