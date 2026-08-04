# Resolved Technical Decisions

## D17.1 Operations band sandboxing
Each verb runs in a dedicated process under landlock+seccomp with a verb-specific profile. Exploit-runner gets a dedicated network namespace with controlled egress through dioptron-net. MITM verb gets raw socket access scoped to operator-declared target interfaces only, rules engine evaluating every bind. Credential-test verb receives material as ephemeral handles from credential vault, never cleartext crossing process boundaries; handles auto-revoke on completion or revocation.

## D17.2 Knowledge tier read defaults
Default nous query posture: tier 1 first, tier 2 if insufficient confidence, tier 3 only on explicit request. Contradiction detection across tiers 1 and 2 by default; tier 3 cross-checking opt-in (raw captures produce contradiction floods). Source reputation weighted by tier.

## D17.3 Identity layer distribution sourcing
Initial corpus from public fingerprint datasets (Mozilla, EFF Panopticlick, academic crawls). Refresh via akroasis passive observation when integrated. Distributions versioned and auditable. Unknown fingerprint properties: rules engine surfaces request, falls back to synthesized plausible value with audit flag.

Anonymity-set floor (R5.2/D17.13) is recomputed against this corpus at every refresh, not set independently — see `docs/design/fingerprint-unlinkability.md`.

## D17.4 Pure-Rust rendering lock
Dioptron does not use Chromium, headless browsers, or C++ rendering fallbacks. Native Rust rendering through the D3 render band is the only supported render path. Origins that fail to render are tracked as native-rendering coverage gaps and native parity work, not fallback candidates.

## D17.5 Standing query economics
Standing queries declare fetch budget and schedule. Rules engine and cost accounting enforce both. Fetches jittered across plausible browsing patterns. Akroasis posture gates when integrated. Warning when pattern crosses fingerprinting threshold.

## D17.6 Plegma session sync
Sessions sync across plegma peers in operator's device set. CRDT conflict resolution: both forks persist on rejoin, operator chooses merge or separate. Forking-while-synced creates new lineage with provenance.

## D17.7 Audit partition access
Audit partition read-restricted: operator has full read via desktop UI. Agents/sub-agents read only their own facts or facts from owned sessions. Rules cannot read audit during evaluation (prevents side channel). Audit reads through explicit operator-initiated query path.

## D17.8 Update mechanism
Engine band: slow cadence, reproducible builds, operator-initiated. Operations band: faster cadence (CT rules, fingerprint distributions, tracker rulesets, verb patches), same signing infrastructure, applied without engine restart. Rollback per-band and atomic.

## D17.9 Rendering completeness floor
v1: renders operator's top-1000 most-visited origins without operator-visible breakage. Measurable, testable, operator-specific.

Measurement contract: `docs/design/rendering-completeness.md`.

## D17.10 Capability grant ceremony
Grants authored as rules. First-contact requests surface as notification with pre-drafted rule. Desktop UI has dedicated grants surface. No modal prompts.

## D17.11 Credential vault interim
Proton Pass bridge is interim (acknowledged sovereignty leak). Clean-room vault prioritized. Until then: audit logging on every access, per-origin grant requirement.

## D17.12 Multi-operator scope
Single-operator. Family members get own instances. Peer-tenant model is for human + agents, not multiple humans.

## D17.13 Fingerprint unlinkability floor
v1: cross-session joint fingerprint (egress, DNS, TLS, HTTP, JavaScript surface, fonts, locale, clock, storage) for a stated web-origin adversary sits in a measured anonymity set no smaller than the current floor, recomputed against the D17.3 distribution corpus at every refresh. Measurable, testable, adversary-scoped.

Measurement contract: `docs/design/fingerprint-unlinkability.md`.
