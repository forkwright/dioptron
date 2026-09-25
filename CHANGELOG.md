# Changelog

## [0.1.7](https://github.com/forkwright/dioptron/compare/v0.1.6...v0.1.7) (2026-09-25)


### Features

* **dioptron:** orchestrate invocations and ship the daemon binary ([#90](https://github.com/forkwright/dioptron/issues/90)) ([b4f093f](https://github.com/forkwright/dioptron/commit/b4f093fec4b6dbac830cf48f6603a9485599f796))
* **dioptron:** serve the capability contract over a Unix socket ([#87](https://github.com/forkwright/dioptron/issues/87)) ([e0fa501](https://github.com/forkwright/dioptron/commit/e0fa501aa0a4abc5ccf0e0464c66132d5370e1c3))
* **epitrope:** implement grant narrowing, validity, budgets and lifecycle ([#86](https://github.com/forkwright/dioptron/issues/86)) ([b7d63b3](https://github.com/forkwright/dioptron/commit/b7d63b355e75c9cbc0f39db379e3393a3a444394))
* **infra:** bootstrap the Rust workspace, CI and implementation kickoff ([#78](https://github.com/forkwright/dioptron/issues/78)) ([d25375f](https://github.com/forkwright/dioptron/commit/d25375f721abd489ba775bbce9175992b3bd5bb6))
* **phylake:** add root key file and at-rest sealing primitives ([#81](https://github.com/forkwright/dioptron/issues/81)) ([a49f36f](https://github.com/forkwright/dioptron/commit/a49f36f7ff1179a2b7fb43cc848c06a6338a55f1)), closes [#35](https://github.com/forkwright/dioptron/issues/35)
* **phylake:** add the custody store with B1–B5 transactions and recovery ([#88](https://github.com/forkwright/dioptron/issues/88)) ([a5acfb1](https://github.com/forkwright/dioptron/commit/a5acfb1ca90fc894d6248c08e54d0fb34b32d478))
* **phylake:** rotate root and tenant keys, crypto-shred, and verify restores ([#89](https://github.com/forkwright/dioptron/issues/89)) ([6f24dd6](https://github.com/forkwright/dioptron/commit/6f24dd6e8e6c1dc2dd46056523dd5cb34a9142c7))
* **syntheke:** implement the Phase 01 capability contract types ([#82](https://github.com/forkwright/dioptron/issues/82)) ([ef044ff](https://github.com/forkwright/dioptron/commit/ef044ff6f5ffe97c81c83e027f01f3f874e9985b))
* **xenos:** implement the independent wire client ([#83](https://github.com/forkwright/dioptron/issues/83)) ([58d1712](https://github.com/forkwright/dioptron/commit/58d17128e0e6f4e11686cf32848d32eb2dc71a91))


### Bug Fixes

* **syntheke:** reject non-canonical frame bodies ([#84](https://github.com/forkwright/dioptron/issues/84)) ([0dbc4af](https://github.com/forkwright/dioptron/commit/0dbc4afe586143104d1fdcc0243304423a9360ff))

## [0.1.6](https://github.com/forkwright/dioptron/compare/v0.1.5...v0.1.6) (2026-09-03)


### Bug Fixes

* **infra:** adopt honest hybrid gate ([#70](https://github.com/forkwright/dioptron/issues/70)) ([8b3fbe8](https://github.com/forkwright/dioptron/commit/8b3fbe8b7c34355498a26f6870b6ac5235a29738))
* **infra:** make GitHub the honest authority ([#73](https://github.com/forkwright/dioptron/issues/73)) ([9a9b73a](https://github.com/forkwright/dioptron/commit/9a9b73aa27dac2dc41dd8874e1ab61d77c852f19))

## [0.1.5](https://github.com/forkwright/dioptron/compare/v0.1.4...v0.1.5) (2026-08-09)


### Bug Fixes

* **docs:** drop identity-fluff wording and a stale MANIFEST.toml citation ([#56](https://github.com/forkwright/dioptron/issues/56)) ([d5fc4bd](https://github.com/forkwright/dioptron/commit/d5fc4bd3357c9587b0f702fd0402fe327a881322))

## [0.1.4](https://github.com/forkwright/dioptron/compare/v0.1.3...v0.1.4) (2026-08-04)


### Bug Fixes

* **docs:** replace the absolute fingerprint unlinkability claim with a measurable threat model ([#51](https://github.com/forkwright/dioptron/issues/51)) ([d77aa59](https://github.com/forkwright/dioptron/commit/d77aa599b4e35cce964ea96d66cbb1941c12642f))

## [0.1.3](https://github.com/forkwright/dioptron/compare/v0.1.2...v0.1.3) (2026-08-03)


### Bug Fixes

* **ci:** derive the docs-phase validation set from the document manifest ([#49](https://github.com/forkwright/dioptron/issues/49)) ([bd2e0bc](https://github.com/forkwright/dioptron/commit/bd2e0bce92a8012b6d5e135e1de6a5fa527d5981)), closes [#41](https://github.com/forkwright/dioptron/issues/41)

## [0.1.2](https://github.com/forkwright/dioptron/compare/v0.1.1...v0.1.2) (2026-07-29)


### Bug Fixes

* **docs:** rendering-completeness floor cites D17.9 only, not R10.2 ([#47](https://github.com/forkwright/dioptron/issues/47)) ([74f6622](https://github.com/forkwright/dioptron/commit/74f66220f18283073728b13f0a9ab35aa89b4c22))

## [0.1.1](https://github.com/forkwright/dioptron/compare/v0.1.0...v0.1.1) (2026-07-28)


### Features

* **_llm:** add T0 corpus per [#667](https://github.com/forkwright/dioptron/issues/667) / [#673](https://github.com/forkwright/dioptron/issues/673) fleet rollout ([#5](https://github.com/forkwright/dioptron/issues/5)) ([8727e58](https://github.com/forkwright/dioptron/commit/8727e5852a98bdd8ad2f1e22e81bdbb29921b21a))


### Bug Fixes

* **ci:** add SLSA provenance + CycloneDX SBOM attestation to release-please ([#30](https://github.com/forkwright/dioptron/issues/30)) ([2d906f0](https://github.com/forkwright/dioptron/commit/2d906f0fd3309ab3c2c017de23cc8105a1be0d0d))
* **ci:** inline release-please + gate-attestation, drop broken reusable-workflow indirection ([#29](https://github.com/forkwright/dioptron/issues/29)) ([f892bd3](https://github.com/forkwright/dioptron/commit/f892bd34b5947f11bd65f621baafd70e5150debe))
* **ci:** waive gate attestation by PR author shape, not by bot-login list ([#45](https://github.com/forkwright/dioptron/issues/45)) ([c9f9355](https://github.com/forkwright/dioptron/commit/c9f9355a85538dbc54d3fd30683b489cc8b46be4)), closes [#44](https://github.com/forkwright/dioptron/issues/44)
* **lint:** clear all kanon lint warnings ([#24](https://github.com/forkwright/dioptron/issues/24)) ([7869723](https://github.com/forkwright/dioptron/commit/7869723a9e90c8e35931bb56ab4124d8ab357db7))

## Changelog
