# Dioptron

> δίοπτρον (dia + opt + ron): the instrument through which one sees

Local web runtime with agent co-tenancy. Operator and AI agents are peer users of the same capability surface  -  browsing, ingesting, querying, and acting on the web through a unified programmatic interface.

## Architecture

Three bands across eleven layers, plus a cross-cutting tenancy plane:

| Band | Layers | Purpose |
|------|--------|---------|
| **Engine** | net, render, script, store, identity | Core web engine |
| **Instrument** | ingest, rules, session, ui | Knowledge acquisition |
| **Operations** | ops | Active capability surface |
| **Cross-cutting** | tenancy | Tenant identity, grants, delegation, canonical interface |

## Tenancy

Operator and agents are peer users. Every capability exists once, consumed through the same Rust trait surface. The desktop UI is just another client  -  no more privileged than a nous agent making the same calls over a unix socket.

## Documentation

Full inventory: [docs/MANIFEST.toml](docs/MANIFEST.toml) (CI-enforced against every doc under `docs/**/*.md` by `ci/check-doc-manifest.py`).

- [docs/requirements.md](docs/requirements.md)  -  R1-R12 requirements
- [docs/design/vision.md](docs/design/vision.md)  -  Dual-audience vision: operator sovereign browser and nous-agent web capability surface
- [docs/design/topology.md](docs/design/topology.md)  -  Layer topology
- [docs/design/tenancy.md](docs/design/tenancy.md)  -  Multi-tenant model
- [docs/design/decisions.md](docs/design/decisions.md)  -  Resolved technical decisions
- [docs/design/rendering-completeness.md](docs/design/rendering-completeness.md)  -  D17.9 evidence floor
- [docs/design/script-band-evaluation.md](docs/design/script-band-evaluation.md)  -  D4 evaluation and v1 scope
- [docs/design/ingest-rules-taxonomy.md](docs/design/ingest-rules-taxonomy.md)  -  D7/D8 taxonomy and implementation plan
- [docs/design/fingerprint-unlinkability.md](docs/design/fingerprint-unlinkability.md)  -  R5.2/D17.13 anonymity-set floor against a web-origin adversary
- [docs/design/training-data.md](docs/design/training-data.md)  -  Behavioral emission taxonomy
- [docs/lexicon.md](docs/lexicon.md)  -  Project name registry

## License

AGPL-3.0-or-later. See [NOTICE](NOTICE) for supplemental terms.
