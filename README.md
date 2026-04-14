# Dioptron

> δίοπτρον (dia + opt + ron): the instrument through which one sees

Sovereign web runtime with agent co-tenancy. Local web substrate where operator and AI agents are peer users of the same capability surface  -  browsing, ingesting, querying, and acting on the web through a unified programmatic interface.

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

- [docs/requirements.md](docs/requirements.md)  -  R1-R12 requirements
- [docs/design/topology.md](docs/design/topology.md)  -  Layer topology
- [docs/design/tenancy.md](docs/design/tenancy.md)  -  Multi-tenant model
- [docs/design/decisions.md](docs/design/decisions.md)  -  Resolved technical decisions
- [docs/design/training-data.md](docs/design/training-data.md)  -  Behavioral emission taxonomy
- [docs/lexicon.md](docs/lexicon.md)  -  Project name registry

## License

AGPL-3.0-or-later. See [NOTICE](NOTICE) for supplemental terms.
