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

## Status

Phase 01 implementation started on 2026-09-25. The Rust workspace under `crates/` holds five crates:

| Crate | Role |
|-------|------|
| `syntheke` | Capability contract: wire schema, identifiers, capabilities, outcomes |
| `epitrope` | Authorization: grant narrowing, validity, budgets |
| `phylake` | Custody store: encrypted, transactional persistence |
| `dioptron` | Daemon: orchestrator, producer seam, local socket server |
| `xenos` | Independent wire client for process-level tests |

The crates are skeletons until their implementation slices land. Web acquisition belongs to [Zetesis](docs/design/zetesis-acquisition-boundary.md), not to this workspace.

## Build

Toolchain 1.97.1 is pinned in `rust-toolchain.toml`. The local gate:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo test --workspace --doc --all-features
cargo deny check
```

## Tenancy

Operator and agents are peer users. Every capability exists once, consumed through the same Rust trait surface. The desktop UI is just another client  -  no more privileged than a nous agent making the same calls over a unix socket.

## Documentation

This is a curated, non-exhaustive start-here list. The
[documentation manifest](docs/MANIFEST.toml) is the exhaustive inventory.

- [docs/requirements.md](docs/requirements.md)  -  R1-R12 requirements
- [docs/design/topology.md](docs/design/topology.md)  -  Layer topology
- [docs/design/tenancy.md](docs/design/tenancy.md)  -  Multi-tenant model
- [docs/design/decisions.md](docs/design/decisions.md)  -  Resolved technical decisions
- [docs/design/rendering-completeness.md](docs/design/rendering-completeness.md)  -  D17.9 evidence floor
- [docs/design/script-band-evaluation.md](docs/design/script-band-evaluation.md)  -  D4 evaluation and v1 scope
- [docs/design/ingest-rules-taxonomy.md](docs/design/ingest-rules-taxonomy.md)  -  D7/D8 taxonomy and implementation plan
- [docs/design/training-data.md](docs/design/training-data.md)  -  Behavioral emission taxonomy
- [docs/lexicon.md](docs/lexicon.md)  -  Project name registry

## License

- Code and tooling: [PolyForm Noncommercial 1.0.0](LICENSE).
- Documentation: [CC BY-NC-ND 4.0](LICENSE-DOCS).

See [NOTICE](NOTICE) for supplemental terms.
