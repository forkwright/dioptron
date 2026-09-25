# Lexicon  -  Dioptron

| Name | Greek | Meaning | Layer test |
|------|-------|---------|------------|
| **Dioptron** | δίοπτρον (dia + opt + ron) | Instrument for seeing through | L1: web runtime. L2: the layer between operator and web. L3: makes the opaque transparent  -  TLS introspection, fingerprint defense, knowledge extraction. L4: the system itself is an act of seeing-through at every layer. |

## Crate names

Proposed for the Phase 01 capability and custody stack, pending operator naming
review. Each name is constructed and tested per
`kanon/crates/basanos/standards/GNOMON.md`: the essential nature the crate
serves, not the mechanism it happens to use.

| Name | Greek | Meaning | Essential nature |
|------|-------|---------|------------------|
| **syntheke** | συνθήκη (syn + tithemi) | agreement, compact, convention | The contract every tenant and consumer agrees to before speaking: wire schema, identifiers, capability and outcome vocabulary, protocol constants. It is the agreement itself, not the parties. |
| **epitrope** | ἐπιτροπή (epi + trepo) | commission, entrusted authority, guardianship | The entrusted authority: grant narrowing, delegation-chain validity, budget reservation, invocation transitions. It decides what a tenant may do with what it was entrusted, holding no state and touching no wire. |
| **phylake** | φυλακή (phylasso) | keeping, guard, safekeeping | The custody layer: durable safekeeping of captures, records, and keys under encryption. It keeps what was acquired, and keeps it sealed. |
| **dioptron** (daemon) | δίοπτρον (dia + opt + ron) | instrument for seeing through | The runtime daemon that composes the others into the seeing-through instrument: orchestration, the producer seam, the local socket surface. It shares the project name because it is the project's running form. |
| **xenos** | ξένος | stranger, guest bound by hospitality | The independent client that arrives from outside the trust boundary and is bound by the handshake before it is heard. Its separateness is the point: it links only the contract, proving the contract stands on its own. |

### Naming notes

- **syntheke and the `theke` hub word.** συνθήκη derives from συντίθημι (syn +
  tithemi, "to put together" into an agreement), a distinct word from θήκη
  ("case, receptacle"), the fleet hub word registered in
  `kanon/crates/basanos/standards/hub-words.toml` for the kanon and aletheia
  vaults. The meanings do not collide: an agreement is not a receptacle, and no
  fleet component named for storage or a vault carries the sense syntheke does.
  `grep syntheke` returns only this crate. The substring overlap is the one
  residual cost the name pays, and it is a documented lint interaction, not a
  semantic collision: when the workspace lands, register the crate under the
  `theke` entry's distinct concepts so `VOCAB/crate-name-collision` accepts it.
  Fallback if operator review or the lint rejects syntheke: **homologia**
  (ὁμολογία, "accord, agreement in the same terms").
- **phylake fallback:** **tamieion** (ταμιεῖον, "storeroom, treasury"), if
  operator review prefers the storeroom sense over the guarding sense.
- Suffix discipline (GNOMON): syntheke, epitrope, phylake, homologia all take
  -η/-ή abstract-practice or result suffixes; dioptron keeps its -ον instrument
  suffix; xenos is a bare noun naming the outsider role.

## Name decision record

**Dioptron** selected 2026-04-13. Candidates evaluated:
- `oikesis` (inhabiting)  -  strong but oik- cluster crowded in ecosystem
- `diaplous` (voyage through)  -  Odyssean, but navigating *through* is weaker than *seeing through*
- `parodos` (theatrical entrance)  -  theatrical register too narrow for operations band
- `dioptron` (seeing-through instrument)  -  the -τρον suffix says "instrument" which is correct. All five R1 purposes converge on making the web transparent. Complements aletheia (unconcealment is the commitment, dioptron is the instrument).
