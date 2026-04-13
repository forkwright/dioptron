# Training Data Architecture

## Behavioral Emission Taxonomy

Every operator-relevant and agent-relevant event emitted in a format directly consumable by local fine-tuning pipelines, with tenant behavior as implicit labels.

| Event Type | Label Structure | Downstream Model Class |
|------------|----------------|----------------------|
| Captures with attention scores | Reading quality (time on page, scroll depth, re-visits) | Content quality ranking |
| Contradiction events with resolutions | Reasoning (which source won, why) | Fact verification |
| Rule overrides | Preference (operator chose to allow/deny) | Policy learning |
| Tier-promotion outcomes | Judgment (was promotion correct in hindsight?) | Knowledge curation |
| Form submissions with return-visit follow-up | Trust (did the submission achieve its goal?) | Action quality |
| Query-to-result-selection pairs | Retrieval (which result was useful?) | Search ranking |
| Active-capability invocations with outcomes | Security decision (was the operation successful?) | Operational judgment |
| Agent strategy traces with outcomes | Agent self-improvement (which approach worked?) | Agent policy |
| Operator-overrides-agent events | Alignment (where did the agent diverge from operator intent?) | Alignment training |

## Attribution

Every event records:
- Acting tenant identity
- Grant chain that authorized the action
- Session context
- Rule chain that evaluated

Datasets filterable by: tenant class, individual tenant, delegation depth, grant scope.

## Cross-System Contribution

The runtime contributes to `forkwright-corpus` workspace crate alongside aletheia, akroasis, kanon, harmonia. The runtime is the largest contributor but not the owner.

## Schema Governance

Dataset taxonomy enumerated and versioned. Each type declares: source events, label structure, downstream model class, privacy class, default retention. Adding a new type requires explicit schema declaration.
