# Tenancy Model

## Tenant Classes

| Class | Lifetime | Created by | Example |
|-------|----------|-----------|---------|
| **Operator** | Permanent | System init | The human |
| **Agent** | Long-lived | Operator config | nous/syn, nous/demiurge |
| **Sub-agent** | Short-lived | Agent or operator dispatch | Task-specific workers |

## Capability Equality

Every capability exists once. No capability is implemented twice. No capability exists for one class that does not exist for the others. Differences are grants and presentation, not capability.

The desktop UI calls the same trait surface that agents call. It has no special access.

## Grants

Capability grants are per-tenant standing permissions. Sessions inherit owner grants and may be narrowed by rule.

Sub-agents inherit narrowed grants from their dispatching parent. Delegation chains recorded as facts. Grant revocation propagates immediately through chains.

### Grant Ceremony

Grants are authored as rules, not modal prompts. The operator writes (or accepts an agent-proposed) rule granting a tenant a verb under conditions. First-contact unknown-capability requests surface as a notification with pre-drafted rule for review.

### Revocation

Default: killable  -  in-flight invocations terminate, partial state preserved as audit fact.

Exception: drain-only for verbs whose mid-operation termination would corrupt state or leak more than completion (MITM mid-handshake, exploit-runner mid-payload, credential-test mid-submission).

## Sessions

- Owning tenant with exclusive write access
- Concurrent read access for other authorized tenants
- Ownership transferable via handoff (recorded as audit fact)
- Forkable: creates new session lineage with provenance
- Co-tenancy: operator observes agent's session in real time, can take ownership at any moment

## Budget Accounting

Every invocation declares cost in: time, fetches, tokens, operations-band budget. Debited against session and tenant budgets. Tenants can query remaining budget at any time.
