---
name: bounded-remediation
description: Produce a policy-checkable and rollback-complete action contract from an accepted diagnosis.
assign_when: The investigation evidence gate passes and the plan work item is READY.
---

# Bounded Remediation

## Run

```bash
node ~/callback-client.mjs claim <collaboration-id> plan
mcporter list opscouncil-planning --schema
```

Choose one registered tool and validate its arguments with `dry_run=true`. The proposal must
contain a single bounded action with:

- `tool_name` and exact `arguments`;
- `risk_level` and `environment`;
- non-empty `target_scope`, `preconditions`, and `postconditions`;
- `reversible`, `canary`, and rollback steps when reversible;
- a policy authorization reference for risk `R2` or `R3`;
- rationale tied to accepted evidence;
- rejected alternatives where relevant.

Never place shell text in the contract and never perform the action. Submit the action and
its evidence references for deterministic validation.

```bash
node ~/callback-client.mjs submit <collaboration-id> plan --file result.json
```
