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

When `shared_context.action_candidates` is non-empty, the action contract must bind one of
those accepted dry-run records. Copy its `proposal_id`, `tool_name`, `arguments`, and
`risk_level` exactly. Never downgrade risk, rename an argument, or replace evidence with test
values. Copy `policy_authorization_ref` only from
`shared_context.execution_policy.auto_authorization_refs`. For a pre-authorized reversible
LAB canary, set `canary` to the JSON boolean `true`.

The callback payload has exactly this shape; do not add sibling policy fields:

```json
{
  "action": {
    "proposal_id": 1,
    "tool_name": "safe_log_rotate",
    "arguments": {},
    "risk_level": "R2",
    "environment": "LAB",
    "target_scope": ["host-or-path"],
    "preconditions": ["precondition"],
    "postconditions": ["postcondition"],
    "rollback_steps": ["rollback step"],
    "reversible": true,
    "canary": true,
    "policy_authorization_ref": "policy-reference",
    "rationale": "evidence-bound rationale"
  },
  "evidence_refs": ["evidence-reference"],
  "alternatives_rejected": ["rejected alternative"]
}
```

Never place shell text in the contract and never perform the action. Submit the action and
its evidence references for deterministic validation.

```bash
node ~/callback-client.mjs submit <collaboration-id> plan --file result.json
```
