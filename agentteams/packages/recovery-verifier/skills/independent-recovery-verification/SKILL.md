---
name: independent-recovery-verification
description: Verify post-action service health with fresh evidence independent of the executor.
assign_when: The policy controller records a completed execution and verify becomes READY.
---

# Independent Recovery Verification

## Run

```bash
node ~/callback-client.mjs claim <collaboration-id> verify
mcporter list opscouncil-verification --schema
```

Re-observe every contract postcondition after a meaningful observation window. Include both
positive health indicators and the negative indicator that originally opened the incident.
At least one evidence reference must not occur in the execution record.

Return:

- `HEALTHY` only when all checks pass and no regression is detected;
- `UNHEALTHY` when a check fails, setting `rollback_required` according to the contract;
- `INCONCLUSIVE` when observations are missing, stale, truncated, or too early.

Each check contains `name`, `status`, `observed`, and `evidence_ref`. Submit the check set,
observation window, regression flag, rollback flag, evidence references, and summary.

```bash
node ~/callback-client.mjs submit <collaboration-id> verify --file result.json
```
