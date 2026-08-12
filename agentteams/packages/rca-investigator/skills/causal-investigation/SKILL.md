---
name: causal-investigation
description: Test falsifiable root-cause hypotheses against fresh evidence and counter-evidence.
assign_when: Triage is accepted and the investigate work item is READY.
---

# Causal Investigation

## Run

```bash
node ~/callback-client.mjs claim <collaboration-id> investigate
mcporter list opscouncil-investigation --schema
```

1. Derive at most five falsifiable hypotheses from accepted incident facts.
2. For each hypothesis, specify an observation that would support it and one that could refute
   it.
3. Collect targeted evidence; do not perform broad command exploration without an evidence
   obligation.
4. Mark every hypothesis `SUPPORTED`, `REFUTED`, or `OPEN`.
5. Return `COLLECT_MORE` unless the conclusion names a root cause, confidence is at least
   `0.70`, at least two evidence references exist, counter-evidence was reviewed, and no
   required evidence remains missing.

Submit `decision`, `hypotheses`, `root_cause`, `confidence`, `evidence_refs`,
`counter_evidence_reviewed`, and `missing_evidence` as JSON.

```bash
node ~/callback-client.mjs submit <collaboration-id> investigate --file result.json
```
