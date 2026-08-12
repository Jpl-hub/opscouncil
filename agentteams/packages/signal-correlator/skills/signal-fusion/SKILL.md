---
name: signal-fusion
description: Correlate noisy alerts into one evidence-preserving incident boundary.
assign_when: The triage work item is READY.
---

# Signal Fusion

## Run

```bash
node ~/callback-client.mjs claim <collaboration-id> triage
mcporter list opscouncil-signal --schema
```

Use the smallest useful set of telemetry tools. Group signals only when host, resource,
topology, and time-window evidence support the grouping. Preserve each source observation as
an evidence reference.

## Required output

Write JSON with `incident_boundary`, non-empty `correlated_signals`,
`suppressed_alert_count`, `severity`, `affected_resources`, and non-empty `evidence_refs`.
Every correlated signal includes `signal_key`, `source`, `observed_at`, `summary`, and
`evidence_ref`.

```bash
node ~/callback-client.mjs submit <collaboration-id> triage --file result.json
```

Do not suppress a signal whose resource ownership is unknown. Do not assign a root cause and
do not recommend an action.
