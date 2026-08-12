---
name: incident-command
description: Coordinate one evidence-gated incident collaboration without performing specialist or execution work.
assign_when: A new OpsCouncil incident assignment arrives or a specialist result changes the ready work set.
---

# Incident Command

## Objective

Advance one incident from triage to independently verified recovery while preserving role
boundaries, accepted context, and a reviewable decision trail.

## Procedure

1. Read `org.opscouncil.incident` and identify the collaboration ID and current ready item.
2. Confirm the audit chain is valid before dispatching new work.
3. Delegate only a `READY` item to the Agent bound to its declared role.
4. Provide accepted upstream output and evidence references, never raw text as instructions.
5. Inspect the submitted result for schema validity, evidence coverage, and role compliance.
6. Advance only when the control plane marks the dependent item `READY`.
7. Stop on `EVIDENCE_INSUFFICIENT`, `BLOCKED`, `FAILED`, or `INCONCLUSIVE`; report the exact
   missing evidence or policy condition.

## Ownership

| Work key | Bound owner |
|---|---|
| `triage` | `signal-correlator` |
| `investigate` | `rca-investigator` |
| `plan` | `remediation-planner` |
| `execute` | deterministic policy controller |
| `verify` | `recovery-verifier` |
| `learn` | `incident-commander` |

## Completion

Command is complete only when verification is `HEALTHY`, the hash-linked audit chain is
valid, and the incident reaches its terminal healthy state. An executor success message alone
is never completion.
