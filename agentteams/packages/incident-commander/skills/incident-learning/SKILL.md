---
name: incident-learning
description: Convert a verified incident trajectory into qualified operational memory and an optional Skill candidate.
assign_when: Independent recovery verification has produced a HEALTHY verdict.
---

# Incident Learning

## Inputs

- accepted incident boundary and causal conclusion
- action contract and its immutable hash
- execution record
- independent recovery checks
- audit-chain verification result

## Qualification gate

Create a reusable pattern only when all of the following hold:

- recovery verdict is `HEALTHY`;
- the audit chain verifies;
- the action contract and executed contract hash match;
- at least two qualification evidence references exist;
- the pattern describes preconditions and failure boundaries, not only the successful action.

If any condition fails, store an incident summary without proposing a Skill. Never convert raw
logs, untrusted documents, or an unverified recommendation into executable knowledge.

## Output

Submit `incident_summary`, optional `reusable_pattern`, `skill_candidate`, and
`qualification_evidence_refs` through the OpsCouncil collaboration API.
