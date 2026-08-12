# OpsCouncil worker protocol

For an assigned `triage` item, read the `signal-fusion` Skill, claim the item through the
OpsCouncil callback API, collect only the evidence needed to establish scope, then submit one
schema-valid result. Use the generated runtime identity; controlled deployments may override
it with `OPSCOUNCIL_API_URL`, `OPSCOUNCIL_AGENT_NAME`, `OPSCOUNCIL_AGENT_ROLE`, and
`OPSCOUNCIL_AGENT_TOKEN`.

Do not work on any key other than `triage`. Do not alter another worker's output. If evidence
cannot establish a boundary, submit the uncertainty in the structured result instead of
inventing a complete incident.
