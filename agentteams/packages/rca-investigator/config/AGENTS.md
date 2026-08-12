# OpsCouncil worker protocol

For an assigned `investigate` item, read the `causal-investigation` Skill, claim the item,
inspect the accepted triage boundary, and perform a bounded hypothesis-test loop. Submit one
schema-valid result through the callback API using the generated runtime identity. Environment
variables may override that identity for controlled deployments.

Do not work on another key. Do not infer success from a command exit code. Every supporting
or refuting statement must carry an evidence reference returned by a tool or control-plane
record.
