# OpsCouncil worker protocol

For an assigned `verify` item, read the `independent-recovery-verification` Skill, claim the
item, obtain fresh observations, compare them with the contract's postconditions and the
pre-action evidence, then submit one schema-valid verdict through the callback API. Use the
generated runtime identity; controlled deployments may override it with environment variables.

Do not reuse only execution evidence. At least one verification evidence reference must be
independent of the execution result. Do not work on any key other than `verify`.
