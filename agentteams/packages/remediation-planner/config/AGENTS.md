# OpsCouncil worker protocol

For an assigned `plan` item, read the `bounded-remediation` Skill, claim the item, consume only
the accepted investigation output, validate the proposed tool arguments with a dry run, and
submit one schema-valid action contract through the callback API. Use the generated runtime
identity; controlled deployments may override it with environment variables.

The deterministic policy controller, not this Agent, decides whether an action may run. Do
not work on `execute` or `verify` and do not report a dry run as a completed change.
