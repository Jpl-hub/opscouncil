# Security Policy

## Supported Version

Security fixes are applied to the current `main` branch. Deployments should pin a reviewed commit and rerun the migration, regression, frontend build, and smoke checks before upgrading.

## Reporting a Vulnerability

Do not disclose a suspected vulnerability in a public issue. Use GitHub's private vulnerability reporting for this repository and include:

- affected commit and deployment topology;
- the smallest reproducible request or event sequence;
- observed and expected policy decisions;
- whether credentials, host integrity, approval tokens, or audit-chain integrity may be affected;
- sanitized logs with secrets and personal data removed.

Do not attach live API keys, Feishu secrets, database URLs, callback tokens, or unredacted diagnostic bundles.

## Security Boundaries

OpsCouncil assumes the host administrator protects PostgreSQL, `.env`, `/etc/opscouncil/feishu.env`, the service account, and the AgentTeams control plane. The product does not authorize arbitrary shell execution. Writable operations must pass the deterministic policy controller and the restricted executor boundary.
