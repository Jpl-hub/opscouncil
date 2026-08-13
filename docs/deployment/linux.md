# Linux Deployment

This guide installs OpsCouncil on one Linux node with PostgreSQL, pgvector, a restricted service identity, and systemd. Run application processes as a dedicated unprivileged account. Use `sudo` only for package installation, database provisioning, and installation of narrowly scoped service policy.

## 1. Host Prerequisites

Install these distribution packages before running the repository scripts:

- Python 3.10-3.13 with `venv` and development headers
- PostgreSQL client and server
- pgvector for the installed PostgreSQL major version
- `curl`, `iproute`/`ss`, `procps`, `systemd`, and `sudo`
- a C compiler and `make`
- Node.js 20+ and npm when building the frontend on the target host

Create a service account, check out the repository under a directory it owns, and grant only the provisioning permissions required by local policy. Do not run the API or worker as root.

## 2. Configure PostgreSQL and Python

Choose a unique deployment password. Read it without echoing so it is not written into shell history:

```bash
cd /opt/opscouncil
export OPSCOUNCIL_DB_NAME=opscouncil
export OPSCOUNCIL_DB_USER=opscouncil
read -rsp 'PostgreSQL password: ' OPSCOUNCIL_DB_PASSWORD && echo
export OPSCOUNCIL_DB_PASSWORD
./scripts/prepare.sh
```

`prepare.sh` creates the virtual environment, installs dependencies from `requirements/base.txt`, provisions the role and database, enables the `vector` extension, and builds the Vue frontend. On `loongarch64`, it uses distribution-native NumPy and lxml packages where binary wheels are unavailable.

Copy the configuration template and make it private:

```bash
cp .env.example .env
chmod 0600 .env
```

Set `DATABASE_URL` to the provisioned password and set the model credential. Keep `OPSCOUNCIL_ALLOW_ROOT_EXECUTOR=false`. Add only explicitly approved services to `OPSCOUNCIL_RESTARTABLE_UNITS` and only explicitly approved files to `OPSCOUNCIL_REPAIRABLE_CONFIG_PATHS`. Leave `OPSCOUNCIL_AUTO_POLICY_REFS` empty until a versioned reversible-action policy has been reviewed and deployed; model-generated references are never trusted implicitly.

## 3. Validate and Migrate

```bash
./scripts/preflight.sh
./scripts/migrate.sh
```

Preflight verifies the kernel, architecture, runtime identity, host tools, PostgreSQL connectivity, pgvector, frontend artifact, and model configuration. A production PostgreSQL URL is mandatory; SQLite is supported only by isolated tests.

## 4. Install systemd Services

```bash
./scripts/install_service.sh
sudo systemctl start opscouncil opscouncil-worker opscouncil-policy-controller
sudo systemctl status opscouncil opscouncil-worker opscouncil-policy-controller
```

The installer creates separate API, task worker, and deterministic policy-controller services with a restrictive umask and `NoNewPrivileges`. The policy controller is outside the model team: it verifies the sealed action hash, proposal binding, deployed policy reference, runtime scope, and independent pre/postconditions before the existing restricted executor can run. Expired execution leases are reconciled without replaying a side effect. If controlled service restart is configured, the installer writes a polkit rule containing only the approved units and rejects protected infrastructure services.

Run the release checks:

```bash
OPSCOUNCIL_REQUIRE_SAFE_RUNTIME=true \
OPSCOUNCIL_REQUIRE_MODEL=true \
OPSCOUNCIL_REQUIRE_DEPLOYMENT_READY=true \
OPSCOUNCIL_REQUIRE_WORKER=true \
./scripts/smoke_check.sh
```

## 5. Feishu Channel

Copy `config/feishu.env.example` to `/etc/opscouncil/feishu.env`, fill it outside the repository, and protect it:

```bash
sudo install -d -m 0750 /etc/opscouncil
sudo install -o root -g root -m 0600 config/feishu.env.example /etc/opscouncil/feishu.env
sudo systemctl restart opscouncil-feishu
```

Set the same random `OPSCOUNCIL_CHANNEL_INTERNAL_TOKEN` in `.env` and the Feishu environment file. The Feishu process accepts messages over the official long connection, writes them through an authenticated internal API, and sends approval cards from a durable outbox. The channel process never receives executor privileges.

## 6. AgentTeams Response Team

Install the pinned AgentTeams `v1.2.2` release. Confirm that the
`agentteams-manager` container and its `agt` operator CLI are healthy. The API
URL below must be reachable from AgentTeams Worker containers.

```bash
export OPSCOUNCIL_API_URL=http://host.containers.internal:8000
export OPSCOUNCIL_AGENT_MODEL=qwen3.6-plus
export AGENTTEAMS_CALLBACK_SECRET='generate-a-random-deployment-secret'
python -m agentteams.scripts.deploy_team
```

Generated Worker packages and policy-controller credentials are written under ignored `agentteams/dist/` with mode `0600` where applicable. Each Worker receives a derived role-specific token. The deployment fails when managed resources already exist; `--replace` explicitly deletes and recreates them to avoid stale seed-only package content.

After deployment, set `AGENTTEAMS_TEAM_ROOM_ID` to the Team resource's
`teamRoomID` and `AGENTTEAMS_LEADER_USER_ID` to the incident commander's full
Matrix user ID. OpsCouncil dispatches into the shared Team room with a standard
Matrix mention; dispatch readiness therefore requires both values rather than
relying on an unaddressed room message.

## 7. Operations

```bash
sudo journalctl -u opscouncil -f
sudo journalctl -u opscouncil-worker -f
sudo journalctl -u opscouncil-policy-controller -f
sudo journalctl -u opscouncil-feishu -f
opscouncilctl doctor --strict
```

Back up PostgreSQL and the protected configuration files according to local policy. Do not restore generated action approvals or callback tokens across environments; rotate them and recreate the AgentTeams team instead.
