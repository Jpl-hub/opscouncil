#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="${OPSCOUNCIL_SERVICE_NAME:-opscouncil}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
WORKER_SERVICE_NAME="${OPSCOUNCIL_WORKER_SERVICE_NAME:-opscouncil-worker}"
WORKER_SERVICE_FILE="/etc/systemd/system/${WORKER_SERVICE_NAME}.service"
POLICY_CONTROLLER_SERVICE_NAME="${OPSCOUNCIL_POLICY_CONTROLLER_SERVICE_NAME:-opscouncil-policy-controller}"
POLICY_CONTROLLER_SERVICE_FILE="/etc/systemd/system/${POLICY_CONTROLLER_SERVICE_NAME}.service"
FEISHU_SERVICE_NAME="${OPSCOUNCIL_FEISHU_SERVICE_NAME:-opscouncil-feishu}"
FEISHU_SERVICE_FILE="/etc/systemd/system/${FEISHU_SERVICE_NAME}.service"
FEISHU_ENV_FILE="${OPSCOUNCIL_FEISHU_ENV_FILE:-/etc/opscouncil/feishu.env}"
LAB_FIXTURE_SERVICE_NAME="${OPSCOUNCIL_LAB_FIXTURE_SERVICE_NAME:-opscouncil-lab-failed}"
LAB_FIXTURE_SERVICE_FILE="/etc/systemd/system/${LAB_FIXTURE_SERVICE_NAME}.service"
LAB_FIXTURE_UNIT_SOURCE="$ROOT_DIR/deploy/systemd/opscouncil-lab-failed.service"
LAB_IMPACT_FIXTURE_UNITS=(
  "opsbench-impact-root.service"
  "opsbench-impact-part.service"
  "opsbench-impact-ordered.service"
)
OPSCOUNCILCTL_PATH="${OPSCOUNCILCTL_PATH:-/usr/local/bin/opscouncilctl}"
RESTARTABLE_UNITS_RAW="${OPSCOUNCIL_RESTARTABLE_UNITS:-}"
REPAIRABLE_CONFIG_PATHS_RAW="${OPSCOUNCIL_REPAIRABLE_CONFIG_PATHS:-}"
MANAGED_RESTART_POLKIT="/etc/polkit-1/rules.d/49-${SERVICE_NAME}-managed-restart.rules"
INSTALL_LAB_FIXTURES="${OPSCOUNCIL_INSTALL_LAB_FIXTURES:-false}"
VENV_DIR="${OPSCOUNCIL_VENV_DIR:-$ROOT_DIR/.venv}"
HOST="${OPSCOUNCIL_HOST:-0.0.0.0}"
PORT="${OPSCOUNCIL_PORT:-8000}"
RUN_USER="${OPSCOUNCIL_SERVICE_USER:-$(id -un)}"

if [ "$RUN_USER" = "root" ] || [ "$RUN_USER" = "0" ]; then
  echo "refusing to install services with a root runtime account." >&2
  echo "set OPSCOUNCIL_SERVICE_USER to an existing restricted account." >&2
  exit 2
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required to install the systemd unit." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required on the target Linux host." >&2
  exit 1
fi

if [ ! -x "$ROOT_DIR/scripts/run.sh" ]; then
  chmod +x "$ROOT_DIR/scripts/run.sh"
fi
if [ ! -x "$ROOT_DIR/scripts/worker.py" ]; then
  chmod +x "$ROOT_DIR/scripts/worker.py"
fi
if [ ! -x "$ROOT_DIR/scripts/policy_controller.py" ]; then
  chmod +x "$ROOT_DIR/scripts/policy_controller.py"
fi
if [ ! -x "$ROOT_DIR/scripts/feishu_channel.py" ]; then
  chmod +x "$ROOT_DIR/scripts/feishu_channel.py"
fi
if [ ! -x "$ROOT_DIR/scripts/migrate.sh" ]; then
  chmod +x "$ROOT_DIR/scripts/migrate.sh"
fi
if [ ! -x "$ROOT_DIR/scripts/opscouncilctl.py" ]; then
  chmod +x "$ROOT_DIR/scripts/opscouncilctl.py"
fi

if ! id "$RUN_USER" >/dev/null 2>&1; then
  echo "service user not found: $RUN_USER" >&2
  echo "run scripts/prepare.sh first, or set OPSCOUNCIL_SERVICE_USER to an existing restricted account." >&2
  exit 1
fi

"$ROOT_DIR/scripts/migrate.sh"

api_unit="$(mktemp)"
worker_unit="$(mktemp)"
policy_controller_unit="$(mktemp)"
feishu_unit="$(mktemp)"
restart_polkit="$(mktemp)"
trap 'rm -f "$api_unit" "$worker_unit" "$policy_controller_unit" "$feishu_unit" "$restart_polkit"' EXIT

cat >"$api_unit" <<UNIT
[Unit]
Description=OpsCouncil Security Operations Agent
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${ROOT_DIR}
Environment=OPSCOUNCIL_HOST=${HOST}
Environment=OPSCOUNCIL_PORT=${PORT}
Environment=OPSCOUNCIL_ALLOW_ROOT_RUN=false
Environment=OPSCOUNCIL_EXECUTOR_USER=${RUN_USER}
Environment="OPSCOUNCIL_RESTARTABLE_UNITS=${RESTARTABLE_UNITS_RAW}"
Environment="OPSCOUNCIL_REPAIRABLE_CONFIG_PATHS=${REPAIRABLE_CONFIG_PATHS_RAW}"
ExecStart=${ROOT_DIR}/scripts/run.sh
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=false

[Install]
WantedBy=multi-user.target
UNIT

cat >"$worker_unit" <<UNIT
[Unit]
Description=OpsCouncil Agent Task Worker
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${ROOT_DIR}
Environment=OPSCOUNCIL_ALLOW_ROOT_RUN=false
Environment=OPSCOUNCIL_EXECUTOR_USER=${RUN_USER}
Environment="OPSCOUNCIL_RESTARTABLE_UNITS=${RESTARTABLE_UNITS_RAW}"
Environment="OPSCOUNCIL_REPAIRABLE_CONFIG_PATHS=${REPAIRABLE_CONFIG_PATHS_RAW}"
ExecStart=${VENV_DIR}/bin/python ${ROOT_DIR}/scripts/worker.py
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=false

[Install]
WantedBy=multi-user.target
UNIT

cat >"$policy_controller_unit" <<UNIT
[Unit]
Description=OpsCouncil Deterministic Policy Controller
After=network-online.target postgresql.service ${SERVICE_NAME}.service
Wants=network-online.target ${SERVICE_NAME}.service

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${ROOT_DIR}
Environment=OPSCOUNCIL_ALLOW_ROOT_RUN=false
Environment=OPSCOUNCIL_EXECUTOR_USER=${RUN_USER}
Environment=OPSCOUNCIL_POLICY_CONTROLLER_ID=policy-controller
Environment="OPSCOUNCIL_RESTARTABLE_UNITS=${RESTARTABLE_UNITS_RAW}"
Environment="OPSCOUNCIL_REPAIRABLE_CONFIG_PATHS=${REPAIRABLE_CONFIG_PATHS_RAW}"
ExecStart=${VENV_DIR}/bin/python ${ROOT_DIR}/scripts/policy_controller.py
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=false

[Install]
WantedBy=multi-user.target
UNIT

cat >"$feishu_unit" <<UNIT
[Unit]
Description=OpsCouncil Feishu Collaboration Channel
After=network-online.target ${SERVICE_NAME}.service
Wants=network-online.target ${SERVICE_NAME}.service
ConditionPathExists=${FEISHU_ENV_FILE}

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${ROOT_DIR}
EnvironmentFile=${FEISHU_ENV_FILE}
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=${VENV_DIR}/bin/python ${ROOT_DIR}/scripts/feishu_channel.py
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
UNIT

if [ -n "$RESTARTABLE_UNITS_RAW" ]; then
  if [ ! -d /etc/polkit-1/rules.d ]; then
    echo "polkit rules directory is required when OPSCOUNCIL_RESTARTABLE_UNITS is configured." >&2
    exit 1
  fi
  if [[ ! "$RUN_USER" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]]; then
    echo "invalid service user for polkit rule: $RUN_USER" >&2
    exit 1
  fi
  allowed_units_js=""
  IFS=',' read -r -a restart_units <<<"$RESTARTABLE_UNITS_RAW"
  for raw_unit in "${restart_units[@]}"; do
    unit="${raw_unit//[[:space:]]/}"
    if [[ ! "$unit" =~ ^[A-Za-z0-9_.@:-]+(\.service)?$ ]]; then
      echo "invalid restart unit: $raw_unit" >&2
      exit 1
    fi
    if [[ "$unit" != *.service ]]; then
      unit="${unit}.service"
    fi
    lowered="${unit,,}"
    case "$lowered" in
      opscouncil*|mariadb*|mysql*|postgresql*|systemd-*|auditd.service|dbus.service|firewalld.service|network.service|networkmanager.service|nftables.service|polkit.service|ssh.service|sshd.service)
        echo "refusing protected restart unit: $unit" >&2
        exit 1
        ;;
    esac
    if [ -n "$allowed_units_js" ]; then
      allowed_units_js+=", "
    fi
    allowed_units_js+="\"${unit}\""
  done
  cat >"$restart_polkit" <<RULE
polkit.addRule(function(action, subject) {
  var allowedUnits = [${allowed_units_js}];
  if (action.id === "org.freedesktop.systemd1.manage-units" &&
      subject.user === "${RUN_USER}" &&
      action.lookup("verb") === "restart" &&
      allowedUnits.indexOf(action.lookup("unit")) !== -1) {
    return polkit.Result.YES;
  }
});
RULE
  sudo install -o root -g root -m 0644 "$restart_polkit" "$MANAGED_RESTART_POLKIT"
else
  sudo rm -f "$MANAGED_RESTART_POLKIT"
fi

sudo install -d -m 0750 "$(dirname "$FEISHU_ENV_FILE")"
if sudo test -e "$FEISHU_ENV_FILE"; then
  sudo chown root:root "$FEISHU_ENV_FILE"
  sudo chmod 0600 "$FEISHU_ENV_FILE"
fi

sudo install -m 0644 "$api_unit" "$SERVICE_FILE"
sudo install -m 0644 "$worker_unit" "$WORKER_SERVICE_FILE"
sudo install -m 0644 "$policy_controller_unit" "$POLICY_CONTROLLER_SERVICE_FILE"
sudo install -m 0644 "$feishu_unit" "$FEISHU_SERVICE_FILE"
sudo install -o root -g root -m 0755 "$ROOT_DIR/scripts/opscouncilctl.py" "$OPSCOUNCILCTL_PATH"
if [ "$INSTALL_LAB_FIXTURES" = "true" ]; then
  sudo install -m 0644 "$LAB_FIXTURE_UNIT_SOURCE" "$LAB_FIXTURE_SERVICE_FILE"
  for unit_name in "${LAB_IMPACT_FIXTURE_UNITS[@]}"; do
    sudo install -m 0644 \
      "$ROOT_DIR/deploy/systemd/$unit_name" \
      "/etc/systemd/system/$unit_name"
  done
fi
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME" "$WORKER_SERVICE_NAME" "$POLICY_CONTROLLER_SERVICE_NAME"
sudo systemctl enable "$FEISHU_SERVICE_NAME"
if [ "$INSTALL_LAB_FIXTURES" = "true" ]; then
  if sudo systemctl restart "$LAB_FIXTURE_SERVICE_NAME"; then
    echo "lab fixture unexpectedly succeeded: $LAB_FIXTURE_SERVICE_NAME" >&2
    exit 1
  fi
  fixture_state="$(sudo systemctl show "$LAB_FIXTURE_SERVICE_NAME" --property=ActiveState --value)"
  if [ "$fixture_state" != "failed" ]; then
    echo "lab fixture did not enter failed state: $LAB_FIXTURE_SERVICE_NAME ($fixture_state)" >&2
    exit 1
  fi
fi

echo "Installed $SERVICE_FILE"
echo "Installed $WORKER_SERVICE_FILE"
echo "Installed $POLICY_CONTROLLER_SERVICE_FILE"
echo "Installed $FEISHU_SERVICE_FILE"
echo "Installed $OPSCOUNCILCTL_PATH"
if [ "$INSTALL_LAB_FIXTURES" = "true" ]; then
  echo "Installed bounded lab fixture $LAB_FIXTURE_SERVICE_FILE"
  echo "Installed bounded service-impact relationship fixtures"
fi
echo "Start with: sudo systemctl start $SERVICE_NAME $WORKER_SERVICE_NAME $POLICY_CONTROLLER_SERVICE_NAME"
echo "Feishu starts when $FEISHU_ENV_FILE exists; install config/feishu.env.example there with mode 0600."
echo "API logs: sudo journalctl -u $SERVICE_NAME -f"
echo "Worker logs: sudo journalctl -u $WORKER_SERVICE_NAME -f"
echo "Policy controller logs: sudo journalctl -u $POLICY_CONTROLLER_SERVICE_NAME -f"
echo "Feishu logs: sudo journalctl -u $FEISHU_SERVICE_NAME -f"
