#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${OPSCOUNCIL_VENV_DIR:-$ROOT_DIR/.venv}"
DB_NAME="${OPSCOUNCIL_DB_NAME:-opscouncil}"
DB_USER="${OPSCOUNCIL_DB_USER:-opscouncil}"
DB_PASSWORD="${OPSCOUNCIL_DB_PASSWORD:-}"
ARCH="$(uname -m)"
VENV_SYSTEM_SITE_PACKAGES="${OPSCOUNCIL_VENV_SYSTEM_SITE_PACKAGES:-auto}"

cd "$ROOT_DIR"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing command: $1" >&2
    exit 1
  fi
}

need_cmd python3
need_cmd psql

if [ "$(id -u)" = "0" ]; then
  echo "do not prepare OpsCouncil as root; use its restricted service account" >&2
  exit 2
fi

if [ -z "$DB_PASSWORD" ]; then
  echo "OPSCOUNCIL_DB_PASSWORD must be set while provisioning PostgreSQL" >&2
  exit 2
fi
if [[ "$DB_NAME" != [A-Za-z_]* ]] || [[ "$DB_NAME" == *[^A-Za-z0-9_]* ]]; then
  echo "invalid OPSCOUNCIL_DB_NAME" >&2
  exit 2
fi
if [[ "$DB_USER" != [A-Za-z_]* ]] || [[ "$DB_USER" == *[^A-Za-z0-9_]* ]]; then
  echo "invalid OPSCOUNCIL_DB_USER" >&2
  exit 2
fi

venv_args=()
if [ "$ARCH" = "loongarch64" ]; then
  need_cmd sudo
  need_cmd dnf
  native_packages=(gcc make python3-devel python3-numpy python3-lxml)
  echo "installing LoongArch native dependencies: ${native_packages[*]}"
  sudo dnf install -y "${native_packages[@]}"
fi

if [ "$VENV_SYSTEM_SITE_PACKAGES" = "true" ] || {
  [ "$VENV_SYSTEM_SITE_PACKAGES" = "auto" ] && [ "$ARCH" = "loongarch64" ]
}; then
  python3 -c 'import numpy, lxml' >/dev/null 2>&1 || {
    echo "system numpy/lxml packages are required for this architecture" >&2
    exit 1
  }
  venv_args+=(--system-site-packages)
fi

python3 -m venv "${venv_args[@]}" "$VENV_DIR"
# shellcheck disable=SC1091
. "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip
python -m pip install -r requirements/base.txt
python -c 'import lark_oapi, Crypto, websockets'

if command -v sudo >/dev/null 2>&1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1 \
    || printf 'CREATE ROLE %s WITH LOGIN PASSWORD :\x27db_password\x27;\n' "$DB_USER" \
      | sudo -u postgres psql -v ON_ERROR_STOP=1 -v db_password="$DB_PASSWORD"
  sudo -u postgres psql -v ON_ERROR_STOP=1 -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1 \
    || sudo -u postgres createdb -O "$DB_USER" "$DB_NAME"
  sudo -u postgres psql -v ON_ERROR_STOP=1 -d "$DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS vector;"
else
  echo "sudo is required to provision the local PostgreSQL role and database" >&2
  exit 1
fi

if [ ! -f "$ROOT_DIR/.env" ]; then
  cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
  chmod 0600 "$ROOT_DIR/.env"
  echo "created .env; set DATABASE_URL and model credentials before startup"
fi

if [ -f "$ROOT_DIR/frontend/package.json" ]; then
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    npm --prefix frontend ci
    npm --prefix frontend run build
  elif [ ! -f "$ROOT_DIR/frontend/dist/index.html" ]; then
    echo "node/npm is unavailable and frontend/dist is missing" >&2
    exit 1
  else
    echo "using bundled frontend/dist"
  fi
elif [ -f "$ROOT_DIR/frontend/dist/index.html" ]; then
  echo "using bundled frontend/dist"
else
  echo "frontend build artifact missing: frontend/dist/index.html" >&2
  exit 1
fi

echo "OpsCouncil preparation complete."
