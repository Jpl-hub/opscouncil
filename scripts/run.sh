#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${OPSCOUNCIL_VENV_DIR:-$ROOT_DIR/.venv}"
HOST="${OPSCOUNCIL_HOST:-0.0.0.0}"
PORT="${OPSCOUNCIL_PORT:-8000}"
ALLOW_ROOT_RUN="${OPSCOUNCIL_ALLOW_ROOT_RUN:-false}"

cd "$ROOT_DIR"

if [ "$(id -u)" = "0" ] && [ "$ALLOW_ROOT_RUN" != "true" ]; then
  echo "refusing to start as root: use a restricted service account" >&2
  echo "temporary local override: OPSCOUNCIL_ALLOW_ROOT_RUN=true $0" >&2
  exit 2
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "virtual environment not found: $VENV_DIR" >&2
  echo "run scripts/prepare.sh first" >&2
  exit 1
fi

# shellcheck disable=SC1091
. "$VENV_DIR/bin/activate"

load_env_file() {
  local file="$1"
  local line key value
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ""|\#*) continue ;;
    esac
    key="${line%%=*}"
    value="${line#*=}"
    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      continue
    fi
    if [ -z "${!key+x}" ]; then
      export "$key=$value"
    fi
  done < "$file"
}

if [ -f "$ROOT_DIR/.env" ]; then
  load_env_file "$ROOT_DIR/.env"
fi

exec python -m uvicorn backend.app.main:app --host "$HOST" --port "$PORT"
