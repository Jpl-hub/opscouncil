#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_DATABASE_URL="postgresql+psycopg://opscouncil@127.0.0.1:5432/opscouncil"
status=0

cd "$ROOT_DIR"

ok() { printf '[OK] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1" >&2; }
fail() { printf '[FAIL] %s\n' "$1" >&2; status=1; }

need_cmd() {
  if command -v "$1" >/dev/null 2>&1; then
    ok "$1 found"
  else
    fail "$1 not found"
  fi
}

read_env_value() {
  local key="$1"
  local file="${2:-.env}"
  [ -f "$file" ] || return 1
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

if [ "$(uname -s 2>/dev/null || echo unknown)" = "Linux" ]; then
  ok "kernel: Linux"
else
  fail "OpsCouncil requires a Linux host"
fi

arch="$(uname -m 2>/dev/null || echo unknown)"
case "$arch" in
  x86_64|aarch64|arm64|loongarch64|riscv64)
    ok "architecture: $arch"
    ;;
  *)
    warn "architecture has not been validated: $arch"
    ;;
esac

if [ -r /etc/os-release ]; then
  os_name="$(grep -E '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"' || true)"
  ok "operating system: ${os_name:-Linux}"
else
  fail "/etc/os-release is not readable"
fi

if [ "$(id -u)" = "0" ]; then
  fail "current user is root; run OpsCouncil as a restricted service account"
else
  ok "runtime identity: $(id -un)/uid $(id -u)"
fi

for command in python3 curl psql journalctl systemctl ss ps; do
  need_cmd "$command"
done

if command -v python3 >/dev/null 2>&1; then
  python_version="$(python3 - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
PY
)"
  case "$python_version" in
    3.10.*|3.11.*|3.12.*|3.13.*)
      ok "python version: $python_version"
      ;;
    *)
      fail "python version $python_version is outside the supported 3.10-3.13 range"
      ;;
  esac
fi

database_url="${DATABASE_URL:-$(read_env_value DATABASE_URL .env || true)}"
database_url="${database_url:-$DEFAULT_DATABASE_URL}"
if [[ "$database_url" == sqlite* ]]; then
  fail "DATABASE_URL uses SQLite; production requires PostgreSQL with pgvector"
elif command -v psql >/dev/null 2>&1; then
  psql_url="${database_url/postgresql+psycopg:\/\//postgresql://}"
  if psql "$psql_url" -Atc "SELECT 1;" >/dev/null 2>&1; then
    ok "database reachable"
    if psql "$psql_url" -Atc "SELECT 1 FROM pg_extension WHERE extname='vector';" 2>/dev/null | grep -qx 1; then
      ok "pgvector extension enabled"
    else
      fail "pgvector extension is not enabled"
    fi
  else
    warn "database is not reachable; provision it before running migrations"
  fi
fi

if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  ok "node/npm found: $(node --version) / npm $(npm --version)"
elif [ -f frontend/dist/index.html ]; then
  warn "node/npm not found; the verified bundled frontend can still be served"
else
  fail "node/npm not found and frontend/dist is absent"
fi

if [ -f .env ]; then
  ok ".env exists"
  if grep -Eq '^(BAILIAN_API_KEY|DASHSCOPE_API_KEY)=.+$' .env; then
    ok "model credential configured"
  else
    warn "model credential is empty; model-backed workflows will be unavailable"
  fi
else
  warn ".env not found; copy .env.example and set deployment credentials"
fi

exit "$status"
