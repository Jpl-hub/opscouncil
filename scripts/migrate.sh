#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${OPSCOUNCIL_VENV_DIR:-$ROOT_DIR/.venv}"

cd "$ROOT_DIR"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "virtual environment not found: $VENV_DIR" >&2
  echo "run scripts/prepare.sh first" >&2
  exit 1
fi

schema_state="$($VENV_DIR/bin/python - <<'PY'
from sqlalchemy import inspect
from backend.app.core.database import engine

tables = set(inspect(engine).get_table_names())
if "alembic_version" in tables:
    print("versioned")
elif "investigations" in tables:
    print("unexpected-unversioned-investigation")
elif "task_jobs" in tables:
    print("unexpected-unversioned-async-runtime")
elif "tasks" in tables:
    print("existing-v2")
else:
    print("empty")
PY
)"

case "$schema_state" in
  existing-v2)
    "$VENV_DIR/bin/python" -m alembic stamp 0001_existing_schema
    ;;
  unexpected-unversioned-investigation)
    echo "unversioned database already contains investigations; refusing to guess a migration revision" >&2
    exit 2
    ;;
  unexpected-unversioned-async-runtime)
    echo "unversioned database already contains task_jobs; refusing to guess a migration revision" >&2
    exit 2
    ;;
  versioned|empty)
    ;;
  *)
    echo "unknown database schema state: $schema_state" >&2
    exit 2
    ;;
esac

"$VENV_DIR/bin/python" -m alembic upgrade head
echo "OpsCouncil database migration complete."
