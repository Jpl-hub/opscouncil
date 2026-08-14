#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/output"
PACKAGE_NAME="${OPSCOUNCIL_PACKAGE_NAME:-opscouncil.tar.gz}"
PACKAGE_PATH="$PACKAGE_DIR/$PACKAGE_NAME"

package_entries=(
  ".env.example"
  "LICENSE"
  "README.md"
  "agentteams"
  "alembic.ini"
  "backend"
  "config/feishu.env.example"
  "deploy/systemd"
  "docs/assets"
  "docs/deployment/linux.md"
  "frontend/dist"
  "migrations"
  "requirements"
  "scripts/opscouncilctl.py"
  "scripts/policy_controller.py"
  "scripts/feishu_channel.py"
  "scripts/install_service.sh"
  "scripts/migrate.sh"
  "scripts/preflight.sh"
  "scripts/prepare.sh"
  "scripts/run.sh"
  "scripts/smoke_check.sh"
  "scripts/worker.py"
)

cd "$ROOT_DIR"

node_can_build() {
  command -v node >/dev/null 2>&1 || return 1
  command -v npm >/dev/null 2>&1 || return 1
  node -e 'const major = Number(process.versions.node.split(".")[0]); process.exit(major >= 20 ? 0 : 1)' >/dev/null 2>&1
}

if node_can_build; then
  npm --prefix frontend ci
  npm --prefix frontend run build
elif command -v node >/dev/null 2>&1; then
  echo "node version is too old for frontend rebuild: $(node --version)" >&2
  echo "using existing frontend/dist if present" >&2
fi

if [ ! -f "$ROOT_DIR/frontend/dist/index.html" ]; then
  echo "frontend build artifact missing: frontend/dist/index.html" >&2
  exit 1
fi

for entry in "${package_entries[@]}"; do
  if [ ! -e "$ROOT_DIR/$entry" ]; then
    echo "required package entry missing: $entry" >&2
    exit 1
  fi
done

mkdir -p "$PACKAGE_DIR"
staging_dir="$(mktemp -d)"
trap 'rm -r -- "$staging_dir"' EXIT

tar \
  --exclude='*/__pycache__' \
  --exclude='*.pyc' \
  --exclude='*.pyo' \
  --exclude='agentteams/dist' \
  -cf - \
  -- "${package_entries[@]}" | tar -xf - -C "$staging_dir"

find "$staging_dir" -type d -exec chmod 0755 {} +
find "$staging_dir" -type f -exec chmod 0644 {} +
chmod 0755 "$staging_dir/scripts/"*

tar \
  --sort=name \
  --mtime='UTC 2026-01-01' \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "$staging_dir" \
  -czf "$PACKAGE_PATH" \
  -- "${package_entries[@]}"

echo "$PACKAGE_PATH"
