# Contributing

## Development Setup

Use an isolated Python environment and an isolated test database. Never reuse production credentials in development.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements/base.txt
npm --prefix frontend ci
```

## Change Rules

- Keep model planning, deterministic authorization, and execution in separate modules.
- Add MCP operations through the typed registry; do not introduce arbitrary command passthroughs.
- Bind every writable action to a canonical action contract and evidence references.
- Add an Alembic migration for persistent schema changes.
- Keep credentials in local environment files and generated deployment artifacts only.
- Preserve generic Linux behavior across supported architectures.

## Verification

```bash
python -m pytest -q
npm --prefix frontend run build
bash -n scripts/*.sh
git diff --check
```

Changes to policy, execution, approval, evidence, or audit behavior require focused regression cases covering both allowed and rejected paths.
