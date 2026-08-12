from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.mcp.registry import ToolRegistry
from backend.app.models.entities import ConfigBaseline, ConfigBaselineCheck


LIVE_SCOPE = "LIVE"
LAB_SCOPE = "LAB"
BASELINE_SCOPES = frozenset({LIVE_SCOPE, LAB_SCOPE})


SAFE_SNAPSHOT_FIELDS = (
    "path",
    "resolved_path",
    "exists",
    "file_type",
    "size_bytes",
    "mtime",
    "mode",
    "uid",
    "gid",
    "sha256",
    "hash_truncated",
    "link_target_sha256",
)
CONTENT_FIELDS = ("sha256", "link_target_sha256", "size_bytes")
PERMISSION_FIELDS = ("mode", "uid", "gid")
METADATA_FIELDS = ("mtime", "resolved_path", "file_type")


def _safe_snapshot(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        field: observation[field]
        for field in SAFE_SNAPSHOT_FIELDS
        if field in observation
    }


def _fields_changed(
    baseline: dict[str, Any],
    current: dict[str, Any],
    fields: tuple[str, ...],
) -> bool:
    return any(baseline.get(field) != current.get(field) for field in fields)


class ConfigBaselineService:
    def __init__(self, session: Session, registry: ToolRegistry) -> None:
        self.session = session
        self.registry = registry

    def create(
        self,
        *,
        name: str,
        paths: list[str],
        created_by: str = "local-admin",
        scope: str = LIVE_SCOPE,
    ) -> ConfigBaseline:
        normalized_paths = list(dict.fromkeys(path.strip() for path in paths if path.strip()))
        if not normalized_paths:
            raise ValueError("config baseline requires at least one path")
        normalized_scope = scope.strip().upper()
        if normalized_scope not in BASELINE_SCOPES:
            raise ValueError(f"unsupported config baseline scope: {scope}")

        result = self.registry.call(
            "config_integrity_scan",
            {"paths": normalized_paths},
        )
        snapshot = [_safe_snapshot(item) for item in result.observations]
        snapshot = [item for item in snapshot if item.get("path")]
        if not snapshot:
            raise ValueError("config baseline scan returned no eligible paths")

        baseline = ConfigBaseline(
            name=name.strip(),
            scope=normalized_scope,
            paths_json=[item["path"] for item in snapshot],
            snapshot_json=snapshot,
            warnings_json=result.warnings,
            created_by=created_by.strip() or "local-admin",
        )
        self.session.add(baseline)
        self.session.flush()
        return baseline

    def list(self, limit: int = 20, *, scope: str = LIVE_SCOPE) -> list[ConfigBaseline]:
        normalized_scope = scope.strip().upper()
        if normalized_scope not in BASELINE_SCOPES:
            raise ValueError(f"unsupported config baseline scope: {scope}")
        return list(
            self.session.scalars(
                select(ConfigBaseline)
                .where(ConfigBaseline.scope == normalized_scope)
                .order_by(ConfigBaseline.id.desc())
                .limit(min(max(limit, 1), 100))
            )
        )

    def latest(self, *, scope: str = LIVE_SCOPE) -> ConfigBaseline | None:
        baselines = self.list(limit=1, scope=scope)
        return baselines[0] if baselines else None

    def latest_covering(
        self,
        paths: list[str],
        *,
        scope: str = LIVE_SCOPE,
    ) -> ConfigBaseline | None:
        normalized_paths = {
            path.strip()
            for path in paths
            if isinstance(path, str) and path.strip()
        }
        if not normalized_paths:
            return self.latest(scope=scope)
        for baseline in self.list(limit=100, scope=scope):
            baseline_paths = {
                str(path).strip()
                for path in baseline.paths_json
                if str(path).strip()
            }
            if normalized_paths.issubset(baseline_paths):
                return baseline
        return None

    def compare(
        self,
        baseline_id: int,
        *,
        scope: str | None = None,
        paths: list[str] | None = None,
    ) -> ConfigBaselineCheck:
        baseline = self.session.get(ConfigBaseline, baseline_id)
        expected_scope = scope.strip().upper() if scope is not None else None
        if expected_scope is not None and expected_scope not in BASELINE_SCOPES:
            raise ValueError(f"unsupported config baseline scope: {scope}")
        if baseline is None or (expected_scope is not None and baseline.scope != expected_scope):
            raise LookupError(f"config baseline not found: {baseline_id}")

        baseline_paths = {
            str(path).strip()
            for path in baseline.paths_json
            if str(path).strip()
        }
        requested_paths = (
            {
                path.strip()
                for path in paths
                if isinstance(path, str) and path.strip()
            }
            if paths is not None
            else baseline_paths
        )
        if not requested_paths:
            raise ValueError("config baseline comparison requires at least one path")
        if not requested_paths.issubset(baseline_paths):
            raise ValueError("comparison paths must be covered by the selected baseline")
        selected_snapshots = [
            snapshot
            for snapshot in baseline.snapshot_json
            if isinstance(snapshot, dict)
            and str(snapshot.get("path") or "") in requested_paths
        ]

        result = self.registry.call(
            "config_integrity_scan",
            {"paths": sorted(requested_paths)},
        )
        current_snapshot = [_safe_snapshot(item) for item in result.observations]
        current_by_path = {
            item["path"]: item
            for item in current_snapshot
            if item.get("path")
        }

        changes: list[dict[str, Any]] = []
        unchanged = 0
        added = 0
        missing = 0
        incomplete = False
        for original in selected_snapshots:
            path = original["path"]
            current = current_by_path.get(path)
            if current is None:
                incomplete = True
                changes.append(
                    {
                        "path": path,
                        "change_types": ["unavailable"],
                        "baseline": original,
                        "current": None,
                    }
                )
                continue

            baseline_exists = bool(original.get("exists"))
            current_exists = bool(current.get("exists"))
            change_types: list[str] = []
            if not baseline_exists and current_exists:
                added += 1
                change_types.append("added")
            elif baseline_exists and not current_exists:
                missing += 1
                change_types.append("missing")
            elif baseline_exists and current_exists:
                if _fields_changed(original, current, CONTENT_FIELDS):
                    change_types.append("content_changed")
                if _fields_changed(original, current, PERMISSION_FIELDS):
                    change_types.append("permission_changed")
                if _fields_changed(original, current, METADATA_FIELDS):
                    change_types.append("metadata_changed")

            if change_types:
                changes.append(
                    {
                        "path": path,
                        "change_types": change_types,
                        "baseline": original,
                        "current": current,
                    }
                )
            else:
                unchanged += 1

        status = "incomplete" if incomplete else ("drifted" if changes else "clean")
        check = ConfigBaselineCheck(
            baseline_id=baseline.id,
            status=status,
            summary_json={
                "total": len(selected_snapshots),
                "unchanged": unchanged,
                "changed": len(changes),
                "missing": missing,
                "added": added,
            },
            changes_json=changes,
            current_snapshot_json=current_snapshot,
            warnings_json=result.warnings,
        )
        self.session.add(check)
        self.session.flush()
        return check

    def list_checks(
        self,
        baseline_id: int,
        limit: int = 20,
        *,
        scope: str | None = None,
    ) -> list[ConfigBaselineCheck]:
        baseline = self.session.get(ConfigBaseline, baseline_id)
        expected_scope = scope.strip().upper() if scope is not None else None
        if expected_scope is not None and expected_scope not in BASELINE_SCOPES:
            raise ValueError(f"unsupported config baseline scope: {scope}")
        if baseline is None or (expected_scope is not None and baseline.scope != expected_scope):
            raise LookupError(f"config baseline not found: {baseline_id}")
        return list(
            self.session.scalars(
                select(ConfigBaselineCheck)
                .where(ConfigBaselineCheck.baseline_id == baseline_id)
                .order_by(ConfigBaselineCheck.id.desc())
                .limit(min(max(limit, 1), 100))
            )
        )
