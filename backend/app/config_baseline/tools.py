from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from sqlalchemy.orm import Session

from backend.app.config_baseline.service import (
    ConfigBaselineService,
    LAB_SCOPE,
    LIVE_SCOPE,
)
from backend.app.core.pydantic_compat import BaseModel, Field, field_validator
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.schemas.enums import RiskLevel


class ConfigBaselineCheckInput(BaseModel):
    paths: list[str] = Field(default_factory=list)
    scope: Literal["LIVE", "LAB"] = LIVE_SCOPE

    @field_validator("paths")
    @classmethod
    def normalize_paths(cls, value: list[str]) -> list[str]:
        paths = list(
            dict.fromkeys(
                path.strip()
                for path in value
                if isinstance(path, str) and path.strip()
            )
        )
        if len(paths) > 20:
            raise ValueError("单次最多检查 20 个配置路径")
        return paths


def register_config_baseline_tool(
    registry: ToolRegistry,
    session_factory: Callable[[], Session],
) -> None:
    def config_baseline_check(payload: BaseModel) -> ToolResult:
        args = ConfigBaselineCheckInput.model_validate(payload)
        with session_factory() as session:
            service = ConfigBaselineService(session, registry)
            baseline = service.latest_covering(args.paths, scope=args.scope)
            if baseline is None:
                current = registry.call(
                    "config_integrity_scan",
                    {"paths": args.paths or _default_paths(args.scope)},
                )
                observations = [
                    {
                        **item,
                        "baseline_available": False,
                        "baseline_scope": args.scope,
                        "baseline_status": "unavailable",
                        "change_types": [],
                    }
                    for item in current.observations
                ]
                return ToolResult(
                    status=current.status,
                    observations=observations,
                    evidence_refs=list(current.evidence_refs),
                    warnings=[
                        *current.warnings,
                        "当前路径没有已确认配置基线，只能形成本次安全采样，不能判定漂移。",
                    ],
                    summary_fields={
                        "baseline_available": False,
                        "scope": args.scope,
                        "status": "unavailable",
                        "sampled": len(observations),
                    },
                    risk_hints=list(current.risk_hints),
                )

            check = service.compare(
                baseline.id,
                scope=args.scope,
                paths=args.paths or list(baseline.paths_json),
            )
            session.commit()
            changes_by_path = {
                str(item.get("path")): item
                for item in check.changes_json
                if isinstance(item, dict) and item.get("path")
            }
            observations = []
            for current in check.current_snapshot_json:
                if not isinstance(current, dict):
                    continue
                change = changes_by_path.get(str(current.get("path"))) or {}
                observations.append(
                    {
                        **current,
                        "baseline_available": True,
                        "baseline_id": baseline.id,
                        "baseline_name": baseline.name,
                        "baseline_scope": baseline.scope,
                        "baseline_status": check.status,
                        "baseline_check_id": check.id,
                        "change_types": list(change.get("change_types") or []),
                    }
                )
            return ToolResult(
                status="partial" if check.status == "incomplete" else "ok",
                observations=observations,
                evidence_refs=[
                    f"config-baseline:{baseline.id}",
                    f"config-baseline-check:{check.id}",
                ],
                warnings=list(check.warnings_json),
                summary_fields={
                    "baseline_available": True,
                    "baseline_id": baseline.id,
                    "baseline_name": baseline.name,
                    "scope": baseline.scope,
                    "baseline_created_at": baseline.created_at.isoformat(),
                    "check_id": check.id,
                    "status": check.status,
                    **dict(check.summary_json),
                },
            )

    registry.register(
        ToolDefinition(
            name="config_baseline_check",
            version="1.0.0",
            description=(
                "Compare approved configuration snapshots with a fresh bounded metadata and "
                "hash sample. LIVE and LAB baselines are selected in separate scopes."
            ),
            risk_level=RiskLevel.R0,
            input_model=ConfigBaselineCheckInput,
            output_model=ToolResult,
            handler=config_baseline_check,
            capability_requirements=("filesystem.read",),
        )
    )


def _default_paths(scope: str) -> list[str]:
    if scope == LAB_SCOPE:
        return [
            "/tmp/opscouncil-lab/etc/service-agent.conf",
            "/tmp/opscouncil-lab/etc/managed-agent.conf",
        ]
    return ["/etc/hosts", "/etc/resolv.conf", "/etc/fstab"]
