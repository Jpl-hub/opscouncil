from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import inspect
import json
import marshal
from pathlib import Path
from typing import Any

from backend.app.core.pydantic_compat import BaseModel, Field

from backend.app.schemas.enums import RiskLevel


class ToolResult(BaseModel):
    status: str = "ok"
    observations: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    summary_fields: dict[str, Any] = Field(default_factory=dict)
    risk_hints: list[str] = Field(default_factory=list)
    actions_proposed: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)


def schema_hash(schema: dict[str, Any]) -> str:
    payload = json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    version: str
    description: str
    risk_level: RiskLevel
    input_model: type[BaseModel]
    output_model: type[ToolResult]
    handler: Callable[[BaseModel], ToolResult]
    dry_run_supported: bool = True
    rollback_strategy: str = "none"
    capability_requirements: tuple[str, ...] = ()

    def to_public_dict(self) -> dict[str, Any]:
        input_schema = self.input_model.model_json_schema()
        output_schema = self.output_model.model_json_schema()
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "dry_run_supported": self.dry_run_supported,
            "rollback_strategy": self.rollback_strategy,
            "capability_requirements": list(self.capability_requirements),
            "input_schema": input_schema,
            "output_schema": output_schema,
            "input_schema_hash": schema_hash(input_schema),
            "output_schema_hash": schema_hash(output_schema),
            "runtime_manifest": tool_runtime_manifest(self),
        }


def tool_runtime_manifest(tool: ToolDefinition) -> dict[str, Any]:
    input_schema_hash = schema_hash(tool.input_model.model_json_schema())
    output_schema_hash = schema_hash(tool.output_model.model_json_schema())
    payload = {
        "manifest_version": "1.0.0",
        "name": tool.name,
        "version": tool.version,
        "risk_level": tool.risk_level.value,
        "permission_mode": (
            "READ_ONLY"
            if tool.risk_level in {RiskLevel.R0, RiskLevel.R1}
            else "CONTROLLED_CHANGE"
        ),
        "dry_run_supported": tool.dry_run_supported,
        "rollback_strategy": tool.rollback_strategy,
        "capability_requirements": list(tool.capability_requirements),
        "source_module": tool.handler.__module__,
        "implementation_sha256": _implementation_hash(tool.handler),
        "input_schema_sha256": input_schema_hash,
        "output_schema_sha256": output_schema_hash,
    }
    return {
        **payload,
        "manifest_sha256": schema_hash(payload),
    }


def _implementation_hash(handler: Callable[[BaseModel], ToolResult]) -> str:
    source_file = inspect.getsourcefile(handler)
    if source_file:
        try:
            return hashlib.sha256(Path(source_file).read_bytes()).hexdigest()
        except OSError:
            pass
    code = getattr(handler, "__code__", None)
    if code is not None:
        return hashlib.sha256(marshal.dumps(code)).hexdigest()
    identity = f"{handler.__module__}:{handler.__qualname__}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()
