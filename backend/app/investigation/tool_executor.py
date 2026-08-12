from __future__ import annotations

import hashlib
import json
import time

from sqlalchemy.orm import Session

from backend.app.audit.service import AuditService
from backend.app.mcp.registry import ToolCapabilityUnavailableError, ToolRegistry
from backend.app.mcp.types import ToolDefinition, schema_hash, tool_runtime_manifest
from backend.app.models.entities import (
    PlatformCapabilitySnapshot,
    SystemSnapshot,
    Task,
    ToolCall,
    utcnow,
)
from backend.app.schemas.enums import TaskStatus


class MCPObservationExecutor:
    def __init__(
        self,
        session: Session,
        registry: ToolRegistry,
        audit: AuditService,
    ) -> None:
        self.session = session
        self.registry = registry
        self.audit = audit

    def execute(
        self,
        task: Task,
        tool_name: str,
        arguments: dict,
        *,
        reason: str,
        source: str,
        iteration: int | None = None,
        stage: str = TaskStatus.PERCEIVE.value,
    ) -> ToolCall:
        if stage not in {
            TaskStatus.PERCEIVE.value,
            TaskStatus.DYNAMIC_REVIEW.value,
            TaskStatus.VERIFY.value,
        }:
            raise ValueError(f"unsupported observation audit stage: {stage}")
        tool = self.registry.get(tool_name)
        started = time.monotonic()
        call = ToolCall(
            task_id=task.id,
            tool_name=tool.name,
            tool_version=tool.version,
            input_json=arguments,
            risk_level=tool.risk_level.value,
            status="running",
        )
        self.session.add(call)
        self.session.flush()
        try:
            result = self.registry.call(tool.name, arguments)
            call.status = result.status
            call.output_json = result.model_dump(mode="json")
            if tool.name == "system_snapshot":
                self.session.add(SystemSnapshot(task_id=task.id, payload_json=call.output_json))
            elif tool.name == "platform_capability_profile":
                self._persist_platform_capability_snapshot(task, call.output_json)
        except ToolCapabilityUnavailableError as exc:
            call.status = "unavailable"
            call.output_json = {
                "status": "unavailable",
                "warnings": [str(exc)[:1000]],
                "summary_fields": {
                    "required_capabilities": exc.requirements,
                    "capability_gaps": exc.reasons,
                },
            }
        except Exception as exc:
            call.status = "error"
            call.output_json = {
                "status": "error",
                "warnings": [str(exc)[:1000]],
            }
        finally:
            call.ended_at = utcnow()
            call.duration_ms = int((time.monotonic() - started) * 1000)
            self.audit.append_event(
                task,
                stage,
                "tool_call",
                f"调用工具 {tool.name} 完成，状态 {call.status}。",
                {
                    "tool_call_id": call.id,
                    "tool_name": tool.name,
                    "tool_version": tool.version,
                    **tool_schema_evidence(tool),
                    "tool_integrity": self.registry.tool_integrity(tool.name),
                    "input": call.input_json,
                    "output": call.output_json,
                    "duration_ms": call.duration_ms,
                    "reason": reason,
                    "source": source,
                    "iteration": iteration,
                },
            )
        return call

    def _persist_platform_capability_snapshot(
        self,
        task: Task,
        output: dict,
    ) -> None:
        observations = output.get("observations")
        if not isinstance(observations, list) or not observations:
            return
        profile = observations[0]
        if not isinstance(profile, dict):
            return
        platform = profile.get("platform")
        platform = platform if isinstance(platform, dict) else {}
        os_release = platform.get("os_release")
        os_release = os_release if isinstance(os_release, dict) else {}
        payload = json.dumps(
            profile,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        snapshot = PlatformCapabilitySnapshot(
            task_id=task.id,
            hostname=str(platform.get("hostname") or "unknown"),
            machine=str(platform.get("machine") or "unknown"),
            kernel=str(platform.get("kernel") or "unknown"),
            os_name=str(
                os_release.get("pretty_name")
                or os_release.get("name")
                or "unknown"
            ),
            profile_version=str(profile.get("profile_version") or "unknown"),
            status=str(profile.get("status") or "UNAVAILABLE"),
            payload_hash=hashlib.sha256(payload).hexdigest(),
            payload_json=profile,
        )
        self.session.add(snapshot)
        self.session.flush()


def tool_schema_evidence(tool: ToolDefinition) -> dict[str, str]:
    manifest = tool_runtime_manifest(tool)
    return {
        "input_schema_hash": schema_hash(tool.input_model.model_json_schema()),
        "output_schema_hash": schema_hash(tool.output_model.model_json_schema()),
        "tool_manifest_hash": str(manifest["manifest_sha256"]),
        "implementation_hash": str(manifest["implementation_sha256"]),
    }
