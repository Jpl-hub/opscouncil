from __future__ import annotations

from collections.abc import Callable
import time
from typing import Any

from backend.app.core.pydantic_compat import BaseModel, ValidationError

from backend.app.deployment.capabilities import (
    CAPABILITY_DEGRADED,
    CAPABILITY_SUPPORTED,
    CAPABILITY_UNAVAILABLE,
)
from backend.app.mcp.semantics import enrich_tool_result
from backend.app.mcp.types import ToolDefinition, ToolResult, tool_runtime_manifest


class ToolNotFoundError(KeyError):
    pass


class ToolValidationError(ValueError):
    pass


class ToolCapabilityUnavailableError(RuntimeError):
    def __init__(
        self,
        tool_name: str,
        requirements: list[str],
        reasons: list[str],
    ) -> None:
        self.tool_name = tool_name
        self.requirements = requirements
        self.reasons = reasons
        detail = "；".join(reasons) or "运行时能力探测未返回可用证据"
        super().__init__(f"工具 {tool_name} 的运行前置条件不满足：{detail}")


class ToolIntegrityError(RuntimeError):
    pass


class ToolRegistry:
    def __init__(
        self,
        *,
        capability_provider: Callable[[], dict[str, Any]] | None = None,
        capability_ttl_seconds: int = 60,
    ) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._registered_manifest_hashes: dict[str, str] = {}
        self._capability_provider = capability_provider
        self._capability_ttl_seconds = max(1, capability_ttl_seconds)
        self._capability_cache: dict[str, Any] | None = None
        self._capability_cached_at = 0.0

    def register(self, tool: ToolDefinition) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool registered: {tool.name}")
        self._tools[tool.name] = tool
        self._registered_manifest_hashes[tool.name] = tool_runtime_manifest(tool)[
            "manifest_sha256"
        ]

    def scoped(self, allowed_names: set[str] | frozenset[str]) -> "ScopedToolRegistry":
        unknown = sorted(set(allowed_names) - set(self._tools))
        if unknown:
            raise ValueError(f"unknown tools in registry scope: {', '.join(unknown)}")
        return ScopedToolRegistry(self, frozenset(allowed_names))

    def list_tools(self) -> list[dict]:
        items: list[dict[str, Any]] = []
        for tool in sorted(self._tools.values(), key=lambda item: item.name):
            item = tool.to_public_dict()
            item["availability"] = self.tool_availability(tool.name)
            item["integrity"] = self.tool_integrity(tool.name)
            items.append(item)
        return items

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolNotFoundError(name) from exc

    def call(self, name: str, payload: dict) -> ToolResult:
        tool = self.get(name)
        integrity = self.tool_integrity(name)
        if integrity["status"] != "VERIFIED":
            raise ToolIntegrityError(
                f"工具 {name} 的运行清单已漂移，拒绝执行并等待重新部署"
            )
        availability = self.tool_availability(name)
        if not availability["available"]:
            raise ToolCapabilityUnavailableError(
                name,
                availability["required_capabilities"],
                availability["reasons"],
            )
        try:
            validated: BaseModel = tool.input_model.model_validate(payload)
        except ValidationError as exc:
            raise ToolValidationError(str(exc)) from exc
        result = enrich_tool_result(tool.name, tool.handler(validated))
        if tool.name == "platform_capability_profile" and result.observations:
            profile = result.observations[0]
            if isinstance(profile, dict):
                self.set_capability_profile(profile)
        return result

    def tool_integrity(self, name: str) -> dict[str, Any]:
        tool = self.get(name)
        current = tool_runtime_manifest(tool)
        expected_hash = self._registered_manifest_hashes[name]
        current_hash = str(current["manifest_sha256"])
        return {
            "status": "VERIFIED" if current_hash == expected_hash else "DRIFTED",
            "expected_manifest_sha256": expected_hash,
            "current_manifest_sha256": current_hash,
            "implementation_sha256": current["implementation_sha256"],
            "source_module": current["source_module"],
            "permission_mode": current["permission_mode"],
        }

    def capability_profile(self, *, force: bool = False) -> dict[str, Any] | None:
        if self._capability_provider is None:
            return None
        cache_valid = (
            self._capability_cache is not None
            and time.monotonic() - self._capability_cached_at
            < self._capability_ttl_seconds
        )
        if cache_valid and not force:
            return self._capability_cache
        try:
            profile = self._capability_provider()
        except Exception as exc:
            profile = {
                "profile_version": "1.0.0",
                "status": CAPABILITY_UNAVAILABLE,
                "probe_error": str(exc)[:500],
                "capabilities": {},
            }
        self.set_capability_profile(profile)
        return profile

    def set_capability_profile(self, profile: dict[str, Any]) -> None:
        self._capability_cache = profile
        self._capability_cached_at = time.monotonic()

    def tool_availability(
        self,
        name: str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        tool = self.get(name)
        requirements = list(tool.capability_requirements)
        if not requirements:
            return {
                "status": CAPABILITY_SUPPORTED,
                "available": True,
                "required_capabilities": [],
                "reasons": [],
            }

        profile = self.capability_profile(force=force)
        if profile is None:
            return {
                "status": "UNKNOWN",
                "available": True,
                "required_capabilities": requirements,
                "reasons": ["当前注册表未配置主机能力探针。"],
            }

        capabilities = profile.get("capabilities")
        capabilities = capabilities if isinstance(capabilities, dict) else {}
        reasons: list[str] = []
        degraded = False
        unavailable = False
        for requirement in requirements:
            item = capabilities.get(requirement)
            if not isinstance(item, dict):
                unavailable = True
                reasons.append(f"{requirement} 未出现在能力快照中")
                continue
            status = str(item.get("status") or CAPABILITY_UNAVAILABLE)
            if status == CAPABILITY_UNAVAILABLE:
                unavailable = True
                reasons.append(
                    f"{requirement}: {item.get('reason') or '不可用'}"
                )
            elif status != CAPABILITY_SUPPORTED:
                degraded = True
                reasons.append(
                    f"{requirement}: {item.get('reason') or '降级'}"
                )
        return {
            "status": (
                CAPABILITY_UNAVAILABLE
                if unavailable
                else CAPABILITY_DEGRADED
                if degraded
                else CAPABILITY_SUPPORTED
            ),
            "available": not unavailable,
            "required_capabilities": requirements,
            "reasons": reasons,
            "profile_version": profile.get("profile_version"),
            "probed_at": profile.get("probed_at"),
        }


class ScopedToolRegistry:
    """Read-through registry view that enforces a fixed tool allowlist."""

    def __init__(self, registry: ToolRegistry, allowed_names: frozenset[str]) -> None:
        self._registry = registry
        self._allowed_names = allowed_names

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self._registry.list_tools()
            if item["name"] in self._allowed_names
        ]

    def get(self, name: str) -> ToolDefinition:
        self._require_allowed(name)
        return self._registry.get(name)

    def call(self, name: str, payload: dict[str, Any]) -> ToolResult:
        self._require_allowed(name)
        return self._registry.call(name, payload)

    def tool_availability(self, name: str, *, force: bool = False) -> dict[str, Any]:
        self._require_allowed(name)
        return self._registry.tool_availability(name, force=force)

    def tool_integrity(self, name: str) -> dict[str, Any]:
        self._require_allowed(name)
        return self._registry.tool_integrity(name)

    def _require_allowed(self, name: str) -> None:
        if name not in self._allowed_names:
            raise ToolNotFoundError(name)
