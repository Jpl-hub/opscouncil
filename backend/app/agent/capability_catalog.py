from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Literal

from backend.app.core.pydantic_compat import BaseModel, Field, ValidationError
from backend.app.mcp.registry import ToolNotFoundError


CATALOG_PATH = Path(__file__).with_name("capabilities.json")
SCHEMA_PATH = Path(__file__).with_name("capability.schema.json")
_SEMVER_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class CapabilityCatalogError(ValueError):
    pass


class _StrictSchemaModel(BaseModel):
    class Config:
        extra = "forbid"


class _ToolSchema(_StrictSchemaModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,127}$")
    min_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    purpose: str = Field(min_length=2, max_length=300)


class _CapabilitySchema(_StrictSchemaModel):
    id: str = Field(pattern=r"^skill\.[a-z][a-z0-9_.-]{2,120}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    status: Literal["ACTIVE", "DRAFT", "INACTIVE"]
    intent: str = Field(pattern=r"^[a-z][a-z0-9_]{2,127}$")
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(min_length=5, max_length=500)
    tools: list[_ToolSchema] = Field(default_factory=list, max_items=30)
    control_nodes: list[
        Literal[
            "STATIC_REVIEW",
            "PLAN_POLICY",
            "INVESTIGATION",
            "APPROVAL",
            "EXECUTION",
            "VERIFICATION",
            "AUDIT",
        ]
    ] = Field(min_items=1)
    workflow: list[str] = Field(min_items=3, max_items=12)
    safety_gates: list[str] = Field(min_items=1, max_items=12)
    output_contract: str = Field(min_length=5, max_length=500)


class _CatalogSchema(_StrictSchemaModel):
    catalog_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    capabilities: list[_CapabilitySchema] = Field(min_items=1)


class CapabilityCatalog:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = deepcopy(payload)
        self.catalog_version = str(payload["catalog_version"])
        self.catalog_hash = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self._by_intent = {
            capability["intent"]: capability
            for capability in payload["capabilities"]
            if capability["status"] == "ACTIVE"
        }

    @classmethod
    def load_default(cls, registry: Any | None = None) -> "CapabilityCatalog":
        return cls.load(CATALOG_PATH, schema_path=SCHEMA_PATH, registry=registry)

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        schema_path: Path = SCHEMA_PATH,
        registry: Any | None = None,
    ) -> "CapabilityCatalog":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapabilityCatalogError(f"unable to load capability catalog: {exc}") from exc
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CapabilityCatalogError(f"unable to load capability schema: {exc}") from exc
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise CapabilityCatalogError("capability schema must declare JSON Schema draft 2020-12")
        return cls.from_payload(payload, registry=registry)

    @classmethod
    def from_payload(
        cls,
        payload: dict[str, Any],
        *,
        registry: Any | None = None,
    ) -> "CapabilityCatalog":
        try:
            validated = _CatalogSchema.model_validate(payload).model_dump(mode="json")
        except ValidationError as exc:
            raise CapabilityCatalogError(f"capability schema violation: {exc}") from exc
        _validate_uniqueness(validated["capabilities"])
        catalog = cls(validated)
        if registry is not None:
            catalog.validate_registry(registry)
        return catalog

    def list_active(self) -> list[dict[str, Any]]:
        return [self._public(capability) for capability in self._by_intent.values()]

    def get_for_intent(self, intent: str) -> dict[str, Any]:
        try:
            return self._public(self._by_intent[intent])
        except KeyError as exc:
            raise CapabilityCatalogError(f"unknown active capability intent: {intent}") from exc

    def validate_registry(self, registry: Any) -> None:
        for capability in self._by_intent.values():
            self.validate_tools(capability, registry, [tool["name"] for tool in capability["tools"]])

    def validate_tools(
        self,
        capability: dict[str, Any],
        registry: Any,
        tool_names: list[str],
    ) -> None:
        requirements = {tool["name"]: tool["min_version"] for tool in capability["tools"]}
        for tool_name in tool_names:
            minimum = requirements.get(tool_name)
            if minimum is None:
                raise CapabilityCatalogError(
                    f"capability {capability['id']} does not allow MCP tool {tool_name}"
                )
            try:
                registered = registry.get(tool_name)
            except (ToolNotFoundError, KeyError) as exc:
                raise CapabilityCatalogError(
                    f"capability {capability['id']} references unknown MCP tool {tool_name}"
                ) from exc
            if _semver(registered.version) < _semver(minimum):
                raise CapabilityCatalogError(
                    f"MCP tool {tool_name} {registered.version} requires >= {minimum}"
                )

    def _public(self, capability: dict[str, Any]) -> dict[str, Any]:
        return {
            **deepcopy(capability),
            "catalog_version": self.catalog_version,
            "catalog_hash": self.catalog_hash,
        }


def _validate_uniqueness(capabilities: list[dict[str, Any]]) -> None:
    seen_ids: set[str] = set()
    seen_intents: set[str] = set()
    for capability in capabilities:
        capability_id = capability["id"]
        intent = capability["intent"]
        if capability_id in seen_ids:
            raise CapabilityCatalogError(f"duplicate capability id: {capability_id}")
        if intent in seen_intents:
            raise CapabilityCatalogError(f"duplicate capability intent: {intent}")
        seen_ids.add(capability_id)
        seen_intents.add(intent)
        tool_names = [tool["name"] for tool in capability["tools"]]
        if len(tool_names) != len(set(tool_names)):
            raise CapabilityCatalogError(f"duplicate MCP tool in capability {capability_id}")


def _semver(value: str) -> tuple[int, int, int]:
    match = _SEMVER_PATTERN.fullmatch(str(value))
    if match is None:
        raise CapabilityCatalogError(f"invalid semantic version: {value}")
    return tuple(int(item) for item in match.groups())
