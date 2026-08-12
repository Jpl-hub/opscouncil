from __future__ import annotations

from functools import lru_cache
import hashlib
import json
from typing import Any

from backend.app.agent.capability_catalog import CapabilityCatalog, CapabilityCatalogError
from backend.app.agent.planner import Plan


class SkillPolicyError(ValueError):
    def __init__(self, message: str, rejected_tools: list[str] | None = None) -> None:
        super().__init__(message)
        self.rejected_tools = rejected_tools or []


@lru_cache(maxsize=1)
def _catalog() -> CapabilityCatalog:
    return CapabilityCatalog.load_default()


def validate_catalog_registry(registry: Any) -> None:
    try:
        _catalog().validate_registry(registry)
    except CapabilityCatalogError as exc:
        raise SkillPolicyError(str(exc)) from exc


def list_agent_skills() -> list[dict[str, Any]]:
    return _catalog().list_active()


def get_agent_skill(intent: str) -> dict[str, Any]:
    try:
        return _catalog().get_for_intent(intent)
    except CapabilityCatalogError as exc:
        raise SkillPolicyError(str(exc)) from exc


def validate_plan_against_skill(plan: Plan, registry: Any | None = None) -> dict[str, Any]:
    skill = get_agent_skill(plan.intent)
    allowed_tools = [tool["name"] for tool in skill["tools"]]
    allowed_tool_set = set(allowed_tools)
    used_tools = list(dict.fromkeys(call.tool_name for call in plan.tool_calls))
    rejected_tools = [tool_name for tool_name in used_tools if tool_name not in allowed_tool_set]
    if rejected_tools:
        raise SkillPolicyError(
            f"plan for {plan.intent} uses tools outside selected skill: {', '.join(rejected_tools)}",
            rejected_tools=rejected_tools,
        )
    tool_attestations: list[dict[str, Any]] = []
    execution_manifest_hash = ""
    if registry is not None:
        try:
            _catalog().validate_tools(skill, registry, used_tools)
        except CapabilityCatalogError as exc:
            raise SkillPolicyError(str(exc), rejected_tools=used_tools) from exc
        tool_attestations = [registry.tool_integrity(name) | {"name": name} for name in allowed_tools]
        drifted = [item["name"] for item in tool_attestations if item["status"] != "VERIFIED"]
        if drifted:
            raise SkillPolicyError(
                "runtime tool manifest drift detected: " + ", ".join(drifted),
                rejected_tools=drifted,
            )
        execution_manifest_hash = hashlib.sha256(
            json.dumps(
                {
                    "catalog_hash": skill["catalog_hash"],
                    "tools": [
                        {
                            "name": item["name"],
                            "manifest_sha256": item["expected_manifest_sha256"],
                        }
                        for item in tool_attestations
                    ],
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    return {
        "skill_id": skill["id"],
        "skill_name": skill["name"],
        "skill_version": skill["version"],
        "catalog_version": skill["catalog_version"],
        "catalog_hash": skill["catalog_hash"],
        "execution_manifest_hash": execution_manifest_hash,
        "tool_attestations": tool_attestations,
        "intent": skill["intent"],
        "used_tools": used_tools,
        "allowed_tools": allowed_tools,
        "control_nodes": skill["control_nodes"],
        "workflow": skill["workflow"],
        "safety_gates": skill["safety_gates"],
        "output_contract": skill["output_contract"],
    }
