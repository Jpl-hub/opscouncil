from __future__ import annotations

from types import SimpleNamespace

import pytest

from backend.app.agent.capability_catalog import CapabilityCatalog, CapabilityCatalogError
from backend.app.mcp.registry import ToolNotFoundError


class VersionRegistry:
    def __init__(self, versions: dict[str, str]) -> None:
        self.versions = versions

    def get(self, name: str) -> SimpleNamespace:
        if name not in self.versions:
            raise ToolNotFoundError(name)
        return SimpleNamespace(name=name, version=self.versions[name])


def valid_payload() -> dict:
    return {
        "catalog_version": "3.0.0",
        "capabilities": [
            {
                "id": "skill.disk_pressure_analysis",
                "version": "1.0.0",
                "status": "ACTIVE",
                "intent": "disk_pressure_analysis",
                "name": "磁盘空间分析",
                "description": "定位磁盘压力来源。",
                "tools": [
                    {
                        "name": "disk_usage",
                        "min_version": "1.0.0",
                        "purpose": "采集磁盘容量。",
                    }
                ],
                "control_nodes": ["STATIC_REVIEW", "PLAN_POLICY", "APPROVAL", "AUDIT"],
                "workflow": ["采集容量", "定位来源", "核对边界"],
                "safety_gates": ["副作用动作必须人工审批"],
                "output_contract": "返回证据、风险和建议。",
            }
        ],
    }


def test_catalog_validates_schema_registry_and_produces_stable_hash() -> None:
    registry = VersionRegistry({"disk_usage": "1.1.0"})

    first = CapabilityCatalog.from_payload(valid_payload(), registry=registry)
    second = CapabilityCatalog.from_payload(valid_payload(), registry=registry)

    assert first.catalog_hash == second.catalog_hash
    assert len(first.catalog_hash) == 64
    capability = first.get_for_intent("disk_pressure_analysis")
    assert capability["version"] == "1.0.0"
    assert capability["tools"][0]["name"] == "disk_usage"


def test_catalog_rejects_unknown_tool() -> None:
    with pytest.raises(CapabilityCatalogError, match="unknown MCP tool"):
        CapabilityCatalog.from_payload(valid_payload(), registry=VersionRegistry({}))


def test_catalog_rejects_tool_below_declared_minimum_version() -> None:
    with pytest.raises(CapabilityCatalogError, match="requires >= 1.0.0"):
        CapabilityCatalog.from_payload(
            valid_payload(),
            registry=VersionRegistry({"disk_usage": "0.9.9"}),
        )


def test_catalog_rejects_executable_or_unknown_fields() -> None:
    payload = valid_payload()
    payload["capabilities"][0]["script"] = "rm -rf /"

    with pytest.raises(CapabilityCatalogError, match="script"):
        CapabilityCatalog.from_payload(
            payload,
            registry=VersionRegistry({"disk_usage": "1.1.0"}),
        )


def test_catalog_rejects_duplicate_intent() -> None:
    payload = valid_payload()
    duplicate = {**payload["capabilities"][0], "id": "skill.disk_pressure_duplicate"}
    payload["capabilities"].append(duplicate)

    with pytest.raises(CapabilityCatalogError, match="duplicate capability intent"):
        CapabilityCatalog.from_payload(
            payload,
            registry=VersionRegistry({"disk_usage": "1.1.0"}),
        )


def test_repository_catalog_loads_and_has_no_executable_payload() -> None:
    catalog = CapabilityCatalog.load_default()

    assert len(catalog.list_active()) >= 7
    assert all("script" not in capability for capability in catalog.list_active())
    assert all(capability["status"] == "ACTIVE" for capability in catalog.list_active())
