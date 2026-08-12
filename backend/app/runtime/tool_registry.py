from __future__ import annotations

from collections.abc import Callable
from typing import Any

from backend.app.agent.skills import validate_catalog_registry
from backend.app.assets.tools import register_service_expectation_tool
from backend.app.config_baseline.tools import register_config_baseline_tool
from backend.app.executor.tools import register_executor_tools
from backend.app.mcp.registry import ToolRegistry
from backend.app.perception.tools import build_perception_registry


def build_runtime_tool_registry(
    session_factory: Callable[[], Any],
) -> ToolRegistry:
    """Build the authoritative tool registry shared by API and workers."""
    registry = build_perception_registry()
    register_executor_tools(registry)
    register_config_baseline_tool(registry, session_factory)
    register_service_expectation_tool(registry, session_factory)
    validate_catalog_registry(registry)
    return registry
