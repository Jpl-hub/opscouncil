from __future__ import annotations

import unittest

from backend.app.mcp.registry import ToolNotFoundError
from backend.app.runtime.tool_registry import build_runtime_tool_registry


class RuntimeToolRegistryTest(unittest.TestCase):
    def test_shared_registry_contains_catalog_and_database_backed_tools(self) -> None:
        registry = build_runtime_tool_registry(lambda: None)
        names = {item["name"] for item in registry.list_tools()}

        self.assertIn("system_snapshot", names)
        self.assertIn("restart_managed_service", names)
        self.assertIn("service_desired_state", names)
        self.assertIn("service_catalog_snapshot", names)
        self.assertIn("config_baseline_check", names)
        self.assertIn("deleted_open_files", names)
        self.assertEqual(27, len(names))

    def test_scoped_registry_hides_and_rejects_tools_outside_role_scope(self) -> None:
        registry = build_runtime_tool_registry(lambda: None)
        scoped = registry.scoped({"system_snapshot", "disk_usage"})

        self.assertEqual(
            {item["name"] for item in scoped.list_tools()},
            {"system_snapshot", "disk_usage"},
        )
        with self.assertRaises(ToolNotFoundError):
            scoped.get("restart_managed_service")
        with self.assertRaises(ToolNotFoundError):
            scoped.call("restart_managed_service", {"unit": "example.service"})


if __name__ == "__main__":
    unittest.main()
