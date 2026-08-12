from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.executor.tools import register_executor_tools
from backend.app.mcp.protocol import MCP_PROTOCOL_VERSION, build_mcp_router
from backend.app.perception.tools import build_perception_registry


def build_client() -> TestClient:
    registry = build_perception_registry()
    register_executor_tools(registry)
    app = FastAPI()
    app.include_router(build_mcp_router(registry))
    return TestClient(app)


class MCPProtocolTest(unittest.TestCase):
    def test_initialize_negotiates_tools_capability(self) -> None:
        response = build_client().post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "unit-test", "version": "1.0.0"},
                },
            },
            headers={"Accept": "application/json, text/event-stream"},
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["jsonrpc"], "2.0")
        self.assertEqual(body["id"], 1)
        self.assertEqual(body["result"]["protocolVersion"], MCP_PROTOCOL_VERSION)
        self.assertEqual(body["result"]["capabilities"]["tools"]["listChanged"], True)
        self.assertEqual(body["result"]["serverInfo"]["name"], "opscouncil-agent")

    def test_initialized_notification_is_accepted_without_body(self) -> None:
        response = build_client().post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers={"Accept": "application/json, text/event-stream"},
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.content, b"")

    def test_get_mcp_endpoint_reports_post_only(self) -> None:
        response = build_client().get("/mcp")

        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.headers["allow"], "POST")
        self.assertEqual(response.json()["error"]["code"], -32000)

    def test_lists_registered_tools_with_mcp_schema_and_safety_annotations(self) -> None:
        response = build_client().post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            },
        )

        self.assertEqual(response.status_code, 200)
        result = response.json()["result"]
        tools = {tool["name"]: tool for tool in result["tools"]}

        self.assertIn("system_snapshot", tools)
        self.assertIn("platform_capability_profile", tools)
        self.assertEqual(
            tools["platform_capability_profile"]["title"],
            "主机能力画像",
        )
        self.assertEqual(tools["system_snapshot"]["inputSchema"]["type"], "object")
        self.assertTrue(tools["system_snapshot"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["system_snapshot"]["annotations"]["destructiveHint"])
        self.assertEqual(tools["system_snapshot"]["_meta"]["riskLevel"], "R0")
        self.assertRegex(tools["system_snapshot"]["_meta"]["inputSchemaHash"], r"^[a-f0-9]{64}$")
        self.assertRegex(tools["system_snapshot"]["_meta"]["outputSchemaHash"], r"^[a-f0-9]{64}$")
        self.assertEqual(tools["system_snapshot"]["_meta"]["integrity"]["status"], "VERIFIED")
        self.assertRegex(
            tools["system_snapshot"]["_meta"]["integrity"]["current_manifest_sha256"],
            r"^[a-f0-9]{64}$",
        )
        self.assertIn(
            "kernel.procfs",
            tools["system_snapshot"]["_meta"]["capabilityRequirements"],
        )
        self.assertTrue(
            tools["system_snapshot"]["_meta"]["availability"]["available"]
        )

        self.assertIn("time_sync_status", tools)
        self.assertTrue(tools["time_sync_status"]["annotations"]["readOnlyHint"])
        self.assertEqual(tools["time_sync_status"]["_meta"]["riskLevel"], "R0")

        self.assertIn("service_dependency_snapshot", tools)
        self.assertEqual(
            tools["service_dependency_snapshot"]["title"],
            "服务关系快照",
        )
        self.assertTrue(
            tools["service_dependency_snapshot"]["annotations"]["readOnlyHint"]
        )

        self.assertIn("safe_log_rotate", tools)
        self.assertFalse(tools["safe_log_rotate"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["safe_log_rotate"]["annotations"]["destructiveHint"])
        self.assertEqual(tools["safe_log_rotate"]["_meta"]["approval"], "required_for_execution")
        self.assertRegex(tools["safe_log_rotate"]["_meta"]["inputSchemaHash"], r"^[a-f0-9]{64}$")
        self.assertRegex(tools["safe_log_rotate"]["_meta"]["outputSchemaHash"], r"^[a-f0-9]{64}$")

        self.assertIn("restore_log_backup", tools)
        self.assertEqual(tools["restore_log_backup"]["title"], "日志备份恢复")
        self.assertFalse(tools["restore_log_backup"]["annotations"]["readOnlyHint"])
        self.assertEqual(tools["restore_log_backup"]["_meta"]["approval"], "required_for_execution")
        self.assertEqual(
            tools["restore_log_backup"]["_meta"]["rollbackStrategy"],
            "restore_pre_restore_snapshot",
        )

        self.assertIn("restart_managed_service", tools)
        self.assertEqual(tools["restart_managed_service"]["title"], "受控服务重启")
        self.assertFalse(tools["restart_managed_service"]["annotations"]["readOnlyHint"])
        self.assertEqual(tools["restart_managed_service"]["_meta"]["riskLevel"], "R3")
        self.assertEqual(
            tools["restart_managed_service"]["_meta"]["rollbackStrategy"],
            "manual_takeover",
        )

        self.assertIn("file_integrity_state", tools)
        self.assertEqual(tools["file_integrity_state"]["title"], "文件完整性校验")
        self.assertTrue(tools["file_integrity_state"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["file_integrity_state"]["annotations"]["destructiveHint"])
        self.assertEqual(tools["file_integrity_state"]["_meta"]["riskLevel"], "R0")

    def test_calls_readonly_tool_and_returns_structured_content(self) -> None:
        response = build_client().post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "system_snapshot", "arguments": {}},
            },
            headers={
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            },
        )

        self.assertEqual(response.status_code, 200)
        result = response.json()["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["status"], "ok")
        self.assertIsInstance(result["structuredContent"]["observations"], list)
        self.assertEqual(result["content"][0]["type"], "text")

    def test_rejects_non_dry_run_side_effect_tool_call_inside_tool_result(self) -> None:
        with tempfile.NamedTemporaryFile(prefix="opscouncil-mcp-", dir="/tmp") as handle:
            Path(handle.name).write_text("test log\n", encoding="utf-8")
            response = build_client().post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "safe_log_rotate",
                        "arguments": {"path": handle.name, "dry_run": False},
                    },
                },
                headers={
                    "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                },
            )

        self.assertEqual(response.status_code, 200)
        result = response.json()["result"]
        self.assertTrue(result["isError"])
        self.assertIn("requires approval", result["content"][0]["text"])

    def test_unknown_tool_is_protocol_error(self) -> None:
        response = build_client().post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "missing_tool", "arguments": {}},
            },
            headers={
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["error"]["code"], -32602)
        self.assertIn("Unknown tool", body["error"]["message"])

    def test_rejects_direct_restore_execution_without_approval(self) -> None:
        response = build_client().post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "restore_log_backup",
                    "arguments": {
                        "artifact_path": "/tmp/app.log.opscouncil.1234abcd.bak.gz",
                        "restore_target": "/tmp/app.log",
                        "dry_run": False,
                    },
                },
            },
            headers={
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            },
        )

        self.assertEqual(response.status_code, 200)
        result = response.json()["result"]
        self.assertTrue(result["isError"])
        self.assertIn("requires approval", result["content"][0]["text"])

    def test_rejects_non_local_origin_for_streamable_http(self) -> None:
        response = build_client().post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 6, "method": "tools/list"},
            headers={
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                "Origin": "https://example.com",
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], -32000)


if __name__ == "__main__":
    unittest.main()
