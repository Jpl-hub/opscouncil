from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.api.routes import build_router
from backend.app.deployment.readiness import DeploymentEnvironment, DeploymentReadinessService
from backend.app.mcp.types import ToolResult


class SnapshotRegistry:
    def __init__(self, snapshot: dict, tool_count: int = 5) -> None:
        self.snapshot = snapshot
        self.tool_count = tool_count

    def call(self, tool_name: str, payload: dict) -> ToolResult:
        if tool_name != "system_snapshot":
            raise KeyError(tool_name)
        return ToolResult(observations=[self.snapshot], evidence_refs=["/etc/os-release", "/proc/meminfo"])

    def list_tools(self) -> list[dict]:
        return [{"name": f"tool_{index}", "version": "v1.0.0"} for index in range(self.tool_count)]


class DeploymentReadinessServiceTest(unittest.TestCase):
    def test_linux_loongarch_with_restricted_user_is_ready(self) -> None:
        service = DeploymentReadinessService(
            SnapshotRegistry(
                {
                    "machine": "loongarch64",
                    "os_family": "linux",
                    "is_loongarch": True,
                    "os_release": {
                        "id": "enterprise-linux",
                        "pretty_name": "Enterprise Linux 9",
                        "version_id": "9",
                    },
                }
            ),
            command_exists=lambda command: command in {"journalctl", "ss", "ps"},
            runtime_user=lambda: ("vmuser", 1000),
            environment=DeploymentEnvironment(
                app_env="production",
                frontend_index="/opt/opscouncil/frontend/dist/index.html",
                database_url="postgresql+psycopg://kg:kg@127.0.0.1:5432/opscouncil",
                ai_key_configured=True,
                chat_model="qwen-plus-latest",
                embedding_model="text-embedding-v4",
            ),
            path_exists=lambda path: str(path).endswith("index.html"),
            database_probe=lambda url: {
                "status": "ok",
                "detail": "PostgreSQL reachable, pgvector enabled",
                "evidence": ["postgresql", "pgvector"],
            },
        )

        report = service.read()

        self.assertEqual(report["overall_status"], "ok")
        self.assertEqual(report["summary"], "Linux 平台与运行边界满足部署要求。")
        self.assertEqual(report["platform"]["machine"], "loongarch64")
        self.assertTrue(all(check["status"] == "ok" for check in report["checks"]))
        self.assertEqual(report["environment"]["database"], "postgresql")
        self.assertTrue(report["environment"]["frontend_ready"])
        self.assertTrue(report["environment"]["model_configured"])

    def test_missing_frontend_and_sqlite_are_not_production_ready(self) -> None:
        service = DeploymentReadinessService(
            SnapshotRegistry(
                {
                    "machine": "loongarch64",
                    "os_family": "linux",
                    "is_loongarch": True,
                    "os_release": {
                        "id": "enterprise-linux",
                        "pretty_name": "Enterprise Linux 9",
                        "version_id": "9",
                    },
                }
            ),
            command_exists=lambda command: True,
            runtime_user=lambda: ("vmuser", 1000),
            environment=DeploymentEnvironment(
                app_env="production",
                frontend_index="/opt/opscouncil/frontend/dist/index.html",
                database_url="sqlite:///data/opscouncil.db",
                ai_key_configured=False,
                chat_model="qwen-plus-latest",
                embedding_model="text-embedding-v4",
            ),
            path_exists=lambda path: False,
            database_probe=lambda url: {"status": "ok", "detail": "unexpected"},
        )

        report = service.read()

        statuses = {check["key"]: check["status"] for check in report["checks"]}
        self.assertEqual(report["overall_status"], "blocked")
        self.assertEqual(statuses["frontend"], "blocked")
        self.assertEqual(statuses["database"], "blocked")
        self.assertEqual(statuses["model"], "warn")
        self.assertFalse(report["environment"]["frontend_ready"])
        self.assertFalse(report["environment"]["model_configured"])

    def test_local_x86_root_runtime_is_not_marked_ready(self) -> None:
        service = DeploymentReadinessService(
            SnapshotRegistry(
                {
                    "machine": "x86_64",
                    "os_family": "linux",
                    "is_loongarch": False,
                    "os_release": {
                        "id": "ubuntu",
                        "pretty_name": "Ubuntu 22.04 LTS",
                        "version_id": "22.04",
                    },
                }
            ),
            command_exists=lambda command: command in {"journalctl", "ps"},
            runtime_user=lambda: ("root", 0),
            environment=DeploymentEnvironment(
                app_env="development",
                frontend_index="frontend/dist/index.html",
                database_url="postgresql+psycopg://kg:kg@127.0.0.1:5432/opscouncil",
                ai_key_configured=True,
                chat_model="qwen-plus-latest",
                embedding_model="text-embedding-v4",
            ),
            path_exists=lambda path: True,
            database_probe=lambda url: {"status": "ok", "detail": "PostgreSQL reachable, pgvector enabled"},
        )

        report = service.read()

        self.assertEqual(report["overall_status"], "blocked")
        statuses = {check["key"]: check["status"] for check in report["checks"]}
        self.assertEqual(statuses["os"], "ok")
        self.assertEqual(statuses["arch"], "ok")
        self.assertEqual(statuses["tools"], "blocked")
        self.assertEqual(statuses["executor"], "blocked")


class DeploymentReadinessApiTest(unittest.TestCase):
    def test_readiness_endpoint_returns_report(self) -> None:
        app = FastAPI()
        app.include_router(
            build_router(
                SnapshotRegistry(
                    {
                        "machine": "loongarch64",
                        "os_family": "linux",
                        "is_loongarch": True,
                        "os_release": {"id": "enterprise-linux", "pretty_name": "Enterprise Linux 9", "version_id": "9"},
                    }
                )
            )  # type: ignore[arg-type]
        )
        client = TestClient(app)
        try:
            response = client.get("/api/deployment/readiness")
        finally:
            client.close()

        self.assertEqual(response.status_code, 200)
        self.assertIn("checks", response.json())


if __name__ == "__main__":
    unittest.main()
