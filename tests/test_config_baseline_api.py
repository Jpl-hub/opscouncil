from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.core.database import get_session
from backend.app.mcp.types import ToolResult
from backend.app.models.entities import ConfigBaseline, ConfigBaselineCheck


class BaselineRegistry:
    def __init__(self) -> None:
        self.hash_value = "a" * 64

    def call(self, tool_name: str, payload: dict) -> ToolResult:
        if tool_name != "config_integrity_scan":
            raise AssertionError(f"unexpected tool: {tool_name}")
        return ToolResult(
            observations=[
                {
                    "path": path,
                    "resolved_path": path,
                    "exists": True,
                    "file_type": "file",
                    "size_bytes": 128,
                    "mtime": 100.0,
                    "mode": "0o644",
                    "uid": 0,
                    "gid": 0,
                    "sha256": self.hash_value,
                }
                for path in payload["paths"]
            ]
        )

    def list_tools(self) -> list[dict]:
        return []


class ConfigBaselineApiTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        ConfigBaseline.__table__.create(engine)
        ConfigBaselineCheck.__table__.create(engine)
        self.session = Session(engine, expire_on_commit=False)
        self.registry = BaselineRegistry()
        app = FastAPI()
        app.include_router(build_router(self.registry))  # type: ignore[arg-type]

        def override_session():
            yield self.session

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.session.close()

    def test_create_compare_and_list_baseline(self) -> None:
        created = self.client.post(
            "/api/config-baselines",
            json={
                "name": "系统关键配置",
                "paths": ["/etc/hosts", "/etc/fstab"],
                "created_by": "admin",
            },
        )
        self.assertEqual(created.status_code, 200)
        baseline = created.json()
        self.assertEqual(baseline["name"], "系统关键配置")
        self.assertEqual(baseline["file_count"], 2)
        self.assertIsNone(baseline["latest_check"])

        self.registry.hash_value = "b" * 64
        checked = self.client.post(
            f"/api/config-baselines/{baseline['id']}/checks"
        )
        self.assertEqual(checked.status_code, 200)
        result = checked.json()
        self.assertEqual(result["status"], "drifted")
        self.assertEqual(result["summary"]["changed"], 2)
        self.assertEqual(
            result["changes"][0]["change_types"],
            ["content_changed"],
        )

        listed = self.client.get("/api/config-baselines")
        self.assertEqual(listed.status_code, 200)
        rows = listed.json()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["latest_check"]["id"], result["id"])

        lab = ConfigBaseline(
            name="内部评测基线",
            scope="LAB",
            paths_json=["/tmp/opscouncil-lab/etc/managed-agent.conf"],
            snapshot_json=[],
            warnings_json=[],
            created_by="opsbench",
        )
        self.session.add(lab)
        self.session.commit()
        listed = self.client.get("/api/config-baselines")
        self.assertEqual([item["id"] for item in listed.json()], [baseline["id"]])
        hidden = self.client.post(f"/api/config-baselines/{lab.id}/checks")
        self.assertEqual(hidden.status_code, 404)

    def test_compare_unknown_baseline_returns_not_found(self) -> None:
        response = self.client.post("/api/config-baselines/999/checks")

        self.assertEqual(response.status_code, 404)
        self.assertIn("config baseline not found", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
