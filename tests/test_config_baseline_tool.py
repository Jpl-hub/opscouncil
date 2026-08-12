from __future__ import annotations

import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.config_baseline.service import ConfigBaselineService, LAB_SCOPE
from backend.app.config_baseline.tools import register_config_baseline_tool
from backend.app.core.pydantic_compat import BaseModel, Field
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.models.entities import ConfigBaseline, ConfigBaselineCheck
from backend.app.schemas.enums import RiskLevel


class PathsInput(BaseModel):
    paths: list[str] = Field(default_factory=list)


class ConfigBaselineToolTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        ConfigBaseline.__table__.create(engine)
        ConfigBaselineCheck.__table__.create(engine)
        self.session_factory = sessionmaker(bind=engine, expire_on_commit=False)
        self.current_mode = "0o640"
        self.registry = ToolRegistry()

        def scan(payload: BaseModel) -> ToolResult:
            args = PathsInput.model_validate(payload)
            return ToolResult(
                observations=[
                    {
                        "path": path,
                        "resolved_path": path,
                        "exists": True,
                        "file_type": "file",
                        "size_bytes": 32,
                        "mtime": 100.0,
                        "mode": self.current_mode,
                        "uid": 0,
                        "gid": 0,
                        "sha256": "a" * 64,
                        "hash_truncated": False,
                    }
                    for path in args.paths
                ],
                evidence_refs=[f"config:{path}" for path in args.paths],
            )

        self.registry.register(
            ToolDefinition(
                name="config_integrity_scan",
                version="1.0.0",
                description="test scan",
                risk_level=RiskLevel.R0,
                input_model=PathsInput,
                output_model=ToolResult,
                handler=scan,
            )
        )
        register_config_baseline_tool(self.registry, self.session_factory)

    def test_tool_compares_covering_baseline_and_persists_check(self) -> None:
        with self.session_factory() as session:
            baseline = ConfigBaselineService(session, self.registry).create(
                name="系统关键配置",
                paths=["/etc/hosts"],
            )
            session.commit()
            baseline_id = baseline.id

        self.current_mode = "0o666"
        result = self.registry.call(
            "config_baseline_check",
            {"paths": ["/etc/hosts"], "scope": "LIVE"},
        )

        self.assertEqual(result.status, "ok")
        self.assertTrue(result.summary_fields["baseline_available"])
        self.assertEqual(result.summary_fields["baseline_id"], baseline_id)
        self.assertEqual(result.summary_fields["status"], "drifted")
        self.assertEqual(result.observations[0]["change_types"], ["permission_changed"])
        self.assertNotIn("content", result.observations[0])
        with self.session_factory() as session:
            checks = list(session.scalars(select(ConfigBaselineCheck)))
            self.assertEqual(len(checks), 1)

    def test_tool_never_uses_lab_baseline_for_live_request(self) -> None:
        path = "/tmp/opscouncil-lab/etc/service-agent.conf"
        with self.session_factory() as session:
            ConfigBaselineService(session, self.registry).create(
                name="靶场配置",
                paths=[path],
                scope=LAB_SCOPE,
            )
            session.commit()

        result = self.registry.call(
            "config_baseline_check",
            {"paths": [path], "scope": "LIVE"},
        )

        self.assertFalse(result.summary_fields["baseline_available"])
        self.assertEqual(result.summary_fields["scope"], "LIVE")
        self.assertFalse(result.observations[0]["baseline_available"])
        with self.session_factory() as session:
            self.assertEqual(list(session.scalars(select(ConfigBaselineCheck))), [])


if __name__ == "__main__":
    unittest.main()
