from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
import unittest

from backend.app.config_baseline.service import ConfigBaselineService, LAB_SCOPE, LIVE_SCOPE
from backend.app.mcp.types import ToolResult
from backend.app.models.entities import ConfigBaseline, ConfigBaselineCheck


class SequenceRegistry:
    def __init__(self, results: list[ToolResult]) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, dict]] = []

    def call(self, tool_name: str, payload: dict) -> ToolResult:
        self.calls.append((tool_name, payload))
        return self.results.pop(0)


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    ConfigBaseline.__table__.create(engine)
    ConfigBaselineCheck.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


class ConfigBaselineServiceTest(unittest.TestCase):
    def test_create_baseline_persists_only_safe_config_metadata(self) -> None:
        registry = SequenceRegistry(
            [
                ToolResult(
                    observations=[
                        {
                            "path": "/etc/hosts",
                            "resolved_path": "/etc/hosts",
                            "exists": True,
                            "file_type": "file",
                            "size_bytes": 128,
                            "mtime": 100.0,
                            "mode": "0o644",
                            "uid": 0,
                            "gid": 0,
                            "sha256": "a" * 64,
                            "content": "must-not-be-persisted",
                        }
                    ],
                    evidence_refs=["/etc/hosts"],
                )
            ]
        )
        with build_session() as session:
            baseline = ConfigBaselineService(session, registry).create(
                name="系统关键配置",
                paths=["/etc/hosts"],
                created_by="admin",
            )
            session.commit()

            stored = session.get(ConfigBaseline, baseline.id)
            self.assertIsNotNone(stored)
            assert stored is not None
            self.assertEqual(stored.name, "系统关键配置")
            self.assertEqual(stored.scope, LIVE_SCOPE)
            self.assertEqual(stored.paths_json, ["/etc/hosts"])
            self.assertEqual(stored.snapshot_json[0]["sha256"], "a" * 64)
            self.assertNotIn("content", stored.snapshot_json[0])
            self.assertEqual(
                registry.calls,
                [("config_integrity_scan", {"paths": ["/etc/hosts"]})],
            )

    def test_compare_records_content_permission_and_added_drift(self) -> None:
        baseline_result = ToolResult(
            observations=[
                {
                    "path": "/etc/hosts",
                    "resolved_path": "/etc/hosts",
                    "exists": True,
                    "file_type": "file",
                    "size_bytes": 128,
                    "mtime": 100.0,
                    "mode": "0o644",
                    "uid": 0,
                    "gid": 0,
                    "sha256": "a" * 64,
                },
                {
                    "path": "/tmp/opscouncil-lab/etc/service-agent.conf",
                    "resolved_path": "/tmp/opscouncil-lab/etc/service-agent.conf",
                    "exists": False,
                },
            ]
        )
        current_result = ToolResult(
            observations=[
                {
                    "path": "/etc/hosts",
                    "resolved_path": "/etc/hosts",
                    "exists": True,
                    "file_type": "file",
                    "size_bytes": 140,
                    "mtime": 200.0,
                    "mode": "0o640",
                    "uid": 0,
                    "gid": 0,
                    "sha256": "b" * 64,
                },
                {
                    "path": "/tmp/opscouncil-lab/etc/service-agent.conf",
                    "resolved_path": "/tmp/opscouncil-lab/etc/service-agent.conf",
                    "exists": True,
                    "file_type": "file",
                    "size_bytes": 80,
                    "mtime": 200.0,
                    "mode": "0o640",
                    "uid": 1000,
                    "gid": 1000,
                    "sha256": "c" * 64,
                },
            ],
            warnings=["sample warning"],
        )
        registry = SequenceRegistry([baseline_result, current_result])
        with build_session() as session:
            service = ConfigBaselineService(session, registry)
            baseline = service.create(
                name="系统关键配置",
                paths=[
                    "/etc/hosts",
                    "/tmp/opscouncil-lab/etc/service-agent.conf",
                ],
            )
            check = service.compare(baseline.id)
            session.commit()

            self.assertEqual(check.status, "drifted")
            self.assertEqual(
                check.summary_json,
                {
                    "total": 2,
                    "unchanged": 0,
                    "changed": 2,
                    "missing": 0,
                    "added": 1,
                },
            )
            changes = {item["path"]: item for item in check.changes_json}
            self.assertEqual(
                changes["/etc/hosts"]["change_types"],
                [
                    "content_changed",
                    "permission_changed",
                    "metadata_changed",
                ],
            )
            self.assertEqual(
                changes["/tmp/opscouncil-lab/etc/service-agent.conf"]["change_types"],
                ["added"],
            )
            stored_checks = list(
                session.scalars(
                    select(ConfigBaselineCheck).where(
                        ConfigBaselineCheck.baseline_id == baseline.id
                    )
                )
            )
            self.assertEqual([item.id for item in stored_checks], [check.id])
            self.assertEqual(stored_checks[0].warnings_json, ["sample warning"])

    def test_compare_can_bind_check_to_a_requested_baseline_subset(self) -> None:
        baseline_result = ToolResult(
            observations=[
                {"path": "/etc/hosts", "exists": True, "sha256": "a" * 64},
                {"path": "/etc/fstab", "exists": True, "sha256": "b" * 64},
            ]
        )
        current_result = ToolResult(
            observations=[
                {"path": "/etc/hosts", "exists": True, "sha256": "a" * 64},
            ]
        )
        registry = SequenceRegistry([baseline_result, current_result])
        with build_session() as session:
            service = ConfigBaselineService(session, registry)
            baseline = service.create(
                name="系统关键配置",
                paths=["/etc/hosts", "/etc/fstab"],
            )

            check = service.compare(baseline.id, paths=["/etc/hosts"])

            self.assertEqual(check.status, "clean")
            self.assertEqual(check.summary_json["total"], 1)
            self.assertEqual(
                [item["path"] for item in check.current_snapshot_json],
                ["/etc/hosts"],
            )
            self.assertEqual(
                registry.calls[-1],
                ("config_integrity_scan", {"paths": ["/etc/hosts"]}),
            )
            with self.assertRaisesRegex(
                ValueError,
                "comparison paths must be covered",
            ):
                service.compare(baseline.id, paths=["/etc/shadow"])

    def test_live_listing_excludes_lab_baselines(self) -> None:
        result = ToolResult(
            observations=[
                {
                    "path": "/etc/hosts",
                    "exists": True,
                    "sha256": "a" * 64,
                }
            ]
        )
        registry = SequenceRegistry([result, result])
        with build_session() as session:
            service = ConfigBaselineService(session, registry)
            live = service.create(name="生产基线", paths=["/etc/hosts"])
            lab = service.create(
                name="评测基线",
                paths=["/etc/hosts"],
                created_by="opsbench",
                scope=LAB_SCOPE,
            )
            session.commit()

            self.assertEqual([item.id for item in service.list()], [live.id])
            self.assertEqual(service.latest().id, live.id)
            self.assertEqual([item.id for item in service.list(scope=LAB_SCOPE)], [lab.id])
            with self.assertRaisesRegex(LookupError, "config baseline not found"):
                service.compare(lab.id, scope=LIVE_SCOPE)

    def test_compare_rejects_unknown_baseline(self) -> None:
        with build_session() as session:
            service = ConfigBaselineService(session, SequenceRegistry([]))
            with self.assertRaisesRegex(LookupError, "config baseline not found"):
                service.compare(999)


if __name__ == "__main__":
    unittest.main()
