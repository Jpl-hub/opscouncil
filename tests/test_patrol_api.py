from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.core.database import get_session
from backend.app.mcp.types import ToolResult
from backend.app.models.entities import (
    AuditChain,
    ConfigBaseline,
    ConfigBaselineCheck,
    Conversation,
    ConversationTurn,
    Finding,
    Incident,
    PatrolPolicy,
    PatrolRun,
    ServiceExpectation,
    SystemSnapshot,
    Task,
    TaskEvent,
    TaskJob,
)


TABLES = [
    Task.__table__,
    Conversation.__table__,
    ConversationTurn.__table__,
    TaskEvent.__table__,
    AuditChain.__table__,
    TaskJob.__table__,
    SystemSnapshot.__table__,
    ConfigBaseline.__table__,
    ConfigBaselineCheck.__table__,
    ServiceExpectation.__table__,
    PatrolPolicy.__table__,
    PatrolRun.__table__,
    Incident.__table__,
    Finding.__table__,
]


class HealthyRegistry:
    def call(self, tool_name: str, payload: dict) -> ToolResult:
        values = {
            "system_snapshot": ToolResult(
                observations=[
                    {
                        "hostname": "node-a",
                        "machine": "loongarch64",
                        "memory": {"used_percent": 42.0},
                        "pressure": {},
                    }
                ],
                evidence_refs=["/proc/meminfo"],
            ),
            "disk_usage": ToolResult(
                observations=[
                    {"path": "/", "used_percent": 42.0, "inode_used_percent": 20.0}
                ],
                evidence_refs=["/", "statvfs:/"],
            ),
            "network_listeners": ToolResult(observations=[], evidence_refs=["ss"]),
            "process_list": ToolResult(
                observations=[
                    {"pid": 1, "command": "systemd", "cpu_percent": 0.1, "is_zombie": False}
                ],
                evidence_refs=["ps"],
            ),
            "service_status": ToolResult(observations=[], evidence_refs=["systemctl"]),
            "time_sync_status": ToolResult(
                observations=[
                    {
                        "ntp_synchronized": True,
                        "ntp_enabled": True,
                        "timezone": "Asia/Shanghai",
                        "local_rtc": False,
                    }
                ],
                evidence_refs=["timedatectl show"],
            ),
        }
        return values[tool_name]

    def list_tools(self) -> list[dict]:
        return []


class PatrolApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in TABLES:
            table.create(self.engine)
        self.session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
            future=True,
        )
        self.now = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)
        app = FastAPI()
        app.include_router(
            build_router(
                HealthyRegistry(),
                session_factory=self.session_factory,
            )
        )

        def override_session():
            with self.session_factory() as session:
                try:
                    yield session
                    session.commit()
                except Exception:
                    session.rollback()
                    raise

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.engine.dispose()

    def _seed_event(self, *, task_status: str | None = None) -> tuple[int, int, int, int | None]:
        with self.session_factory() as session:
            policy = PatrolPolicy(
                name="核心巡检",
                enabled=True,
                interval_seconds=300,
                signal_keys_json=["disk_pressure"],
                thresholds_json={},
                next_run_at=self.now + timedelta(minutes=5),
            )
            session.add(policy)
            session.flush()
            run = PatrolRun(
                policy_id=policy.id,
                host_key="node-a",
                status="SUCCEEDED",
                snapshot_json={"status": "warn"},
                started_at=self.now,
                completed_at=self.now,
            )
            session.add(run)
            session.flush()
            task_id = None
            if task_status is not None:
                task = Task(
                    trace_id=f"trace-{task_status.lower()}",
                    user_input="调查磁盘压力",
                    intent="disk_pressure_analysis",
                    status=task_status,
                    risk_level="R1",
                    summary="调查中",
                )
                session.add(task)
                session.flush()
                task_id = task.id
            incident = Incident(
                host_key="node-a",
                signal_key="disk_pressure",
                dedupe_key="node-a:disk_pressure",
                status="INVESTIGATING" if task_id else "OPEN",
                severity="WARN",
                title="磁盘压力",
                summary="根分区使用率 86%。",
                task_id=task_id,
                opened_at=self.now,
                updated_at=self.now,
            )
            session.add(incident)
            session.flush()
            finding = Finding(
                policy_id=policy.id,
                patrol_run_id=run.id,
                incident_id=incident.id,
                host_key="node-a",
                signal_key="disk_pressure",
                fingerprint="a" * 64,
                severity="WARN",
                status="OPEN",
                title="磁盘压力",
                summary="根分区使用率 86%。",
                metric_json={"metric": "86.0%", "status": "warn"},
                evidence_refs_json=["disk_usage", "/"],
                first_observed_at=self.now,
                last_observed_at=self.now,
                occurrence_count=2,
            )
            session.add(finding)
            session.commit()
            return policy.id, run.id, incident.id, task_id

    def test_overview_and_paginated_queries_use_persisted_counts(self) -> None:
        _, _, incident_id, task_id = self._seed_event(task_status="SEALED")

        overview = self.client.get("/api/patrol/overview")
        findings = self.client.get("/api/findings", params={"status": "OPEN", "page": 1, "page_size": 10})
        incidents = self.client.get("/api/incidents", params={"status": "INVESTIGATING"})

        self.assertEqual(overview.status_code, 200)
        self.assertEqual(overview.json()["open_finding_count"], 1)
        self.assertEqual(overview.json()["open_incident_count"], 1)
        self.assertEqual(overview.json()["latest_run"]["status"], "SUCCEEDED")
        self.assertEqual(findings.status_code, 200)
        self.assertEqual(findings.json()["total"], 1)
        self.assertEqual(findings.json()["items"][0]["occurrence_count"], 2)
        self.assertEqual(findings.json()["items"][0]["evidence_refs"], ["disk_usage", "/"])
        self.assertNotIn("snapshot_json", findings.text)
        self.assertEqual(incidents.json()["items"][0]["id"], incident_id)
        self.assertEqual(incidents.json()["items"][0]["task_id"], task_id)
        self.assertEqual(incidents.json()["items"][0]["healthy_streak"], 0)
        self.assertEqual(incidents.json()["items"][0]["recovery_target"], 2)

    def test_acknowledge_is_idempotent_and_unknown_finding_is_not_found(self) -> None:
        self._seed_event()
        with self.session_factory() as session:
            finding = session.scalar(select(Finding))
            assert finding is not None
            finding_id = finding.id

        first = self.client.post(f"/api/findings/{finding_id}/acknowledge")
        second = self.client.post(f"/api/findings/{finding_id}/acknowledge")
        missing = self.client.post("/api/findings/999/acknowledge")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["status"], "ACKNOWLEDGED")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["status"], "ACKNOWLEDGED")
        self.assertEqual(missing.status_code, 404)

    def test_close_incident_rejects_running_task_then_resolves_findings(self) -> None:
        _, _, incident_id, task_id = self._seed_event(task_status="PERCEIVE")
        assert task_id is not None

        blocked = self.client.post(f"/api/incidents/{incident_id}/close")
        self.assertEqual(blocked.status_code, 409)

        with self.session_factory() as session:
            task = session.get(Task, task_id)
            assert task is not None
            task.status = "SEALED"
            session.commit()
        closed = self.client.post(f"/api/incidents/{incident_id}/close")

        self.assertEqual(closed.status_code, 200)
        self.assertEqual(closed.json()["status"], "CLOSED")
        with self.session_factory() as session:
            incident = session.get(Incident, incident_id)
            finding = session.scalar(select(Finding))
            assert incident is not None and finding is not None
            self.assertIsNone(incident.dedupe_key)
            self.assertEqual(finding.status, "RESOLVED")

    def test_manual_policy_run_returns_actual_persisted_result(self) -> None:
        with self.session_factory() as session:
            policy = PatrolPolicy(
                name="手动巡检",
                enabled=True,
                interval_seconds=300,
                signal_keys_json=["disk_pressure", "mcp_health"],
                thresholds_json={},
                next_run_at=self.now + timedelta(hours=1),
            )
            session.add(policy)
            session.commit()
            policy_id = policy.id

        response = self.client.post(f"/api/patrol/policies/{policy_id}/run")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["policy_id"], policy_id)
        self.assertEqual(body["host_key"], "node-a")
        self.assertEqual(body["status"], "SUCCEEDED")
        self.assertTrue(body["completed_at"])


if __name__ == "__main__":
    unittest.main()
