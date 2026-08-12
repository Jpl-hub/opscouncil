from __future__ import annotations

from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.collaboration.api import build_collaboration_router
from backend.app.core.database import get_session
from backend.app.models.entities import (
    AgentWorkItem,
    CollaborationEvent,
    Finding,
    Incident,
    IncidentCollaboration,
    PatrolPolicy,
    PatrolRun,
)


TABLES = [
    PatrolPolicy.__table__,
    PatrolRun.__table__,
    Incident.__table__,
    Finding.__table__,
    IncidentCollaboration.__table__,
    AgentWorkItem.__table__,
    CollaborationEvent.__table__,
]


class FakeAgentTeamsClient:
    def dispatch_incident(self, payload: dict) -> str:
        assert payload["incident"]["title"] == "根分区压力"
        return "$dispatch-event-1001"


class CollaborationApiTest(unittest.TestCase):
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
        app = FastAPI()
        app.include_router(build_collaboration_router(), prefix="/api")

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
        self.incident_id = self._seed_incident()

    def tearDown(self) -> None:
        self.client.close()
        self.engine.dispose()

    def _seed_incident(self) -> int:
        now = datetime(2026, 8, 12, 20, 0, tzinfo=timezone.utc)
        with self.session_factory() as session:
            policy = PatrolPolicy(
                name="核心巡检",
                enabled=True,
                interval_seconds=300,
                signal_keys_json=["disk_pressure"],
                thresholds_json={},
                next_run_at=now,
            )
            session.add(policy)
            session.flush()
            run = PatrolRun(
                policy_id=policy.id,
                host_key="node-a",
                status="SUCCEEDED",
                snapshot_json={"status": "warn"},
                started_at=now,
                completed_at=now,
            )
            session.add(run)
            session.flush()
            incident = Incident(
                host_key="node-a",
                signal_key="disk_pressure",
                dedupe_key="node-a:disk_pressure:20260812",
                status="OPEN",
                severity="WARN",
                title="根分区压力",
                summary="根分区使用率持续高于动态基线。",
                opened_at=now,
                updated_at=now,
            )
            session.add(incident)
            session.flush()
            session.add(
                Finding(
                    policy_id=policy.id,
                    patrol_run_id=run.id,
                    incident_id=incident.id,
                    host_key=incident.host_key,
                    signal_key=incident.signal_key,
                    fingerprint="f" * 64,
                    severity="WARN",
                    status="OPEN",
                    title=incident.title,
                    summary=incident.summary,
                    metric_json={"used_percent": 86.0},
                    evidence_refs_json=["disk_usage", "statvfs:/"],
                    first_observed_at=now,
                    last_observed_at=now,
                    occurrence_count=1,
                )
            )
            session.commit()
            return incident.id

    def test_existing_patrol_incident_starts_once_with_real_evidence(self) -> None:
        first = self.client.post(f"/api/collaboration/patrol-incidents/{self.incident_id}")
        second = self.client.post(f"/api/collaboration/patrol-incidents/{self.incident_id}")

        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        self.assertEqual(first.json()["id"], second.json()["id"])
        self.assertEqual(first.json()["incident"]["task_id"], None)
        self.assertEqual(len(first.json()["work_items"]), 6)
        self.assertEqual(first.json()["work_items"][0]["status"], "READY")
        self.assertEqual(
            first.json()["work_items"][0]["input"]["evidence_refs"],
            ["disk_usage", "statvfs:/"],
        )
        self.assertTrue(first.json()["audit"]["valid"])
        with self.session_factory() as session:
            self.assertEqual(
                session.scalar(select(func.count()).select_from(IncidentCollaboration)),
                1,
            )

    def test_dispatch_receipt_is_visible_and_hash_verified(self) -> None:
        created = self.client.post(
            f"/api/collaboration/patrol-incidents/{self.incident_id}"
        ).json()

        with patch(
            "backend.app.collaboration.api._agentteams_client",
            return_value=FakeAgentTeamsClient(),
        ):
            dispatched = self.client.post(
                f"/api/collaboration/incidents/{created['id']}/agentteams/dispatch"
            )
        detail = self.client.get(
            f"/api/collaboration/incidents/{created['id']}"
        )

        self.assertEqual(dispatched.status_code, 200)
        self.assertEqual(dispatched.json()["event_id"], "$dispatch-event-1001")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["events"][-1]["event_type"], "agentteams_dispatched")
        self.assertEqual(detail.json()["events"][-1]["source_system"], "agentteams-matrix")
        self.assertTrue(detail.json()["audit"]["valid"])


if __name__ == "__main__":
    unittest.main()
