from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.models.entities import Finding, Incident, PatrolPolicy, PatrolRun, Task


TABLES = [
    Task.__table__,
    PatrolPolicy.__table__,
    PatrolRun.__table__,
    Incident.__table__,
    Finding.__table__,
]


class PatrolModelTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
        for table in TABLES:
            table.create(self.engine)
        self.session = Session(self.engine, expire_on_commit=False)
        self.now = datetime(2026, 7, 12, 9, 30, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.session.close()
        self.engine.dispose()

    def test_persists_policy_run_incident_and_finding_contract(self) -> None:
        policy = PatrolPolicy(
            name="核心主机巡检",
            enabled=True,
            interval_seconds=300,
            signal_keys_json=["disk_pressure", "memory_pressure"],
            thresholds_json={},
            next_run_at=self.now,
        )
        self.session.add(policy)
        self.session.flush()
        run = PatrolRun(
            policy_id=policy.id,
            host_key="node-a",
            status="SUCCEEDED",
            snapshot_json={"signals": [{"key": "disk_pressure", "status": "warn"}]},
            started_at=self.now,
            completed_at=self.now + timedelta(seconds=2),
        )
        self.session.add(run)
        self.session.flush()
        incident = Incident(
            host_key="node-a",
            signal_key="disk_pressure",
            status="OPEN",
            severity="WARN",
            title="根分区空间偏高",
            summary="根分区使用率为 86%。",
            opened_at=self.now,
            updated_at=self.now,
        )
        self.session.add(incident)
        self.session.flush()
        finding = Finding(
            policy_id=policy.id,
            patrol_run_id=run.id,
            incident_id=incident.id,
            host_key="node-a",
            signal_key="disk_pressure",
            fingerprint="a" * 64,
            severity="WARN",
            status="OPEN",
            title="根分区空间偏高",
            summary="根分区使用率为 86%。",
            metric_json={"used_percent": 86.0},
            evidence_refs_json=["disk_usage", "/"],
            first_observed_at=self.now,
            last_observed_at=self.now,
            occurrence_count=1,
        )
        self.session.add(finding)
        self.session.commit()

        stored = self.session.scalar(select(Finding).where(Finding.fingerprint == "a" * 64))

        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored.incident_id, incident.id)
        self.assertEqual(stored.patrol_run_id, run.id)
        self.assertEqual(stored.evidence_refs_json, ["disk_usage", "/"])
        self.assertEqual(incident.healthy_streak, 0)
        self.assertEqual(incident.recovery_target, 2)
        self.assertIsNone(incident.last_healthy_at)
        indexes = {item["name"] for item in inspect(self.engine).get_indexes("patrol_policies")}
        self.assertIn("ix_patrol_policies_due", indexes)

    def test_rejects_duplicate_fingerprint_and_invalid_occurrence_count(self) -> None:
        policy = PatrolPolicy(
            name="去重测试",
            enabled=True,
            interval_seconds=300,
            signal_keys_json=["disk_pressure"],
            thresholds_json={},
            next_run_at=self.now,
        )
        self.session.add(policy)
        self.session.flush()
        run = PatrolRun(
            policy_id=policy.id,
            host_key="node-a",
            status="SUCCEEDED",
            snapshot_json={},
            started_at=self.now,
            completed_at=self.now,
        )
        self.session.add(run)
        self.session.flush()

        def finding(*, count: int) -> Finding:
            return Finding(
                policy_id=policy.id,
                patrol_run_id=run.id,
                host_key="node-a",
                signal_key="disk_pressure",
                fingerprint="b" * 64,
                severity="WARN",
                status="OPEN",
                title="磁盘压力",
                summary="磁盘使用率偏高。",
                metric_json={},
                evidence_refs_json=["disk_usage"],
                first_observed_at=self.now,
                last_observed_at=self.now,
                occurrence_count=count,
            )

        self.session.add(finding(count=1))
        self.session.commit()
        self.session.add(finding(count=1))
        with self.assertRaises(IntegrityError):
            self.session.commit()
        self.session.rollback()

        invalid = finding(count=0)
        invalid.fingerprint = "c" * 64
        self.session.add(invalid)
        with self.assertRaises(IntegrityError):
            self.session.commit()


if __name__ == "__main__":
    unittest.main()
