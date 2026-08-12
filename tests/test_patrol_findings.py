from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from backend.app.models.entities import Finding, Incident, PatrolPolicy, PatrolRun, Task
from backend.app.patrol.findings import FindingService


TABLES = [
    Task.__table__,
    PatrolPolicy.__table__,
    PatrolRun.__table__,
    Incident.__table__,
    Finding.__table__,
]


class FindingServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
        for table in TABLES:
            table.create(self.engine)
        self.session = Session(self.engine, expire_on_commit=False)
        self.now = datetime(2026, 7, 12, 10, 0, tzinfo=timezone.utc)
        self.policy = PatrolPolicy(
            name="核心巡检",
            enabled=True,
            interval_seconds=300,
            signal_keys_json=[
                "disk_pressure",
                "inode_pressure",
                "memory_pressure",
                "failed_service",
                "process_pressure",
                "network_exposure",
                "config_drift",
                "time_sync",
            ],
            thresholds_json={"dedupe_window_seconds": 900},
            next_run_at=self.now,
        )
        self.session.add(self.policy)
        self.session.flush()

    def tearDown(self) -> None:
        self.session.close()
        self.engine.dispose()

    def _run(self, at: datetime | None = None) -> PatrolRun:
        run = PatrolRun(
            policy_id=self.policy.id,
            host_key="node-a",
            status="SUCCEEDED",
            snapshot_json={},
            started_at=at or self.now,
            completed_at=at or self.now,
        )
        self.session.add(run)
        self.session.flush()
        return run

    def test_creates_traceable_finding_and_open_incident(self) -> None:
        run = self._run()
        report = {
            "signals": [
                {
                    "key": "disk_pressure",
                    "title": "磁盘压力",
                    "status": "warn",
                    "metric": "86.0%",
                    "detail": "根分区使用率 86.0%。",
                    "evidence_refs": ["disk_usage", "/"],
                },
                {
                    "key": "memory_pressure",
                    "title": "内存压力",
                    "status": "ok",
                    "metric": "43.0%",
                    "detail": "内存使用率正常。",
                    "evidence_refs": ["system_snapshot"],
                },
            ]
        }

        findings = FindingService(self.session).apply_run(
            self.policy,
            run,
            report,
            now=self.now,
        )
        self.session.commit()

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.signal_key, "disk_pressure")
        self.assertEqual(finding.severity, "WARN")
        self.assertEqual(finding.evidence_refs_json, ["disk_usage", "/"])
        self.assertEqual(finding.metric_json["metric"], "86.0%")
        self.assertIsNotNone(finding.incident_id)
        incident = self.session.get(Incident, finding.incident_id)
        assert incident is not None
        self.assertEqual(incident.status, "OPEN")
        self.assertEqual(incident.dedupe_key, "node-a:disk_pressure")

    def test_repeated_signal_in_window_updates_one_finding_and_escalates(self) -> None:
        service = FindingService(self.session)
        first_run = self._run()
        service.apply_run(
            self.policy,
            first_run,
            {"signals": [_signal("disk_pressure", "warn", "84.0%")]},
            now=self.now,
        )
        second_run = self._run(self.now + timedelta(minutes=5))

        findings = service.apply_run(
            self.policy,
            second_run,
            {"signals": [_signal("disk_pressure", "critical", "93.0%")]},
            now=self.now + timedelta(minutes=5),
        )
        self.session.commit()

        self.assertEqual(self.session.scalar(select(func.count()).select_from(Finding)), 1)
        self.assertEqual(self.session.scalar(select(func.count()).select_from(Incident)), 1)
        self.assertEqual(findings[0].occurrence_count, 2)
        self.assertEqual(findings[0].severity, "CRITICAL")
        incident = self.session.get(Incident, findings[0].incident_id)
        assert incident is not None
        self.assertEqual(incident.severity, "CRITICAL")
        self.assertEqual(incident.summary, "disk_pressure 当前指标 93.0%。")

    def test_new_window_supersedes_old_finding_but_reuses_open_incident(self) -> None:
        service = FindingService(self.session)
        first = service.apply_run(
            self.policy,
            self._run(),
            {"signals": [_signal("network_exposure", "warn", "1 个高风险端口")]},
            now=self.now,
        )[0]
        second = service.apply_run(
            self.policy,
            self._run(self.now + timedelta(minutes=16)),
            {"signals": [_signal("network_exposure", "warn", "1 个高风险端口")]},
            now=self.now + timedelta(minutes=16),
        )[0]
        self.session.commit()

        self.assertNotEqual(first.id, second.id)
        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(self.session.scalar(select(func.count()).select_from(Finding)), 2)
        self.assertEqual(first.status, "RESOLVED")
        self.assertEqual(second.status, "OPEN")
        self.assertEqual(
            self.session.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.status.in_({"OPEN", "ACKNOWLEDGED"}))
            ),
            1,
        )
        self.assertEqual(self.session.scalar(select(func.count()).select_from(Incident)), 1)

    def test_two_consecutive_healthy_rechecks_resolve_findings_and_incident(self) -> None:
        service = FindingService(self.session)
        active = service.apply_run(
            self.policy,
            self._run(),
            {"signals": [_signal("failed_service", "critical", "1 个失败服务")]},
            now=self.now,
        )[0]
        healthy_at = self.now + timedelta(minutes=5)

        first_healthy = service.apply_run(
            self.policy,
            self._run(healthy_at),
            {"signals": [_signal("failed_service", "ok", "0 个失败服务")]},
            now=healthy_at,
        )
        self.session.flush()
        incident = self.session.get(Incident, active.incident_id)
        assert incident is not None
        self.assertEqual(first_healthy, [])
        self.assertEqual(active.status, "OPEN")
        self.assertEqual(incident.status, "OPEN")
        self.assertEqual(incident.healthy_streak, 1)

        resolved_at = healthy_at + timedelta(minutes=5)
        current = service.apply_run(
            self.policy,
            self._run(resolved_at),
            {"signals": [_signal("failed_service", "ok", "0 个失败服务")]},
            now=resolved_at,
        )
        self.session.commit()

        self.assertEqual(current, [])
        self.session.refresh(active)
        self.assertEqual(active.status, "RESOLVED")
        assert active.resolved_at is not None
        self.assertEqual(active.resolved_at.replace(tzinfo=timezone.utc), resolved_at)
        self.assertEqual(incident.status, "RESOLVED")
        self.assertEqual(incident.healthy_streak, 2)
        self.assertIsNone(incident.dedupe_key)
        assert incident.closed_at is not None
        self.assertEqual(incident.closed_at.replace(tzinfo=timezone.utc), resolved_at)

    def test_active_sample_resets_pending_recovery(self) -> None:
        service = FindingService(self.session)
        active = service.apply_run(
            self.policy,
            self._run(),
            {"signals": [_signal("process_pressure", "warn", "CPU 90%")]},
            now=self.now,
        )[0]
        first_healthy_at = self.now + timedelta(minutes=5)
        service.apply_run(
            self.policy,
            self._run(first_healthy_at),
            {"signals": [_signal("process_pressure", "ok", "CPU 20%")]},
            now=first_healthy_at,
        )
        active_again_at = self.now + timedelta(minutes=10)
        service.apply_run(
            self.policy,
            self._run(active_again_at),
            {"signals": [_signal("process_pressure", "warn", "CPU 88%")]},
            now=active_again_at,
        )
        self.session.commit()

        incident = self.session.get(Incident, active.incident_id)
        assert incident is not None
        self.assertEqual(incident.status, "OPEN")
        self.assertEqual(incident.healthy_streak, 0)
        self.assertIsNone(incident.last_healthy_at)

    def test_failed_or_missing_signal_does_not_resolve_existing_evidence(self) -> None:
        service = FindingService(self.session)
        active = service.apply_run(
            self.policy,
            self._run(),
            {"signals": [_signal("config_drift", "warn", "1 项漂移")]},
            now=self.now,
        )[0]

        service.apply_run(
            self.policy,
            self._run(self.now + timedelta(minutes=5)),
            {
                "signals": [
                    {
                        "key": "config_drift",
                        "title": "配置漂移",
                        "status": "unknown",
                        "metric": "采集失败",
                        "detail": "配置工具无有效结果。",
                        "evidence_refs": [],
                    }
                ],
                "warnings": ["config_integrity_scan failed"],
            },
            now=self.now + timedelta(minutes=5),
        )
        service.apply_run(
            self.policy,
            self._run(self.now + timedelta(minutes=10)),
            {"signals": []},
            now=self.now + timedelta(minutes=10),
        )
        self.session.commit()

        self.session.refresh(active)
        self.assertEqual(active.status, "OPEN")
        incident = self.session.get(Incident, active.incident_id)
        assert incident is not None
        self.assertEqual(incident.status, "OPEN")

    def test_ignores_unselected_and_malformed_signals(self) -> None:
        findings = FindingService(self.session).apply_run(
            self.policy,
            self._run(),
            {
                "signals": [
                    _signal("platform", "warn", "开发环境"),
                    {"key": "disk_pressure", "status": "critical"},
                    {"status": "critical", "title": "无键"},
                ]
            },
            now=self.now,
        )

        self.assertEqual(findings, [])


def _signal(key: str, status: str, metric: str) -> dict[str, object]:
    return {
        "key": key,
        "title": key,
        "status": status,
        "metric": metric,
        "detail": f"{key} 当前指标 {metric}。",
        "evidence_refs": [key],
    }


if __name__ == "__main__":
    unittest.main()
