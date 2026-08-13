from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.collaboration.service import IncidentCollaborationService
from backend.app.models.entities import (
    ActionProposal,
    AgentWorkItem,
    AuditChain,
    CollaborationEvent,
    Conversation,
    ConversationTurn,
    Finding,
    Incident,
    IncidentCollaboration,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    PatrolPolicy,
    PatrolRun,
    Task,
    TaskChannelBinding,
    TaskEvent,
    TaskJob,
)
from backend.app.patrol.service import PatrolService


TABLES = [
    Operator.__table__,
    OperatorExternalIdentity.__table__,
    Task.__table__,
    Conversation.__table__,
    ConversationTurn.__table__,
    TaskEvent.__table__,
    AuditChain.__table__,
    TaskJob.__table__,
    ActionProposal.__table__,
    PatrolPolicy.__table__,
    PatrolRun.__table__,
    Incident.__table__,
    Finding.__table__,
    IncidentCollaboration.__table__,
    AgentWorkItem.__table__,
    CollaborationEvent.__table__,
    TaskChannelBinding.__table__,
    NotificationOutbox.__table__,
]


class FakePostureReader:
    def __init__(self, report: dict) -> None:
        self.report = report

    def read(self) -> dict:
        if isinstance(self.report.get("raise"), str):
            raise RuntimeError(self.report["raise"])
        return self.report


class PatrolServiceTest(unittest.TestCase):
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
        self.now = datetime(2026, 7, 12, 11, 0, tzinfo=timezone.utc)
        self.report = _posture_report()

    def tearDown(self) -> None:
        self.engine.dispose()

    def _service(self) -> PatrolService:
        return PatrolService(
            self.session_factory,
            registry=object(),
            posture_factory=lambda registry, session: FakePostureReader(self.report),
            seed_default_policy=False,
        )

    def _policy(
        self,
        *,
        next_run_at: datetime | None = None,
        name: str = "核心巡检",
        signal_keys: list[str] | None = None,
    ) -> int:
        with self.session_factory() as session:
            policy = PatrolPolicy(
                name=name,
                enabled=True,
                interval_seconds=300,
                signal_keys_json=signal_keys or ["disk_pressure", "mcp_health"],
                thresholds_json={"dedupe_window_seconds": 900},
                next_run_at=next_run_at or self.now,
            )
            session.add(policy)
            session.commit()
            return policy.id

    def test_due_policy_persists_run_finding_incident_and_queued_task(self) -> None:
        policy_id = self._policy()

        worked = self._service().run_due_once("worker-a", now=self.now)

        self.assertTrue(worked)
        with self.session_factory() as session:
            policy = session.get(PatrolPolicy, policy_id)
            run = session.scalar(select(PatrolRun))
            finding = session.scalar(select(Finding))
            incident = session.scalar(select(Incident))
            task = session.scalar(select(Task))
            job = session.scalar(select(TaskJob))
            events = list(session.scalars(select(TaskEvent).order_by(TaskEvent.id.asc())))
            collaboration = session.scalar(select(IncidentCollaboration))
            work_items = list(
                session.scalars(
                    select(AgentWorkItem).order_by(AgentWorkItem.id.asc())
                )
            )
            collaboration_audit = (
                IncidentCollaborationService(session).verify_chain(collaboration.id)
                if collaboration is not None
                else None
            )
        assert policy is not None and run is not None and finding is not None
        assert incident is not None and task is not None and job is not None
        assert collaboration is not None
        self.assertEqual(run.status, "SUCCEEDED")
        self.assertEqual(run.host_key, "node-a")
        self.assertEqual(finding.signal_key, "disk_pressure")
        self.assertEqual(incident.task_id, task.id)
        self.assertEqual(incident.status, "INVESTIGATING")
        self.assertEqual(job.status, "QUEUED")
        self.assertIn("巡检发现", task.user_input)
        self.assertEqual([event.event_type for event in events], ["task_created", "patrol_incident_created"])
        self.assertEqual(events[-1].payload_json["finding_id"], finding.id)
        self.assertEqual(events[-1].payload_json["incident_id"], incident.id)
        self.assertEqual(collaboration.incident_id, incident.id)
        self.assertEqual(collaboration.status, "TRIAGING")
        self.assertEqual(len(work_items), 6)
        self.assertEqual(work_items[0].work_key, "triage")
        self.assertEqual(work_items[0].status, "READY")
        self.assertIn("disk_usage", work_items[0].input_json["evidence_refs"])
        self.assertIsNotNone(collaboration_audit)
        self.assertTrue(collaboration_audit["valid"])
        assert policy.last_run_at is not None
        self.assertGreater(policy.next_run_at.replace(tzinfo=timezone.utc), self.now)

    def test_default_policy_upgrade_enables_new_capacity_signal(self) -> None:
        with self.session_factory() as session:
            policy = PatrolPolicy(
                name="核心主机巡检",
                enabled=True,
                interval_seconds=300,
                signal_keys_json=["disk_pressure"],
                thresholds_json={},
                next_run_at=self.now,
            )
            session.add(policy)
            session.commit()

        service = PatrolService(
            self.session_factory,
            registry=object(),
            posture_factory=lambda registry, session: FakePostureReader(self.report),
            seed_default_policy=True,
        )
        policy = service.ensure_default_policy(now=self.now)

        self.assertIn("disk_pressure", policy.signal_keys_json)
        self.assertIn("capacity_forecast", policy.signal_keys_json)
        self.assertIn("service_expectation", policy.signal_keys_json)

    def test_future_policy_is_not_claimed(self) -> None:
        self._policy(next_run_at=self.now + timedelta(minutes=10))

        worked = self._service().run_due_once("worker-a", now=self.now)

        self.assertFalse(worked)
        with self.session_factory() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(PatrolRun)), 0)
            self.assertEqual(session.scalar(select(func.count()).select_from(Task)), 0)

    def test_repeated_finding_reuses_incident_and_investigation_task(self) -> None:
        policy_id = self._policy()
        service = self._service()

        self.assertTrue(service.run_due_once("worker-a", now=self.now))
        with self.session_factory() as session:
            policy = session.get(PatrolPolicy, policy_id)
            assert policy is not None
            policy.next_run_at = self.now + timedelta(minutes=5)
            session.commit()
        self.assertTrue(service.run_due_once("worker-b", now=self.now + timedelta(minutes=5)))

        with self.session_factory() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(PatrolRun)), 2)
            self.assertEqual(session.scalar(select(func.count()).select_from(Finding)), 1)
            self.assertEqual(session.scalar(select(func.count()).select_from(Incident)), 1)
            self.assertEqual(session.scalar(select(func.count()).select_from(Task)), 1)
            self.assertEqual(
                session.scalar(select(func.count()).select_from(IncidentCollaboration)),
                1,
            )
            self.assertEqual(
                session.scalar(select(func.count()).select_from(AgentWorkItem)),
                6,
            )
            finding = session.scalar(select(Finding))
            assert finding is not None
            self.assertEqual(finding.occurrence_count, 2)

    def test_failed_collection_is_persisted_without_creating_false_finding(self) -> None:
        self._policy()
        self.report = {"raise": "collector failed with\nprivate details"}

        worked = self._service().run_due_once("worker-a", now=self.now)

        self.assertTrue(worked)
        with self.session_factory() as session:
            run = session.scalar(select(PatrolRun))
            assert run is not None
            self.assertEqual(run.status, "FAILED")
            self.assertIn("collector failed", run.error or "")
            self.assertNotIn("\n", run.error or "")
            self.assertEqual(session.scalar(select(func.count()).select_from(Finding)), 0)
            self.assertEqual(session.scalar(select(func.count()).select_from(Task)), 0)

    def test_partial_tool_failure_creates_mcp_health_finding_but_run_is_failed(self) -> None:
        self._policy()
        self.report = _posture_report(
            report_status="error",
            signals=[
                {
                    "key": "mcp_health",
                    "title": "感知链路",
                    "status": "critical",
                    "metric": "3/4 正常",
                    "detail": "进程采样工具异常。",
                    "evidence_refs": ["process_list"],
                }
            ],
        )

        self._service().run_due_once("worker-a", now=self.now)

        with self.session_factory() as session:
            run = session.scalar(select(PatrolRun))
            finding = session.scalar(select(Finding))
            assert run is not None and finding is not None
            self.assertEqual(run.status, "FAILED")
            self.assertEqual(finding.signal_key, "mcp_health")
            self.assertEqual(finding.severity, "CRITICAL")

    def test_resource_baseline_incident_keeps_resource_scope_in_agent_request(self) -> None:
        self._policy(signal_keys=["baseline_regression"])
        self.report = _posture_report(
            signals=[
                {
                    "key": "baseline_regression",
                    "title": "动态基线偏离",
                    "status": "warn",
                    "metric": "45 分",
                    "detail": "当前 CPU 负载高于历史中位数。",
                    "evidence_refs": ["posture_baseline"],
                }
            ]
        )

        self._service().run_due_once("worker-a", now=self.now)

        with self.session_factory() as session:
            task = session.scalar(select(Task))
            assert task is not None
            self.assertIn("系统资源动态基线", task.user_input)
            self.assertIn("CPU、内存、负载、PSI", task.user_input)


def _posture_report(
    *,
    report_status: str = "warn",
    signals: list[dict] | None = None,
) -> dict:
    return {
        "collected_at": "2026-07-12T11:00:00+00:00",
        "status": report_status,
        "snapshot": {"hostname": "node-a", "machine": "loongarch64"},
        "signals": signals
        if signals is not None
        else [
            {
                "key": "disk_pressure",
                "title": "磁盘压力",
                "status": "warn",
                "metric": "86.0%",
                "detail": "根分区使用率 86.0%。",
                "evidence_refs": ["disk_usage", "/"],
            },
            {
                "key": "mcp_health",
                "title": "感知链路",
                "status": "ok",
                "metric": "4/4 正常",
                "detail": "感知工具均正常。",
                "evidence_refs": ["system_snapshot", "disk_usage"],
            },
        ],
        "warnings": [],
        "tool_runs": [],
    }


if __name__ == "__main__":
    unittest.main()
