from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.collaboration.policy_controller import PolicyControllerProcessor
from backend.app.collaboration.service import IncidentCollaborationService
from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    AgentWorkItem,
    CollaborationEvent,
    Incident,
    IncidentCollaboration,
    Task,
    ToolCall,
    utcnow,
)


TABLES = [
    Task.__table__,
    ToolCall.__table__,
    ActionProposal.__table__,
    ActionSafetyCase.__table__,
    Incident.__table__,
    IncidentCollaboration.__table__,
    AgentWorkItem.__table__,
    CollaborationEvent.__table__,
]

POLICY_REF = "policy:lab-safe-log-rotate:v1"


class FakeRunner:
    calls: list[int] = []

    def __init__(self, session: Session, registry: object, **kwargs: object) -> None:
        self.session = session

    def execute_policy_authorized_proposal(
        self,
        proposal_id: int,
        *,
        controller_id: str,
        policy_authorization_ref: str,
    ) -> Task:
        self.calls.append(proposal_id)
        proposal = self.session.get(ActionProposal, proposal_id)
        assert proposal is not None
        proposal.status = "EXECUTED"
        proposal.updated_at = utcnow()
        task = self.session.get(Task, proposal.task_id)
        assert task is not None
        task.summary = "受限执行器完成策略授权动作。"
        return task


class FailingRunner(FakeRunner):
    def execute_policy_authorized_proposal(self, *args: object, **kwargs: object) -> Task:
        raise AssertionError("expired execution must not be replayed")


class PolicyControllerTest(unittest.TestCase):
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
        FakeRunner.calls = []

    def tearDown(self) -> None:
        self.engine.dispose()

    def test_deployed_policy_executes_once_and_advances_verification(self) -> None:
        notifications: list[tuple[int, str]] = []
        with self._policy_enabled():
            collaboration_id, proposal_id = self._ready_execution()
            processor = PolicyControllerProcessor(
                self.session_factory,
                object(),
                runner_factory=FakeRunner,
                ready_notifier=lambda collaboration_id, work_key: notifications.append(
                    (collaboration_id, work_key)
                ),
            )

            self.assertTrue(processor.run_once())
            self.assertFalse(processor.run_once())

        with self.session_factory() as session:
            collaboration = session.get(IncidentCollaboration, collaboration_id)
            assert collaboration is not None
            self.assertEqual(collaboration.execution_json["outcome"], "SUCCEEDED")
            items = {
                item.work_key: item
                for item in session.scalars(
                    select(AgentWorkItem).where(
                        AgentWorkItem.collaboration_id == collaboration_id
                    )
                )
            }
            self.assertEqual(items["execute"].status, "SUCCEEDED")
            self.assertEqual(items["execute"].attempt_count, 1)
            self.assertEqual(items["verify"].status, "READY")
            self.assertEqual(FakeRunner.calls, [proposal_id])
            self.assertEqual(notifications, [(collaboration_id, "verify")])
            self.assertTrue(
                IncidentCollaborationService(session).verify_chain(collaboration_id)["valid"]
            )

    def test_missing_deployed_policy_keeps_action_human_gated(self) -> None:
        collaboration_id, _ = self._ready_execution()
        processor = PolicyControllerProcessor(
            self.session_factory,
            object(),
            runner_factory=FakeRunner,
        )

        self.assertFalse(processor.run_once())

        with self.session_factory() as session:
            collaboration = session.get(IncidentCollaboration, collaboration_id)
            assert collaboration is not None
            item = session.scalar(
                select(AgentWorkItem).where(
                    AgentWorkItem.collaboration_id == collaboration_id,
                    AgentWorkItem.work_key == "execute",
                )
            )
            assert item is not None
            self.assertEqual(collaboration.autonomy_mode, "HUMAN_GATED")
            self.assertEqual(item.status, "READY")
            self.assertEqual(FakeRunner.calls, [])

    def test_contract_tampering_is_blocked_without_execution(self) -> None:
        with self._policy_enabled():
            collaboration_id, _ = self._ready_execution()
            with self.session_factory() as session:
                collaboration = session.get(IncidentCollaboration, collaboration_id)
                assert collaboration is not None
                contract = dict(collaboration.action_contract_json)
                contract["target_scope"] = ["host:unapproved"]
                collaboration.action_contract_json = contract
                session.commit()
            processor = PolicyControllerProcessor(
                self.session_factory,
                object(),
                runner_factory=FakeRunner,
            )
            self.assertTrue(processor.run_once())

        with self.session_factory() as session:
            collaboration = session.get(IncidentCollaboration, collaboration_id)
            assert collaboration is not None
            item = session.scalar(
                select(AgentWorkItem).where(
                    AgentWorkItem.collaboration_id == collaboration_id,
                    AgentWorkItem.work_key == "execute",
                )
            )
            assert item is not None
            self.assertEqual(collaboration.status, "NEEDS_OPERATOR")
            self.assertEqual(item.status, "BLOCKED")
            self.assertIn("哈希", item.last_error)
            self.assertEqual(FakeRunner.calls, [])

    def test_expired_lease_reconciles_terminal_proposal_without_replay(self) -> None:
        with self._policy_enabled():
            collaboration_id, proposal_id = self._ready_execution()
            with self.session_factory() as session:
                service = IncidentCollaborationService(session)
                service.claim_execution(
                    collaboration_id,
                    controller_id="crashed-controller",
                    lease_seconds=30,
                )
                item = session.scalar(
                    select(AgentWorkItem).where(
                        AgentWorkItem.collaboration_id == collaboration_id,
                        AgentWorkItem.work_key == "execute",
                    )
                )
                assert item is not None
                item.lease_expires_at = utcnow() - timedelta(seconds=1)
                proposal = session.get(ActionProposal, proposal_id)
                assert proposal is not None
                proposal.status = "EXECUTED"
                session.commit()

            processor = PolicyControllerProcessor(
                self.session_factory,
                object(),
                runner_factory=FailingRunner,
            )
            self.assertTrue(processor.run_once())

        with self.session_factory() as session:
            collaboration = session.get(IncidentCollaboration, collaboration_id)
            assert collaboration is not None
            item = session.scalar(
                select(AgentWorkItem).where(
                    AgentWorkItem.collaboration_id == collaboration_id,
                    AgentWorkItem.work_key == "execute",
                )
            )
            assert item is not None
            self.assertEqual(collaboration.execution_json["outcome"], "SUCCEEDED")
            self.assertEqual(item.attempt_count, 1)

    def _ready_execution(self) -> tuple[int, int]:
        with self.session_factory() as session:
            task = Task(
                trace_id=f"trace-{id(session)}-{utcnow().timestamp()}",
                user_input="分析并安全轮转实验日志",
                status="SEALED",
                risk_level="R2",
            )
            session.add(task)
            session.flush()
            proposal = ActionProposal(
                task_id=task.id,
                tool_name="safe_log_rotate",
                input_json={
                    "path": "/tmp/opscouncil-policy-test.log",
                    "backup": True,
                    "compress": True,
                    "keep_days": 30,
                    "dry_run": False,
                },
                risk_level="R2",
                reason="实验环境可逆日志轮转。",
                status="PENDING_APPROVAL",
                dry_run_result_json={"status": "ok", "evidence_refs": ["dry-run:1"]},
            )
            session.add(proposal)
            session.flush()
            incident = Incident(
                host_key="lab-node",
                signal_key="disk-pressure",
                status="OPEN",
                severity="WARN",
                title="实验日志占用升高",
                summary="受控实验日志触发阈值。",
                task_id=task.id,
            )
            session.add(incident)
            session.flush()
            service = IncidentCollaborationService(session)
            collaboration = service.start(
                incident.id,
                initial_evidence_refs=["metric:disk:1"],
            )
            self._submit_triage(service, collaboration.id)
            self._submit_investigation(service, collaboration.id)
            self._submit_plan(service, collaboration.id, proposal.id)
            session.commit()
            return collaboration.id, proposal.id

    @staticmethod
    def _submit_triage(service: IncidentCollaborationService, collaboration_id: int) -> None:
        service.claim(
            collaboration_id,
            "triage",
            role="signal_correlator",
            agent_name="signal-correlator",
        )
        service.submit(
            collaboration_id,
            "triage",
            role="signal_correlator",
            agent_name="signal-correlator",
            output={
                "incident_boundary": "实验节点磁盘压力事件。",
                "correlated_signals": [{
                    "signal_key": "disk-pressure",
                    "source": "patrol",
                    "observed_at": "2026-08-13T00:00:00Z",
                    "summary": "日志占用超过动态阈值。",
                    "evidence_ref": "metric:disk:1",
                }],
                "suppressed_alert_count": 2,
                "severity": "WARN",
                "affected_resources": ["host:lab-node"],
                "evidence_refs": ["metric:disk:1"],
            },
        )

    @staticmethod
    def _submit_investigation(
        service: IncidentCollaborationService,
        collaboration_id: int,
    ) -> None:
        service.claim(
            collaboration_id,
            "investigate",
            role="rca_investigator",
            agent_name="rca-investigator",
        )
        service.submit(
            collaboration_id,
            "investigate",
            role="rca_investigator",
            agent_name="rca-investigator",
            output={
                "decision": "CONCLUDE",
                "hypotheses": [{
                    "key": "log-growth",
                    "claim": "实验日志持续增长。",
                    "status": "SUPPORTED",
                    "evidence_refs": ["metric:disk:1", "file:/tmp/opscouncil-policy-test.log"],
                    "counter_evidence_refs": ["metric:inode:1"],
                }],
                "root_cause": "实验日志持续增长，inode 与其他挂载点正常。",
                "confidence": 0.91,
                "evidence_refs": [
                    "metric:disk:1",
                    "file:/tmp/opscouncil-policy-test.log",
                    "metric:inode:1",
                ],
                "counter_evidence_reviewed": True,
                "missing_evidence": [],
            },
        )

    @staticmethod
    def _submit_plan(
        service: IncidentCollaborationService,
        collaboration_id: int,
        proposal_id: int,
    ) -> None:
        service.claim(
            collaboration_id,
            "plan",
            role="remediation_planner",
            agent_name="remediation-planner",
        )
        service.submit(
            collaboration_id,
            "plan",
            role="remediation_planner",
            agent_name="remediation-planner",
            output={
                "action": {
                    "proposal_id": proposal_id,
                    "tool_name": "safe_log_rotate",
                    "arguments": {
                        "path": "/tmp/opscouncil-policy-test.log",
                        "backup": True,
                        "compress": True,
                        "keep_days": 30,
                        "dry_run": False,
                    },
                    "risk_level": "R2",
                    "environment": "LAB",
                    "target_scope": ["file:/tmp/opscouncil-policy-test.log"],
                    "preconditions": ["dry-run 已通过"],
                    "postconditions": ["源日志已备份且占用下降"],
                    "rollback_steps": ["从压缩备份恢复源日志"],
                    "reversible": True,
                    "canary": True,
                    "policy_authorization_ref": POLICY_REF,
                    "rationale": "只处理实验目录中的单个日志文件。",
                },
                "evidence_refs": ["dry-run:1", POLICY_REF],
                "alternatives_rejected": ["直接删除不具备回滚条件"],
            },
        )

    @staticmethod
    def _policy_enabled():
        patched = SimpleNamespace(collaboration_auto_policy_refs=(POLICY_REF,))
        return _DualPatch(
            patch("backend.app.collaboration.service.settings", patched),
            patch("backend.app.collaboration.policy_controller.settings", patched),
        )


class _DualPatch:
    def __init__(self, first, second) -> None:  # type: ignore[no-untyped-def]
        self.first = first
        self.second = second

    def __enter__(self):  # type: ignore[no-untyped-def]
        self.first.start()
        self.second.start()
        return self

    def __exit__(self, exc_type, exc, traceback):  # type: ignore[no-untyped-def]
        self.second.stop()
        self.first.stop()


if __name__ == "__main__":
    unittest.main()
