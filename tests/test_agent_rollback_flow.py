from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.agent.runner import AgentRunner
from backend.app.executor.tools import register_executor_tools
from backend.app.mcp.registry import ToolRegistry
from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    Approval,
    AuditChain,
    ExecutionRecord,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    SafetyReview,
    Task,
    TaskChannelBinding,
    TaskEvent,
    ToolCall,
)


TABLES = [
    Operator.__table__,
    OperatorExternalIdentity.__table__,
    Task.__table__,
    TaskEvent.__table__,
    ToolCall.__table__,
    SafetyReview.__table__,
    Approval.__table__,
    ActionProposal.__table__,
    ActionSafetyCase.__table__,
    ExecutionRecord.__table__,
    AuditChain.__table__,
    TaskChannelBinding.__table__,
    NotificationOutbox.__table__,
]


class CorruptPostVerifierRegistry(ToolRegistry):
    def __init__(self) -> None:
        super().__init__()
        self.verifier_calls = 0

    def call(self, name: str, payload: dict):  # type: ignore[no-untyped-def]
        result = super().call(name, payload)
        if name != "file_integrity_state":
            return result
        self.verifier_calls += 1
        if self.verifier_calls == 2:
            for observation in result.observations:
                if str(observation.get("path", "")).endswith(".gz"):
                    observation["content_sha256"] = "0" * 64
        return result


class IncompletePreVerifierRegistry(ToolRegistry):
    def call(self, name: str, payload: dict):  # type: ignore[no-untyped-def]
        result = super().call(name, payload)
        if name == "file_integrity_state" and result.observations:
            result.observations[0]["hash_truncated"] = True
        return result


class UnknownOutcomeRegistry(ToolRegistry):
    def call(self, name: str, payload: dict):  # type: ignore[no-untyped-def]
        result = super().call(name, payload)
        if name == "safe_log_rotate" and payload.get("dry_run") is False:
            raise RuntimeError("executor response channel closed after dispatch")
        return result


class AgentRollbackFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in TABLES:
            table.create(engine)
        self.session = Session(engine, expire_on_commit=False)
        self.registry = ToolRegistry()
        register_executor_tools(self.registry)

    def tearDown(self) -> None:
        self.session.close()

    def test_rotation_execution_creates_one_real_rollback_proposal(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            source = Path(tmp) / "app.log"
            source.write_text("original log\n" * 64, encoding="utf-8")
            task = Task(
                trace_id="trace-rollback-flow",
                user_input="清理测试日志",
                intent="disk_pressure_analysis",
                status="SEALED",
                risk_level="R2",
                summary="等待审批。",
            )
            self.session.add(task)
            self.session.flush()
            proposal = ActionProposal(
                task_id=task.id,
                tool_name="safe_log_rotate",
                input_json={
                    "path": str(source),
                    "backup": True,
                    "compress": True,
                    "keep_days": 30,
                    "dry_run": False,
                },
                risk_level="R2",
                reason="测试轮转。",
                status="PENDING_APPROVAL",
                dry_run_result_json={
                    "status": "ok",
                    "evidence_refs": [str(source)],
                },
            )
            self.session.add(proposal)
            self.session.commit()

            runner = AgentRunner(self.session, self.registry)
            runner.safety_cases.create_for_proposal(proposal)
            with patch(
                "backend.app.executor.policy.current_identity",
                return_value={"uid": 1000, "user": "vmuser"},
            ):
                runner.approve_and_execute_proposal(proposal.id)
            self.session.commit()

            proposals = list(
                self.session.execute(
                    select(ActionProposal).where(ActionProposal.task_id == task.id).order_by(ActionProposal.id)
                ).scalars()
            )

            self.assertEqual(source.stat().st_size, 0)
            self.assertEqual(len(proposals), 2)
            rollback = proposals[1]
            self.assertEqual(rollback.tool_name, "restore_log_backup")
            self.assertEqual(rollback.status, "PENDING_APPROVAL")
            self.assertEqual(rollback.input_json["restore_target"], str(source))
            self.assertTrue(Path(rollback.input_json["artifact_path"]).exists())
            self.assertEqual(
                len([item for item in proposals if item.tool_name == "restore_log_backup"]),
                1,
            )
            rotation_calls = list(
                self.session.scalars(
                    select(ToolCall)
                    .where(ToolCall.task_id == task.id)
                    .order_by(ToolCall.id.asc())
                )
            )
            self.assertEqual(
                [call.tool_name for call in rotation_calls],
                ["file_integrity_state", "safe_log_rotate", "file_integrity_state"],
            )
            rotation_verification = self.session.scalar(
                select(TaskEvent)
                .where(TaskEvent.task_id == task.id, TaskEvent.event_type == "verify_result")
                .order_by(TaskEvent.id.desc())
                .limit(1)
            )
            self.assertIsNotNone(rotation_verification)
            assert rotation_verification is not None
            self.assertTrue(rotation_verification.payload_json["valid"])
            self.assertEqual(len(rotation_verification.payload_json["verifier_tool_call_ids"]), 2)

            with patch(
                "backend.app.executor.policy.current_identity",
                return_value={"uid": 1000, "user": "vmuser"},
            ):
                runner.approve_and_execute_proposal(rollback.id)
            self.session.commit()

            self.assertEqual(source.read_text(encoding="utf-8"), "original log\n" * 64)
            pending_rollbacks = list(
                self.session.execute(
                    select(ActionProposal).where(
                        ActionProposal.task_id == task.id,
                        ActionProposal.tool_name == "restore_log_backup",
                        ActionProposal.status == "PENDING_APPROVAL",
                    )
                ).scalars()
            )
            self.assertEqual(pending_rollbacks, [])
            all_calls = list(
                self.session.scalars(
                    select(ToolCall)
                    .where(ToolCall.task_id == task.id)
                    .order_by(ToolCall.id.asc())
                )
            )
            self.assertEqual(
                [call.tool_name for call in all_calls].count("file_integrity_state"),
                4,
            )
            verification_events = list(
                self.session.scalars(
                    select(TaskEvent)
                    .where(TaskEvent.task_id == task.id, TaskEvent.event_type == "verify_result")
                    .order_by(TaskEvent.id.asc())
                )
            )
            self.assertEqual(len(verification_events), 2)
            self.assertTrue(all(event.payload_json["valid"] for event in verification_events))

    def test_failed_independent_verification_requires_operator_and_no_rollback_proposal(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            source = Path(tmp) / "app.log"
            source.write_text("critical test log\n" * 64, encoding="utf-8")
            task = Task(
                trace_id="trace-verification-failure",
                user_input="清理测试日志",
                intent="disk_pressure_analysis",
                status="SEALED",
                risk_level="R2",
                summary="等待审批。",
            )
            self.session.add(task)
            self.session.flush()
            proposal = ActionProposal(
                task_id=task.id,
                tool_name="safe_log_rotate",
                input_json={
                    "path": str(source),
                    "backup": True,
                    "compress": True,
                    "keep_days": 30,
                    "dry_run": False,
                },
                risk_level="R2",
                reason="测试独立校验失败。",
                status="PENDING_APPROVAL",
                dry_run_result_json={
                    "status": "ok",
                    "evidence_refs": [str(source)],
                },
            )
            self.session.add(proposal)
            self.session.commit()
            registry = CorruptPostVerifierRegistry()
            register_executor_tools(registry)
            runner = AgentRunner(self.session, registry)
            runner.safety_cases.create_for_proposal(proposal)

            with patch(
                "backend.app.executor.policy.current_identity",
                return_value={"uid": 1000, "user": "vmuser"},
            ):
                runner.approve_and_execute_proposal(proposal.id)
            self.session.commit()

            self.assertEqual(source.stat().st_size, 0)
            self.assertEqual(proposal.status, "BLOCKED")
            self.assertEqual(task.status, "NEEDS_OPERATOR")
            rollback = self.session.scalar(
                select(ActionProposal).where(
                    ActionProposal.task_id == task.id,
                    ActionProposal.tool_name == "restore_log_backup",
                )
            )
            self.assertIsNone(rollback)
            event = self.session.scalar(
                select(TaskEvent)
                .where(TaskEvent.task_id == task.id, TaskEvent.event_type == "verify_result")
                .order_by(TaskEvent.id.desc())
                .limit(1)
            )
            self.assertIsNotNone(event)
            assert event is not None
            self.assertFalse(event.payload_json["valid"])

    def test_incomplete_precondition_evidence_blocks_action_before_execution(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            source = Path(tmp) / "app.log"
            original = "precondition must remain\n" * 32
            source.write_text(original, encoding="utf-8")
            task = Task(
                trace_id="trace-precondition-failure",
                user_input="清理测试日志",
                intent="disk_pressure_analysis",
                status="SEALED",
                risk_level="R2",
                summary="等待审批。",
            )
            self.session.add(task)
            self.session.flush()
            proposal = ActionProposal(
                task_id=task.id,
                tool_name="safe_log_rotate",
                input_json={
                    "path": str(source),
                    "backup": True,
                    "compress": True,
                    "keep_days": 30,
                    "dry_run": False,
                },
                risk_level="R2",
                reason="测试执行前证据。",
                status="PENDING_APPROVAL",
                dry_run_result_json={
                    "status": "ok",
                    "evidence_refs": [str(source)],
                },
            )
            self.session.add(proposal)
            self.session.commit()
            registry = IncompletePreVerifierRegistry()
            register_executor_tools(registry)
            runner = AgentRunner(self.session, registry)
            runner.safety_cases.create_for_proposal(proposal)

            with patch(
                "backend.app.executor.policy.current_identity",
                return_value={"uid": 1000, "user": "vmuser"},
            ):
                runner.approve_and_execute_proposal(proposal.id)

            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertEqual(proposal.status, "BLOCKED")
            self.assertEqual(task.status, "BLOCKED")
            calls = list(
                self.session.scalars(
                    select(ToolCall).where(ToolCall.task_id == task.id)
                )
            )
            self.assertEqual([call.tool_name for call in calls], ["file_integrity_state"])
            executions = list(
                self.session.scalars(
                    select(ExecutionRecord).where(ExecutionRecord.task_id == task.id)
                )
            )
            self.assertEqual(executions, [])

    def test_uncertain_side_effect_is_not_retried_or_reported_as_failure(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            source = Path(tmp) / "app.log"
            source.write_text("unknown outcome\n" * 32, encoding="utf-8")
            task = Task(
                trace_id="trace-unknown-outcome",
                user_input="安全轮转测试日志",
                intent="disk_pressure_analysis",
                status="SEALED",
                risk_level="R2",
                summary="等待审批。",
            )
            self.session.add(task)
            self.session.flush()
            proposal = ActionProposal(
                task_id=task.id,
                tool_name="safe_log_rotate",
                input_json={
                    "path": str(source),
                    "backup": True,
                    "compress": True,
                    "keep_days": 30,
                    "dry_run": False,
                },
                risk_level="R2",
                reason="验证不确定结果隔离。",
                status="PENDING_APPROVAL",
                dry_run_result_json={
                    "status": "ok",
                    "evidence_refs": [str(source)],
                },
            )
            self.session.add(proposal)
            self.session.commit()
            registry = UnknownOutcomeRegistry()
            register_executor_tools(registry)
            runner = AgentRunner(self.session, registry)
            safety_case = runner.safety_cases.create_for_proposal(proposal)

            with patch(
                "backend.app.executor.policy.current_identity",
                return_value={"uid": 1000, "user": "vmuser"},
            ):
                runner.approve_and_execute_proposal(proposal.id)

            self.assertEqual(source.stat().st_size, 0)
            self.assertEqual(proposal.status, "NEEDS_OPERATOR")
            self.assertEqual(task.status, "NEEDS_OPERATOR")
            self.assertEqual(safety_case.status, "NEEDS_OPERATOR")
            self.assertEqual(
                safety_case.result_json["execution"]["outcome"],
                "UNKNOWN",
            )
            action_calls = list(
                self.session.scalars(
                    select(ToolCall).where(
                        ToolCall.task_id == task.id,
                        ToolCall.tool_name == "safe_log_rotate",
                    )
                )
            )
            self.assertEqual(len(action_calls), 1)
            self.assertEqual(action_calls[0].status, "unknown")
            event = self.session.scalar(
                select(TaskEvent).where(
                    TaskEvent.task_id == task.id,
                    TaskEvent.event_type == "tool_call_outcome_unknown",
                )
            )
            self.assertIsNotNone(event)
            assert event is not None
            self.assertFalse(event.payload_json["automatic_retry"])


if __name__ == "__main__":
    unittest.main()
