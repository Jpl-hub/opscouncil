from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch
import subprocess
import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.agent.runner import AgentRunner
from backend.app.assets.service import ServiceExpectationService
from backend.app.executor import policy
from backend.app.executor.tools import (
    RestartManagedServiceInput,
    register_executor_tools,
    restart_managed_service,
)
from backend.app.executor.verification import (
    post_action_verification_input,
    pre_action_verification_input,
    validate_post_action_evidence,
    validate_pre_action_evidence,
    verification_tool_name,
)
from backend.app.safety.engine import SafetyEngine
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult
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
    ServiceExpectation,
    Task,
    TaskChannelBinding,
    TaskEvent,
    ToolCall,
)
from backend.app.perception.tools import ServiceStatusInput
from backend.app.perception.topology_tools import ServiceDependencySnapshotInput
from backend.app.schemas.enums import RiskLevel


FAILED_STATE = {
    "Id": "demo-worker.service",
    "LoadState": "loaded",
    "ActiveState": "failed",
    "SubState": "failed",
    "ExecMainPID": "0",
    "Result": "exit-code",
    "NRestarts": "1",
}

ACTIVE_STATE = {
    "Id": "demo-worker.service",
    "LoadState": "loaded",
    "ActiveState": "active",
    "SubState": "running",
    "ExecMainPID": "4242",
    "Result": "success",
    "NRestarts": "2",
}

NORMALIZED_FAILED_STATE = {
    "unit": "demo-worker.service",
    "load_state": "loaded",
    "active_state": "failed",
    "sub_state": "failed",
    "main_pid": 0,
    "result": "exit-code",
    "restart_count": 1,
}

NORMALIZED_ACTIVE_STATE = {
    "unit": "demo-worker.service",
    "load_state": "loaded",
    "active_state": "active",
    "sub_state": "running",
    "main_pid": 4242,
    "result": "success",
    "restart_count": 2,
}


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
    ServiceExpectation.__table__,
]


class StatefulServiceRegistry(ToolRegistry):
    def __init__(self) -> None:
        super().__init__()
        self.active = False
        self.register(
            ToolDefinition(
                name="service_status",
                version="1.0.0",
                description="test service state",
                risk_level=RiskLevel.R0,
                input_model=ServiceStatusInput,
                output_model=ToolResult,
                handler=self._service_status,
            )
        )
        self.register(
            ToolDefinition(
                name="service_dependency_snapshot",
                version="1.1.0",
                description="test service impact state",
                risk_level=RiskLevel.R0,
                input_model=ServiceDependencySnapshotInput,
                output_model=ToolResult,
                handler=self._service_dependency_snapshot,
            )
        )
        register_executor_tools(self)

    def _service_status(self, _: ServiceStatusInput) -> ToolResult:
        return ToolResult(observations=[ACTIVE_STATE if self.active else FAILED_STATE])

    def _service_dependency_snapshot(
        self,
        payload: ServiceDependencySnapshotInput,
    ) -> ToolResult:
        unit = payload.focus_units[0]
        return ToolResult(
            observations=[
                {
                    "change_impact": {
                        "status": "ASSESSED",
                        "coverage": "FULL",
                        "action": payload.change_action,
                        "target_units": [unit],
                        "predicted_units": [
                            {
                                "unit": unit,
                                "role": "TARGET",
                                "certainty": "DIRECT",
                                "mechanism": "DIRECT_TARGET",
                                "path": [f"service:{unit}"],
                                "active_state": "active" if self.active else "failed",
                                "sub_state": "running" if self.active else "failed",
                                "invocation_id": "after" if self.active else "before",
                            }
                        ],
                        "predicted_clients": [],
                        "propagated_unit_count": 0,
                        "possible_client_count": 0,
                        "mechanism_counts": {},
                        "evidence_gaps": [],
                    }
                }
            ],
            evidence_refs=[f"systemctl show {unit}"],
        )

    def call(self, name: str, payload: dict) -> ToolResult:
        result = super().call(name, payload)
        if name == "restart_managed_service" and payload.get("dry_run") is False:
            self.active = True
        return result


class ManagedServiceRestartToolTest(unittest.TestCase):
    def test_dry_run_requires_exact_allowlist_and_does_not_restart(self) -> None:
        with (
            patch(
                "backend.app.executor.tools.settings",
                SimpleNamespace(restartable_systemd_units=("demo-worker.service",)),
            ),
            patch("backend.app.executor.tools._read_systemd_state", return_value=FAILED_STATE),
            patch("backend.app.executor.tools._run_systemd_restart") as restart,
        ):
            result = restart_managed_service(
                RestartManagedServiceInput(unit="demo-worker", dry_run=True)
            )

        restart.assert_not_called()
        self.assertEqual(result.observations[0]["unit"], "demo-worker.service")
        self.assertEqual(result.observations[0]["active_state"], "failed")
        self.assertTrue(result.observations[0]["restart_will_be_requested"])
        self.assertEqual(result.actions_proposed[0]["operation"], "restart_managed_service")

    def test_execution_requests_one_restart_without_claiming_recovery(self) -> None:
        completed = subprocess.CompletedProcess(
            ["systemctl", "restart", "demo-worker.service"],
            returncode=0,
            stdout="",
            stderr="",
        )
        with (
            patch(
                "backend.app.executor.tools.settings",
                SimpleNamespace(restartable_systemd_units=("demo-worker.service",)),
            ),
            patch("backend.app.executor.tools._read_systemd_state", return_value=FAILED_STATE),
            patch("backend.app.executor.tools._run_systemd_restart", return_value=completed) as restart,
        ):
            result = restart_managed_service(
                RestartManagedServiceInput(unit="demo-worker.service", dry_run=False)
            )

        restart.assert_called_once_with("demo-worker.service")
        self.assertTrue(result.observations[0]["restart_requested"])
        self.assertNotIn("recovered", result.observations[0])
        self.assertIn("独立", "".join(result.warnings))

    def test_critical_service_is_denied_even_if_misconfigured_in_allowlist(self) -> None:
        with patch(
            "backend.app.executor.tools.settings",
            SimpleNamespace(restartable_systemd_units=("sshd.service",)),
        ):
            with self.assertRaisesRegex(ValueError, "永久保护"):
                restart_managed_service(
                    RestartManagedServiceInput(unit="sshd.service", dry_run=True)
                )


class ManagedServiceRestartPolicyTest(unittest.TestCase):
    def test_execution_policy_allows_only_configured_unit_at_r3(self) -> None:
        configured = SimpleNamespace(
            executor_mode="restricted-local",
            executor_user="opscouncil-agent",
            allow_root_executor=False,
            restartable_systemd_units=("demo-worker.service",),
        )
        with (
            patch.object(policy, "settings", configured),
            patch.object(policy, "current_identity", return_value={"uid": 1001, "user": "opscouncil-agent"}),
        ):
            context = policy.authorize_execution(
                "restart_managed_service",
                "R3",
                {"unit": "demo-worker.service", "dry_run": False},
            )

        self.assertEqual(context["allowed"], "true")
        self.assertEqual(context["scope"]["unit"], "demo-worker.service")

    def test_dynamic_safety_rejects_unlisted_unit(self) -> None:
        with patch(
            "backend.app.safety.engine.settings",
            SimpleNamespace(restartable_systemd_units=("demo-worker.service",)),
        ):
            outcome = SafetyEngine.classify_tool_action(
                "restart_managed_service",
                {"unit": "unlisted.service", "dry_run": False},
            )

        self.assertEqual(outcome.decision.value, "REJECT")
        self.assertEqual(outcome.risk_level.value, "R4")


class ManagedServiceRestartVerificationTest(unittest.TestCase):
    def test_service_restart_uses_service_status_for_pre_and_post_verification(self) -> None:
        payload = {"unit": "demo-worker.service", "dry_run": False}

        self.assertEqual(verification_tool_name("restart_managed_service"), "service_status")
        self.assertEqual(
            pre_action_verification_input("restart_managed_service", payload),
            {"unit": "demo-worker.service"},
        )
        self.assertEqual(
            post_action_verification_input("restart_managed_service", payload, {"observations": []}),
            {"unit": "demo-worker.service"},
        )

        pre = validate_pre_action_evidence(
            "restart_managed_service",
            payload,
            {"observations": [FAILED_STATE]},
        )
        post = validate_post_action_evidence(
            "restart_managed_service",
            payload,
            {"observations": [FAILED_STATE]},
            {"observations": [{"unit": "demo-worker.service", "restart_requested": True}]},
            {"observations": [ACTIVE_STATE]},
        )

        self.assertTrue(pre.valid)
        self.assertTrue(post.valid)
        self.assertEqual(post.details["active_state_after"], "active")
        self.assertEqual(post.details["main_pid_after"], 4242)

    def test_service_restart_accepts_current_normalized_service_status_contract(
        self,
    ) -> None:
        payload = {"unit": "demo-worker.service", "dry_run": False}

        pre = validate_pre_action_evidence(
            "restart_managed_service",
            payload,
            {"observations": [NORMALIZED_FAILED_STATE]},
        )
        post = validate_post_action_evidence(
            "restart_managed_service",
            payload,
            {"observations": [NORMALIZED_FAILED_STATE]},
            {
                "observations": [
                    {
                        "unit": "demo-worker.service",
                        "restart_requested": True,
                    }
                ]
            },
            {"observations": [NORMALIZED_ACTIVE_STATE]},
        )

        self.assertTrue(pre.valid)
        self.assertTrue(post.valid)
        self.assertEqual(pre.details["active_state_before"], "failed")
        self.assertEqual(post.details["active_state_after"], "active")
        self.assertEqual(post.details["main_pid_after"], 4242)

    def test_post_verification_does_not_accept_failed_state(self) -> None:
        decision = validate_post_action_evidence(
            "restart_managed_service",
            {"unit": "demo-worker.service", "dry_run": False},
            {"observations": [FAILED_STATE]},
            {"observations": [{"unit": "demo-worker.service", "restart_requested": True}]},
            {"observations": [FAILED_STATE]},
        )

        self.assertFalse(decision.valid)


class ManagedServiceRestartFlowTest(unittest.TestCase):
    def test_observed_allowlisted_service_runs_through_approval_and_independent_verification(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in TABLES:
            table.create(engine)
        session = Session(engine, expire_on_commit=False)
        registry = StatefulServiceRegistry()
        configured = SimpleNamespace(
            executor_mode="restricted-local",
            executor_user="opscouncil-agent",
            allow_root_executor=False,
            restartable_systemd_units=("demo-worker.service",),
            feishu_default_chat_id="",
        )
        task = Task(
            trace_id="trace-service-restart",
            user_input="请重启 demo-worker 服务",
            intent="log_analysis",
            status="SEALED",
            risk_level="R3",
            summary="等待处置。",
        )
        session.add(task)
        session.flush()
        ServiceExpectationService(session).register(
            host_key="*",
            unit_name="demo-worker.service",
            expected_active_state="active",
            service_owner="任务平台组",
            criticality="HIGH",
            environment="TEST",
            rationale="测试任务服务应保持运行。",
            source_ref="managed-restart-test",
            approved_by="ops-admin",
        )
        desired_output = {
            "status": "ok",
            "observations": [
                {
                    "unit": "demo-worker.service",
                    "expected_active_state": "active",
                    "service_owner": "任务平台组",
                    "criticality": "HIGH",
                    "environment": "TEST",
                }
            ],
            "evidence_refs": ["service-expectation:demo-worker"],
        }
        impact_output = {
            "status": "ok",
            "observations": [
                {
                    "change_impact": {
                        "status": "ASSESSED",
                        "coverage": "FULL",
                        "action": "restart",
                        "target_units": ["demo-worker.service"],
                        "propagated_unit_count": 0,
                        "possible_client_count": 0,
                        "predicted_units": [
                            {
                                "unit": "demo-worker.service",
                                "role": "TARGET",
                                "certainty": "DIRECT",
                                "mechanism": "DIRECT_TARGET",
                                "path": ["service:demo-worker.service"],
                            }
                        ],
                        "predicted_clients": [],
                        "mechanism_counts": {},
                        "evidence_gaps": [],
                    }
                }
            ],
            "evidence_refs": ["systemctl show demo-worker.service"],
        }
        session.add_all(
            [
                ToolCall(
                    task_id=task.id,
                    tool_name="service_desired_state",
                    tool_version="1.0.0",
                    input_json={"unit": "demo-worker.service"},
                    output_json=desired_output,
                    risk_level="R0",
                    status="ok",
                ),
                ToolCall(
                    task_id=task.id,
                    tool_name="service_dependency_snapshot",
                    tool_version="1.1.0",
                    input_json={
                        "focus_units": ["demo-worker.service"],
                        "change_action": "restart",
                    },
                    output_json=impact_output,
                    risk_level="R0",
                    status="ok",
                ),
            ]
        )
        session.flush()
        runner = AgentRunner(session, registry)
        observations = [
            {
                "tool_name": "service_status",
                "result": {"observations": [FAILED_STATE]},
            },
            {
                "tool_name": "service_desired_state",
                "result": desired_output,
            },
            {
                "tool_name": "service_dependency_snapshot",
                "result": impact_output,
            },
        ]
        completed = subprocess.CompletedProcess(
            ["systemctl", "restart", "demo-worker.service"],
            returncode=0,
            stdout="",
            stderr="",
        )

        with (
            patch("backend.app.agent.runner.settings", configured),
            patch("backend.app.executor.tools.settings", configured),
            patch("backend.app.executor.policy.settings", configured),
            patch("backend.app.safety.engine.settings", configured),
            patch(
                "backend.app.executor.policy.current_identity",
                return_value={"uid": 1001, "user": "opscouncil-agent"},
            ),
            patch("backend.app.executor.tools._read_systemd_state", return_value=FAILED_STATE),
            patch("backend.app.executor.tools._run_systemd_restart", return_value=completed) as restart,
        ):
            context = runner._create_action_proposals(task, observations)
            proposal = session.scalar(
                select(ActionProposal).where(ActionProposal.task_id == task.id)
            )
            assert proposal is not None
            runner.approve_and_execute_proposal(proposal.id)

        self.assertEqual(context["unit"], "demo-worker.service")
        self.assertEqual(proposal.status, "EXECUTED")
        self.assertEqual(task.status, "SEALED")
        restart.assert_called_once_with("demo-worker.service")
        calls = list(
            session.scalars(
                select(ToolCall).where(ToolCall.task_id == task.id).order_by(ToolCall.id)
            )
        )
        self.assertEqual(
            [call.tool_name for call in calls],
            [
                "service_desired_state",
                "service_dependency_snapshot",
                "service_status",
                "service_dependency_snapshot",
                "restart_managed_service",
                "service_status",
                "service_dependency_snapshot",
            ],
        )
        verify_event = session.scalar(
            select(TaskEvent)
            .where(TaskEvent.task_id == task.id, TaskEvent.event_type == "verify_result")
            .order_by(TaskEvent.id.desc())
            .limit(1)
        )
        assert verify_event is not None
        self.assertTrue(verify_event.payload_json["valid"])
        safety_case = session.scalar(
            select(ActionSafetyCase).where(
                ActionSafetyCase.proposal_id == proposal.id
            )
        )
        assert safety_case is not None
        self.assertEqual(
            safety_case.result_json["impact_precondition"]["outcome"],
            "CONFIRMED",
        )
        self.assertEqual(
            safety_case.result_json["impact_verification"]["outcome"],
            "CONFIRMED",
        )
        session.close()


if __name__ == "__main__":
    unittest.main()
