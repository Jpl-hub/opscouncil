from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
import unittest
import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.agent.intent import IntentDecision
from backend.app.agent.planner import Planner
from backend.app.agent.runner import AgentRunner
from backend.app.audit.service import AuditService
from backend.app.core.pydantic_compat import BaseModel
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.mcp.types import schema_hash, tool_runtime_manifest
from backend.app.models.entities import (
    AuditChain,
    Conversation,
    ConversationTurn,
    NotificationOutbox,
    PlatformCapabilitySnapshot,
    RiskChainAssessment,
    Operator,
    OperatorExternalIdentity,
    SafetyReview,
    SystemSnapshot,
    Task,
    TaskChannelBinding,
    TaskEvent,
    ToolCall,
)
from backend.app.schemas.enums import RiskLevel


@dataclass(frozen=True)
class FakeResolvedIntent:
    decision: IntentDecision
    provider: str = "test-model"
    model: str = "fake-qwen"
    prompt_hash: str = "0" * 64


class FakeIntentResolver:
    def resolve(
        self,
        user_input: str,
        conversation_context: list[dict[str, object]] | None = None,
    ) -> FakeResolvedIntent:
        return FakeResolvedIntent(
            IntentDecision(intent="network_exposure_analysis", confidence=0.97)
        )


class FakeRegistry:
    def __init__(self) -> None:
        self.tools = {
            name: ToolDefinition(
                name=name,
                version="1.0.0",
                description=f"fake {name}",
                risk_level=RiskLevel.R0,
                input_model=BaseModel,
                output_model=ToolResult,
                handler=lambda _: ToolResult(
                    observations=[{"local_address": "127.0.0.1:8000"}],
                    evidence_refs=["fake:/network"],
                ),
            )
            for name in (
                "platform_capability_profile",
                "system_snapshot",
                "network_listeners",
                "service_catalog_snapshot",
                "service_dependency_snapshot",
                "socket_process_context",
                "process_runtime_detail",
                "service_status",
            )
        }

    def get(self, name: str) -> ToolDefinition:
        return self.tools[name]

    def call(self, name: str, payload: dict) -> ToolResult:
        return self.tools[name].handler(payload)

    def tool_integrity(self, name: str) -> dict:
        manifest = tool_runtime_manifest(self.get(name))
        return {
            "status": "VERIFIED",
            "expected_manifest_sha256": manifest["manifest_sha256"],
            "current_manifest_sha256": manifest["manifest_sha256"],
            "implementation_sha256": manifest["implementation_sha256"],
            "source_module": manifest["source_module"],
            "permission_mode": manifest["permission_mode"],
        }


class FakeInvestigationEngine:
    def __init__(self, risk_level: str = "R0") -> None:
        self.calls: list[dict[str, object]] = []
        self.risk_level = risk_level

    def run(
        self,
        task: Task,
        skill_context: dict[str, object],
        canonical_summary: str,
    ) -> SimpleNamespace:
        self.calls.append(
            {
                "task_id": task.id,
                "status": task.status,
                "summary": canonical_summary,
                "skill": skill_context["skill_id"],
            }
        )
        analysis = SimpleNamespace(
            id=41,
            result_json={
                "conclusion": "发现一个本地监听端口。",
                "root_cause": "监听来自当前诊断服务。",
                "risk_level": self.risk_level,
                "reasoning_summary": ["network_listeners 返回 1 条观测"],
                "recommended_actions": [],
                "evidence_used": [{"source": "fake:/network", "summary": "网络监听证据"}],
                "residual_risk": "本次未执行系统变更。",
            },
        )
        return SimpleNamespace(
            status="CONCLUDED",
            stop_reason="关键证据已闭环",
            investigation=SimpleNamespace(id=31),
            analysis=analysis,
        )


class FollowUpEvidenceInvestigationEngine(FakeInvestigationEngine):
    def __init__(self, session: Session) -> None:
        super().__init__()
        self.session = session

    def run(
        self,
        task: Task,
        skill_context: dict[str, object],
        canonical_summary: str,
    ) -> SimpleNamespace:
        call = ToolCall(
            task_id=task.id,
            tool_name="network_listeners",
            tool_version="1.0.0",
            input_json={"limit": 80},
            output_json={
                "status": "ok",
                "observations": [
                    {
                        "local_address": "0.0.0.0:9090",
                        "exposure_scope": "wildcard",
                        "pid": 9090,
                        "process": "demo-api",
                    }
                ],
                "summary_fields": {
                    "listener_count": 1,
                    "wildcard_listener_count": 1,
                    "public_listener_count": 0,
                    "unknown_scope_listener_count": 0,
                    "unattributed_listener_count": 0,
                },
                "warnings": [],
                "risk_hints": ["存在全地址监听"],
                "evidence_refs": ["fake:/network/9090"],
            },
            risk_level="R1",
            status="ok",
            duration_ms=3,
        )
        self.session.add(call)
        self.session.flush()
        return super().run(task, skill_context, canonical_summary)


class FakeResponder:
    def __init__(self) -> None:
        self.analysis_results: list[dict | None] = []
        self.canonical_summaries: list[str] = []

    def compose(self, task: Task, analysis_result: dict | None, canonical_summary: str) -> str:
        self.analysis_results.append(analysis_result)
        self.canonical_summaries.append(canonical_summary)
        if analysis_result:
            return str(analysis_result["conclusion"])
        return canonical_summary


def force_iterative_investigation(intent: str, user_input: str) -> SimpleNamespace:
    return SimpleNamespace(mode="ITERATIVE_RCA", reason="测试要求进入调查流程。")


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for table in (
        Operator,
        OperatorExternalIdentity,
        Task,
        Conversation,
        ConversationTurn,
        TaskEvent,
        AuditChain,
        SafetyReview,
        ToolCall,
        PlatformCapabilitySnapshot,
        RiskChainAssessment,
        SystemSnapshot,
        TaskChannelBinding,
        NotificationOutbox,
    ):
        table.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def run_task(session: Session, runner: AgentRunner, user_input: str) -> Task:
    task = Task(trace_id=uuid.uuid4().hex, user_input=user_input, status="RECEIVED")
    session.add(task)
    session.flush()
    AuditService(session).append_event(
        task,
        "RECEIVED",
        "task_created",
        "测试任务已创建。",
        {"user_input": user_input},
    )
    runner.run(task, [])
    return task


class AgentDiagnosisWorkflowTest(unittest.TestCase):
    def test_runner_refreshes_persisted_follow_up_evidence_before_final_summary(self) -> None:
        with build_session() as session:
            runner = AgentRunner(session, FakeRegistry())  # type: ignore[arg-type]
            runner.intent_resolver = FakeIntentResolver()  # type: ignore[assignment]
            runner.planner = Planner()
            runner.investigation_depth_selector = force_iterative_investigation
            investigation = FollowUpEvidenceInvestigationEngine(session)
            responder = FakeResponder()
            runner.investigation_engine = investigation  # type: ignore[attr-defined]
            runner.responder = responder  # type: ignore[assignment]

            task = run_task(session, runner, "检查当前主机端口")

            self.assertIn("发现 1 个公网、全地址或范围未知监听", responder.canonical_summaries[-1])
            refreshed = session.scalar(
                select(TaskEvent).where(
                    TaskEvent.task_id == task.id,
                    TaskEvent.event_type == "investigation_evidence_risk_assessed",
                )
            )
            self.assertIsNotNone(refreshed)

    def test_runner_uses_mcp_evidence_risk_instead_of_model_risk(self) -> None:
        with build_session() as session:
            runner = AgentRunner(session, FakeRegistry())  # type: ignore[arg-type]
            runner.intent_resolver = FakeIntentResolver()  # type: ignore[assignment]
            runner.planner = Planner()
            runner.investigation_depth_selector = force_iterative_investigation
            runner.investigation_engine = FakeInvestigationEngine("R2")  # type: ignore[attr-defined]
            runner.responder = FakeResponder()  # type: ignore[assignment]

            task = run_task(session, runner, "检查当前主机端口")
            session.commit()

            self.assertEqual(task.risk_level, "R1")
            assessment = session.scalar(
                select(TaskEvent)
                .where(TaskEvent.task_id == task.id, TaskEvent.event_type == "evidence_risk_assessed")
                .limit(1)
            )
            self.assertIsNotNone(assessment)
            assert assessment is not None
            self.assertEqual(assessment.payload_json["previous_risk_level"], "R0")
            self.assertEqual(assessment.payload_json["evidence_risk_level"], "R1")
            self.assertEqual(assessment.payload_json["final_risk_level"], "R1")
            self.assertIn("监听端口缺少进程归属", assessment.payload_json["reasons"][0])
            self.assertIsNone(
                session.scalar(
                    select(TaskEvent)
                    .where(TaskEvent.task_id == task.id, TaskEvent.event_type == "risk_level_raised")
                    .limit(1)
                )
            )

    def test_runner_generates_one_diagnosis_after_mcp_evidence(self) -> None:
        with build_session() as session:
            runner = AgentRunner(session, FakeRegistry())  # type: ignore[arg-type]
            runner.intent_resolver = FakeIntentResolver()  # type: ignore[assignment]
            runner.planner = Planner()
            runner.investigation_depth_selector = force_iterative_investigation
            analysis = FakeInvestigationEngine()
            responder = FakeResponder()
            runner.investigation_engine = analysis  # type: ignore[attr-defined]
            runner.responder = responder  # type: ignore[assignment]

            task = run_task(session, runner, "检查当前主机端口")
            session.commit()

            self.assertEqual(len(analysis.calls), 1)
            self.assertIn("当前未发现公网或全地址监听", str(analysis.calls[0]["summary"]))
            self.assertIn("1 个仍需补充归属", str(analysis.calls[0]["summary"]))
            self.assertEqual(responder.analysis_results[0]["root_cause"], "监听来自当前诊断服务。")
            self.assertEqual(task.summary, "发现一个本地监听端口。")
            self.assertIsNone(
                session.scalar(
                    select(TaskEvent)
                    .where(TaskEvent.task_id == task.id, TaskEvent.event_type == "risk_level_raised")
                    .limit(1)
                )
            )
            summary_event = session.scalar(
                select(TaskEvent)
                .where(TaskEvent.task_id == task.id, TaskEvent.event_type == "summary_created")
                .limit(1)
            )
            self.assertIsNotNone(summary_event)
            assert summary_event is not None
            self.assertEqual(summary_event.payload_json["analysis_id"], 41)
            tool_event = session.scalar(
                select(TaskEvent)
                .where(TaskEvent.task_id == task.id, TaskEvent.event_type == "tool_call")
                .order_by(TaskEvent.id.asc())
                .limit(1)
            )
            self.assertIsNotNone(tool_event)
            assert tool_event is not None
            tool_call = session.scalar(
                select(ToolCall)
                .where(ToolCall.task_id == task.id)
                .order_by(ToolCall.id.asc())
                .limit(1)
            )
            self.assertIsNotNone(tool_call)
            assert tool_call is not None
            tool = runner.registry.get(tool_call.tool_name)
            self.assertEqual(tool_event.payload_json["tool_call_id"], tool_call.id)
            self.assertEqual(
                tool_event.payload_json["input_schema_hash"],
                schema_hash(tool.input_model.model_json_schema()),
            )
            self.assertEqual(
                tool_event.payload_json["output_schema_hash"],
                schema_hash(tool.output_model.model_json_schema()),
            )


if __name__ == "__main__":
    unittest.main()
