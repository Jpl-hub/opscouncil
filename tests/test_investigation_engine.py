from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.ai.analysis import AIAnalysisResult
from backend.app.ai.client import ModelNotConfiguredError
from backend.app.audit.service import AuditService
from backend.app.core.pydantic_compat import BaseModel, Field
from backend.app.investigation.engine import InvestigationEngine
from backend.app.investigation.model import AnalysisRepairResult, ModelDecision
from backend.app.investigation.policy import InvestigationBudget
from backend.app.investigation.schemas import InvestigationDecision
from backend.app.knowledge.retrieval import (
    KnowledgeHit,
    KnowledgeRetrievalUnavailableError,
    RetrievalProvenance,
)
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.models.entities import (
    AIAnalysis,
    AuditChain,
    EvidenceItem,
    Hypothesis,
    HypothesisEvidence,
    Investigation,
    InvestigationStep,
    SystemSnapshot,
    Task,
    TaskEvent,
    ToolCall,
)
from backend.app.schemas.enums import RiskLevel


class EmptyInput(BaseModel):
    pass


class LimitInput(BaseModel):
    limit: int = Field(default=5, ge=1, le=20)


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    for table in (
        Task,
        ToolCall,
        SystemSnapshot,
        AIAnalysis,
        TaskEvent,
        AuditChain,
        Investigation,
        InvestigationStep,
        EvidenceItem,
        Hypothesis,
        HypothesisEvidence,
    ):
        table.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def build_registry() -> tuple[ToolRegistry, list[str]]:
    registry = ToolRegistry()
    process_calls: list[str] = []
    registry.register(
        ToolDefinition(
            name="network_listeners",
            version="1.0.0",
            description="读取网络监听",
            risk_level=RiskLevel.R0,
            input_model=LimitInput,
            output_model=ToolResult,
            handler=lambda _: ToolResult(),
        )
    )

    def process_handler(payload: BaseModel) -> ToolResult:
        process_calls.append(str(payload.model_dump(mode="json")))
        return ToolResult(
            observations=[{"pid": 73, "comm": "demo-api", "state": "S"}],
            evidence_refs=["proc:73"],
        )

    registry.register(
        ToolDefinition(
            name="process_list",
            version="1.0.0",
            description="读取进程列表",
            risk_level=RiskLevel.R0,
            input_model=LimitInput,
            output_model=ToolResult,
            handler=process_handler,
        )
    )
    registry.register(
        ToolDefinition(
            name="safe_log_rotate",
            version="1.0.0",
            description="轮转日志",
            risk_level=RiskLevel.R2,
            input_model=EmptyInput,
            output_model=ToolResult,
            handler=lambda _: ToolResult(actions_proposed=[{"changed": True}]),
        )
    )
    return registry, process_calls


def add_task_and_baseline(
    session: Session,
    *,
    tool_name: str = "network_listeners",
    input_json: dict | None = None,
) -> tuple[Task, ToolCall]:
    task = Task(
        trace_id=f"trace-{tool_name}-{datetime.now(timezone.utc).timestamp()}",
        user_input="检查网络暴露并定位进程归属",
        intent="network_exposure_analysis",
        status="SUMMARIZE",
        risk_level="R1",
        summary="发现一个全地址监听且缺少进程归属。",
    )
    session.add(task)
    session.flush()
    call = ToolCall(
        task_id=task.id,
        tool_name=tool_name,
        tool_version="1.0.0",
        input_json=input_json if input_json is not None else {"limit": 80},
        output_json={
            "status": "ok",
            "observations": [{"local_address": "0.0.0.0:8080", "pid": None}],
            "evidence_refs": ["ss:tcp:8080"],
            "warnings": [],
            "summary_fields": {},
            "risk_hints": ["全地址监听缺少进程归属"],
        },
        risk_level="R0",
        status="ok",
        duration_ms=9,
        ended_at=datetime.now(timezone.utc),
    )
    session.add(call)
    session.flush()
    return task, call


def collect_decision(evidence_id: int, tool_name: str = "process_list") -> InvestigationDecision:
    return InvestigationDecision.model_validate(
        {
            "decision": "COLLECT",
            "hypotheses": [
                {
                    "key": "listener_without_owner",
                    "title": "监听端口缺少进程归属",
                    "rationale": "监听证据缺少 PID",
                    "evidence_gap": "需要进程列表补证",
                }
            ],
            "evidence_links": [
                {
                    "hypothesis_key": "listener_without_owner",
                    "evidence_id": evidence_id,
                    "relation": "SUPPORTS",
                    "rationale": "监听记录缺少进程归属",
                }
            ],
            "next_tool": {
                "tool_name": tool_name,
                "arguments": {},
                "reason": "补充进程归属证据",
            },
            "conclusion": None,
            "stop_reason": "当前证据不足",
        }
    )


def conclude_decision(evidence_ids: list[int]) -> InvestigationDecision:
    return InvestigationDecision.model_validate(
        {
            "decision": "CONCLUDE",
            "hypotheses": [
                {
                    "key": "listener_without_owner",
                    "title": "监听归属已确认",
                    "rationale": "监听与进程证据已关联",
                    "evidence_gap": "仍需业务责任人确认端口必要性",
                }
            ],
            "evidence_links": [
                {
                    "hypothesis_key": "listener_without_owner",
                    "evidence_id": evidence_id,
                    "relation": "SUPPORTS",
                    "rationale": "真实工具证据支持该判断",
                }
                for evidence_id in evidence_ids
            ],
            "next_tool": None,
            "conclusion": {
                "conclusion": "已确认 8080 端口由 demo-api 进程监听。",
                "root_cause": "服务监听在全地址且初始采样缺少进程归属。",
                "risk_level": "R0",
                "reasoning_summary": ["网络监听与进程列表证据已关联。"],
                "recommended_actions": [],
                "evidence_used": [{"source": "模型虚构", "summary": "不得保留"}],
                "residual_risk": "仍需确认该端口是否应对外开放。",
            },
            "stop_reason": "关键证据已闭环",
        }
    )


class FakeKnowledge:
    def search(self, query: str, limit: int = 4) -> list:
        return []


class FakeMemory:
    def __init__(self, hits: list[KnowledgeHit] | None = None) -> None:
        self.hits = hits or []
        self.calls: list[tuple[str, str | None, str | None, int]] = []

    def search_confirmed(
        self,
        query: str,
        *,
        host_scope: str | None = None,
        service_scope: str | None = None,
        limit: int = 4,
    ) -> list[KnowledgeHit]:
        self.calls.append((query, host_scope, service_scope, limit))
        return self.hits


class ScriptedModel:
    def __init__(self, handler) -> None:  # type: ignore[no-untyped-def]
        self.handler = handler
        self.calls = 0

    def decide(self, **kwargs) -> ModelDecision:  # type: ignore[no-untyped-def]
        self.calls += 1
        decision = self.handler(self.calls, kwargs)
        return ModelDecision(
            decision=decision,
            provider="bailian",
            model="fake-qwen",
            prompt_hash=str(self.calls) * 64,
            duration_ms=11,
            context_manifest={
                "manifest_version": "1.0.0",
                "manifest_sha256": str(self.calls) * 64,
            },
        )


class RepairingScriptedModel(ScriptedModel):
    def __init__(self, handler, repaired_analysis: AIAnalysisResult) -> None:  # type: ignore[no-untyped-def]
        super().__init__(handler)
        self.repaired_analysis = repaired_analysis
        self.repair_calls = 0

    def repair_analysis(self, **kwargs) -> AnalysisRepairResult:  # type: ignore[no-untyped-def]
        self.repair_calls += 1
        self.repair_kwargs = kwargs
        return AnalysisRepairResult(
            analysis=self.repaired_analysis,
            provider="bailian",
            model="fake-qwen",
            prompt_hash="r" * 64,
            duration_ms=7,
        )


class UnavailableModel:
    def decide(self, **kwargs) -> ModelDecision:  # type: ignore[no-untyped-def]
        raise ModelNotConfiguredError("missing test key")


def build_engine(
    session: Session,
    registry: ToolRegistry,
    model,
    *,
    budget: InvestigationBudget | None = None,
    cancellation_check=None,
    knowledge=None,
    memory=None,
) -> InvestigationEngine:  # type: ignore[no-untyped-def]
    return InvestigationEngine(
        session,
        registry,
        AuditService(session),
        model=model,
        knowledge=knowledge or FakeKnowledge(),
        memory=memory or FakeMemory(),
        budget=budget or InvestigationBudget(4, 12, 120000),
        cancellation_check=cancellation_check,
    )


SKILL_CONTEXT = {
    "allowed_tools": ["network_listeners", "process_list", "safe_log_rotate"],
}


class InvestigationEngineTest(unittest.TestCase):
    def test_confirmed_operational_memory_is_ingested_as_scoped_advisory_evidence(self) -> None:
        with build_session() as session:
            registry, _ = build_registry()
            task, _ = add_task_and_baseline(session)
            memory_hit = KnowledgeHit(
                chunk_id=31,
                document_id=31,
                title="8080 端口归属排查经验",
                source_uri="memory://network-8080/v1",
                trust_level="operator_confirmed",
                content="同主机历史事件中，8080 端口由 demo-api 服务监听。",
                distance=0.09,
                retrieval=RetrievalProvenance(1, 1, 0.032, 0.95),
                source_kind="memory",
            )
            memory = FakeMemory([memory_hit])
            model = ScriptedModel(
                lambda _, kwargs: conclude_decision([item.id for item in kwargs["evidence_items"]])
            )

            build_engine(session, registry, model, memory=memory).run(
                task,
                SKILL_CONTEXT,
                task.summary or "",
            )

            evidence = list(session.scalars(select(EvidenceItem).where(EvidenceItem.source_type == "KNOWLEDGE")))
            self.assertEqual([item.source_key for item in evidence], ["operational_memory:31"])
            self.assertEqual(evidence[0].payload_json["source_kind"], "memory")
            self.assertEqual(len(memory.calls), 1)

    def test_collects_follow_up_evidence_then_persists_one_grounded_conclusion(self) -> None:
        with build_session() as session:
            registry, process_calls = build_registry()
            task, _ = add_task_and_baseline(session)

            def decisions(call_number: int, kwargs: dict) -> InvestigationDecision:
                evidence_ids = [item.id for item in kwargs["evidence_items"]]
                if call_number == 1:
                    return collect_decision(evidence_ids[0])
                return conclude_decision(evidence_ids)

            model = ScriptedModel(decisions)
            outcome = build_engine(session, registry, model).run(
                task,
                SKILL_CONTEXT,
                task.summary or "",
            )
            session.commit()

            self.assertEqual(outcome.status, "CONCLUDED")
            self.assertIsNotNone(outcome.analysis)
            self.assertEqual(model.calls, 2)
            self.assertEqual(len(process_calls), 1)
            investigation = session.scalar(select(Investigation).where(Investigation.task_id == task.id))
            self.assertIsNotNone(investigation)
            assert investigation is not None
            self.assertEqual(investigation.status, "CONCLUDED")
            self.assertEqual(investigation.current_iteration, 2)
            self.assertEqual(
                len(session.scalars(select(InvestigationStep).where(InvestigationStep.investigation_id == investigation.id)).all()),
                2,
            )
            self.assertEqual(
                len(session.scalars(select(ToolCall).where(ToolCall.task_id == task.id)).all()),
                2,
            )
            hypothesis = session.scalar(select(Hypothesis).where(Hypothesis.investigation_id == investigation.id))
            self.assertIsNotNone(hypothesis)
            assert hypothesis is not None
            self.assertEqual(hypothesis.status, "SUPPORTED")
            self.assertEqual(hypothesis.confidence_level, "HIGH")
            analyses = session.scalars(select(AIAnalysis).where(AIAnalysis.task_id == task.id)).all()
            self.assertEqual(len(analyses), 1)
            self.assertEqual(analyses[0].result_json["risk_level"], "R1")
            self.assertNotEqual(analyses[0].evidence_json[0]["source"], "模型虚构")

    def test_ungrounded_final_analysis_is_repaired_once_and_revalidated(self) -> None:
        with build_session() as session:
            registry, _ = build_registry()
            task, _ = add_task_and_baseline(session)

            def decisions(call_number: int, kwargs: dict) -> InvestigationDecision:
                evidence_ids = [item.id for item in kwargs["evidence_items"]]
                if call_number == 1:
                    return collect_decision(evidence_ids[0])
                decision = conclude_decision(evidence_ids)
                assert decision.conclusion is not None
                decision.conclusion.conclusion = "未观测的 3571 端口存在异常。"
                return decision

            repaired = AIAnalysisResult.model_validate(
                {
                    "conclusion": "已确认 8080 端口由当前进程监听。",
                    "root_cause": "网络监听与进程证据已建立归属关系。",
                    "risk_level": "R1",
                    "reasoning_summary": ["两个独立系统观测共同支持当前判断。"],
                    "counter_evidence": [],
                    "recommended_actions": [],
                    "evidence_used": [],
                    "residual_risk": "仍需业务责任人确认该监听是否必要。",
                }
            )
            model = RepairingScriptedModel(decisions, repaired)

            outcome = build_engine(session, registry, model).run(
                task,
                SKILL_CONTEXT,
                task.summary or "",
            )

            self.assertEqual(outcome.status, "CONCLUDED")
            self.assertEqual(model.repair_calls, 1)
            assert outcome.analysis is not None
            self.assertNotIn("3571", outcome.analysis.result_json["conclusion"])
            self.assertEqual(outcome.analysis.prompt_hash, "r" * 64)
            event_types = {
                event.event_type
                for event in session.scalars(
                    select(TaskEvent).where(TaskEvent.task_id == task.id)
                )
            }
            self.assertIn("analysis_grounding_rejected", event_types)
            self.assertIn("analysis_grounding_repaired", event_types)

    def test_conclusion_without_independent_high_confidence_evidence_is_rejected(self) -> None:
        with build_session() as session:
            registry, _ = build_registry()
            task, _ = add_task_and_baseline(session)
            model = ScriptedModel(
                lambda _, kwargs: conclude_decision([kwargs["evidence_items"][0].id])
            )

            outcome = build_engine(session, registry, model).run(
                task,
                SKILL_CONTEXT,
                task.summary or "",
            )

            self.assertEqual(outcome.status, "INCONCLUSIVE")
            self.assertEqual(outcome.stop_reason, "INSUFFICIENT_INDEPENDENT_EVIDENCE")
            self.assertEqual(session.scalars(select(AIAnalysis)).all(), [])
            step = session.scalar(select(InvestigationStep))
            self.assertIsNotNone(step)
            assert step is not None
            self.assertEqual(step.status, "REJECTED")
            hypothesis = session.scalar(select(Hypothesis))
            self.assertIsNotNone(hypothesis)
            assert hypothesis is not None
            self.assertIn("独立证据源", hypothesis.evidence_gap)

    def test_duplicate_normalized_request_stops_without_second_tool_execution(self) -> None:
        with build_session() as session:
            registry, process_calls = build_registry()
            task, _ = add_task_and_baseline(
                session,
                tool_name="process_list",
                input_json={"limit": 5},
            )
            model = ScriptedModel(
                lambda _, kwargs: collect_decision(kwargs["evidence_items"][0].id, "process_list")
            )

            outcome = build_engine(session, registry, model).run(task, SKILL_CONTEXT, task.summary or "")

            self.assertEqual(outcome.status, "INCONCLUSIVE")
            self.assertEqual(outcome.stop_reason, "DUPLICATE_TOOL_CALL")
            self.assertEqual(process_calls, [])
            step = session.scalar(select(InvestigationStep))
            self.assertIsNotNone(step)
            assert step is not None
            self.assertEqual(step.status, "REJECTED")
            self.assertIn("duplicate", step.rejection_reason or "")

    def test_side_effect_request_is_rejected_without_execution(self) -> None:
        with build_session() as session:
            registry, _ = build_registry()
            task, _ = add_task_and_baseline(session)
            model = ScriptedModel(
                lambda _, kwargs: collect_decision(kwargs["evidence_items"][0].id, "safe_log_rotate")
            )

            outcome = build_engine(session, registry, model).run(task, SKILL_CONTEXT, task.summary or "")

            self.assertEqual(outcome.stop_reason, "SIDE_EFFECT_TOOL")
            self.assertEqual(
                len(session.scalars(select(ToolCall).where(ToolCall.task_id == task.id)).all()),
                1,
            )

    def test_out_of_skill_read_only_proposal_is_audited_then_final_round_concludes(
        self,
    ) -> None:
        with build_session() as session:
            registry, process_calls = build_registry()
            task, _ = add_task_and_baseline(session)
            session.add(
                ToolCall(
                    task_id=task.id,
                    tool_name="process_list",
                    tool_version="1.0.0",
                    input_json={"limit": 5},
                    output_json={
                        "status": "ok",
                        "observations": [
                            {"pid": 73, "comm": "demo-api", "state": "S"}
                        ],
                        "evidence_refs": ["proc:73"],
                        "warnings": [],
                        "summary_fields": {},
                        "risk_hints": [],
                    },
                    risk_level="R0",
                    status="ok",
                    duration_ms=7,
                    ended_at=datetime.now(timezone.utc),
                )
            )
            session.flush()

            def decisions(call_number: int, kwargs: dict) -> InvestigationDecision:
                evidence_ids = [item.id for item in kwargs["evidence_items"]]
                if call_number == 1:
                    self.assertFalse(kwargs["final_iteration"])
                    return collect_decision(evidence_ids[0], "file_read")
                self.assertTrue(kwargs["final_iteration"])
                self.assertEqual(
                    kwargs["controller_policy_feedback"][0]["reason_code"],
                    "TOOL_OUTSIDE_SKILL",
                )
                self.assertEqual(
                    kwargs["controller_policy_feedback"][0]["tool_name"],
                    "file_read",
                )
                return conclude_decision(evidence_ids)

            model = ScriptedModel(decisions)
            outcome = build_engine(
                session,
                registry,
                model,
                budget=InvestigationBudget(
                    max_iterations=2,
                    max_tool_calls=12,
                    max_elapsed_ms=120000,
                ),
            ).run(task, SKILL_CONTEXT, task.summary or "")

            self.assertEqual(outcome.status, "CONCLUDED")
            self.assertEqual(model.calls, 2)
            self.assertEqual(process_calls, [])
            steps = list(
                session.scalars(
                    select(InvestigationStep).order_by(InvestigationStep.iteration)
                )
            )
            self.assertEqual([item.status for item in steps], ["REJECTED", "COMPLETED"])
            self.assertEqual(
                steps[0].decision_json["controller_rejection"]["reason_code"],
                "TOOL_OUTSIDE_SKILL",
            )
            event_types = {
                event.event_type
                for event in session.scalars(
                    select(TaskEvent).where(TaskEvent.task_id == task.id)
                )
            }
            self.assertIn("investigation_proposal_rejected", event_types)

    def test_unknown_evidence_reference_fails_closed(self) -> None:
        with build_session() as session:
            registry, _ = build_registry()
            task, _ = add_task_and_baseline(session)
            model = ScriptedModel(lambda *_: collect_decision(999))

            outcome = build_engine(session, registry, model).run(task, SKILL_CONTEXT, task.summary or "")

            self.assertEqual(outcome.status, "INCONCLUSIVE")
            self.assertEqual(outcome.stop_reason, "EVIDENCE_BINDING_REJECTED")
            self.assertEqual(session.scalars(select(Hypothesis)).all(), [])
            self.assertEqual(session.scalars(select(AIAnalysis)).all(), [])

    def test_model_unavailable_after_evidence_marks_task_for_operator(self) -> None:
        with build_session() as session:
            registry, _ = build_registry()
            task, _ = add_task_and_baseline(session)

            outcome = build_engine(session, registry, UnavailableModel()).run(
                task,
                SKILL_CONTEXT,
                task.summary or "",
            )

            self.assertEqual(outcome.status, "NEEDS_OPERATOR")
            self.assertEqual(task.status, "NEEDS_OPERATOR")
            self.assertEqual(session.scalars(select(AIAnalysis)).all(), [])
            investigation = session.scalar(select(Investigation))
            self.assertIsNotNone(investigation)
            assert investigation is not None
            self.assertEqual(investigation.status, "NEEDS_OPERATOR")

    def test_last_iteration_cannot_collect_another_tool(self) -> None:
        with build_session() as session:
            registry, process_calls = build_registry()
            task, _ = add_task_and_baseline(session)
            model = ScriptedModel(
                lambda _, kwargs: collect_decision(kwargs["evidence_items"][0].id, "process_list")
            )
            budget = InvestigationBudget(max_iterations=1, max_tool_calls=12, max_elapsed_ms=120000)

            outcome = build_engine(session, registry, model, budget=budget).run(
                task,
                SKILL_CONTEXT,
                task.summary or "",
            )

            self.assertEqual(outcome.status, "INCONCLUSIVE")
            self.assertEqual(outcome.stop_reason, "FINAL_ITERATION_REQUIRES_CONCLUSION")
            self.assertEqual(process_calls, [])

    def test_cancellation_marks_investigation_before_propagating(self) -> None:
        with build_session() as session:
            registry, _ = build_registry()
            task, _ = add_task_and_baseline(session)

            def cancel() -> None:
                raise RuntimeError("cancelled at safe boundary")

            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                build_engine(
                    session,
                    registry,
                    ScriptedModel(lambda *_: collect_decision(1)),
                    cancellation_check=cancel,
                ).run(task, SKILL_CONTEXT, task.summary or "")

            investigation = session.scalar(select(Investigation))
            self.assertIsNotNone(investigation)
            assert investigation is not None
            self.assertEqual(investigation.status, "CANCELLED")

    def test_unhandled_pipeline_error_closes_active_investigation(self) -> None:
        with build_session() as session:
            registry, _ = build_registry()
            task, _ = add_task_and_baseline(session)
            investigation = Investigation(
                task_id=task.id,
                status="RUNNING",
                current_iteration=2,
                max_iterations=4,
                max_tool_calls=12,
                max_elapsed_ms=120000,
            )
            session.add(investigation)
            session.flush()
            hypothesis = Hypothesis(
                investigation_id=investigation.id,
                key="dependency_unreachable",
                title="依赖不可达",
                rationale="等待证据",
                evidence_gap="需要补充依赖侧观测",
                status="OPEN",
                confidence_level="LOW",
                confidence_score=0,
                first_seen_iteration=1,
                last_updated_iteration=2,
            )
            session.add(hypothesis)
            session.flush()
            engine = build_engine(session, registry, ScriptedModel(lambda *_: None))

            changed = engine.fail_active_investigation(
                task,
                reason_code="INVESTIGATION_PIPELINE_FAILED",
                detail="final grounding rejected",
            )

            self.assertTrue(changed)
            self.assertEqual(investigation.status, "FAILED")
            self.assertEqual(investigation.stop_reason, "INVESTIGATION_PIPELINE_FAILED")
            self.assertIsNotNone(investigation.completed_at)
            self.assertEqual(hypothesis.status, "INCONCLUSIVE")
            event = session.scalar(
                select(TaskEvent).where(
                    TaskEvent.task_id == task.id,
                    TaskEvent.event_type == "investigation_failed",
                )
            )
            self.assertIsNotNone(event)

    def test_second_investigation_for_same_task_is_refused(self) -> None:
        with build_session() as session:
            registry, _ = build_registry()
            task, _ = add_task_and_baseline(session)
            model = ScriptedModel(lambda _, kwargs: conclude_decision([kwargs["evidence_items"][0].id]))
            engine = build_engine(session, registry, model)
            engine.run(task, SKILL_CONTEXT, task.summary or "")

            with self.assertRaisesRegex(RuntimeError, "already has an investigation"):
                engine.run(task, SKILL_CONTEXT, task.summary or "")


if __name__ == "__main__":
    unittest.main()
