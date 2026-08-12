from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.ai.analysis import AIAnalysisResult, ground_final_analysis
from backend.app.ai.client import ModelCallError, ModelNotConfiguredError
from backend.app.audit.service import AuditService
from backend.app.investigation.evidence import (
    EvidenceBindingError,
    apply_hypothesis_updates,
    bound_investigation_decision_claims,
    ingest_knowledge_hits,
    ingest_tool_call,
    mark_open_hypotheses_inconclusive,
)
from backend.app.investigation.model import InvestigationDecisionError, InvestigationModel
from backend.app.investigation.obligations import (
    EvidenceObligation,
    next_evidence_obligation,
)
from backend.app.investigation.policy import (
    InvestigationBudget,
    InvestigationPolicy,
    InvestigationPolicyError,
    tool_call_signature,
)
from backend.app.investigation.schemas import InvestigationToolRequest
from backend.app.investigation.tool_executor import MCPObservationExecutor
from backend.app.knowledge.retrieval import KnowledgeRetrievalUnavailableError
from backend.app.knowledge.service import KnowledgeService
from backend.app.memory.service import OperationalMemoryService
from backend.app.mcp.registry import ToolNotFoundError, ToolRegistry
from backend.app.models.entities import (
    AIAnalysis,
    EvidenceItem,
    Hypothesis,
    Investigation,
    InvestigationStep,
    SafetyReview,
    Task,
    ToolCall,
    SystemSnapshot,
    utcnow,
)
from backend.app.schemas.enums import RiskLevel, TaskStatus, max_risk
from backend.app.safety.content import untrusted_content_policy_identity


@dataclass(frozen=True)
class InvestigationOutcome:
    status: str
    stop_reason: str
    investigation: Investigation
    analysis: AIAnalysis | None


_RECOVERABLE_MODEL_POLICY_REJECTIONS = {
    "ARGUMENT_OUTSIDE_EVIDENCE",
    "TOOL_OUTSIDE_SKILL",
}


class InvestigationEngine:
    def __init__(
        self,
        session: Session,
        registry: ToolRegistry,
        audit: AuditService,
        *,
        model: Any | None = None,
        knowledge: Any | None = None,
        memory: Any | None = None,
        budget: InvestigationBudget | None = None,
        cancellation_check: Callable[[], None] | None = None,
    ) -> None:
        self.session = session
        self.registry = registry
        self.audit = audit
        self.model = model or InvestigationModel()
        model_client = getattr(self.model, "model_client", None)
        self.knowledge = knowledge or KnowledgeService(session, model_client)
        self.memory = memory or OperationalMemoryService(
            session,
            model_client=model_client,
            audit=audit,
        )
        self.budget = budget or InvestigationBudget.from_settings()
        self.cancellation_check = cancellation_check or (lambda: None)
        self.policy = InvestigationPolicy(registry)
        self.observation_executor = MCPObservationExecutor(session, registry, audit)

    def run(
        self,
        task: Task,
        skill_context: dict[str, Any],
        canonical_summary: str,
    ) -> InvestigationOutcome:
        existing = self.session.scalar(
            select(Investigation).where(Investigation.task_id == task.id)
        )
        if existing is not None:
            raise RuntimeError(f"task {task.id} already has an investigation")

        investigation = Investigation(
            task_id=task.id,
            status="RUNNING",
            max_iterations=self.budget.max_iterations,
            max_tool_calls=self.budget.max_tool_calls,
            max_elapsed_ms=self.budget.max_elapsed_ms,
        )
        self.session.add(investigation)
        self.session.flush()
        started = time.monotonic()
        self.audit.append_event(
            task,
            "INVESTIGATE",
            "investigation_started",
            "已建立受预算约束的根因调查。",
            {
                "investigation_id": investigation.id,
                "max_iterations": investigation.max_iterations,
                "max_tool_calls": investigation.max_tool_calls,
                "max_elapsed_ms": investigation.max_elapsed_ms,
            },
        )
        self._check_cancelled(task, investigation)

        tool_calls = self._task_tool_calls(task.id)
        for call in tool_calls:
            ingest_tool_call(self.session, investigation, call)
        self._ingest_knowledge(task, investigation, canonical_summary)
        evidence_items = self._evidence_items(investigation.id)
        self._record_quarantined_evidence(task, investigation, evidence_items)
        trusted_evidence = [
            item for item in evidence_items if item.trust_level != "QUARANTINED"
        ]
        if not any(item.source_type == "MCP" for item in trusted_evidence):
            return self._stop_inconclusive(
                task,
                investigation,
                "NO_MCP_EVIDENCE",
                "调查没有可送入模型的 MCP 系统证据，未生成根因结论。",
            )

        allowed_tool_names = set(skill_context.get("allowed_tools", []))
        allowed_tools, unavailable_tools = self._registered_tools(allowed_tool_names)
        available_tool_names = {tool.name for tool in allowed_tools}
        if unavailable_tools:
            self.audit.append_event(
                task,
                "INVESTIGATE",
                "host_capability_gaps",
                "已按当前主机能力画像从调查工具集中排除不可用工具。",
                {
                    "investigation_id": investigation.id,
                    "unavailable_tools": unavailable_tools,
                },
            )
        signatures = self._existing_signatures(tool_calls)
        controller_policy_feedback: list[dict[str, Any]] = []

        for iteration in range(1, self.budget.max_iterations + 1):
            self._check_cancelled(task, investigation)
            elapsed_ms = _elapsed_ms(started)
            if elapsed_ms >= self.budget.max_elapsed_ms:
                return self._stop_inconclusive(
                    task,
                    investigation,
                    "ELAPSED_BUDGET_EXHAUSTED",
                    "调查已达到墙钟时间预算，未继续调用模型或工具。",
                )

            evidence_items = self._evidence_items(investigation.id)
            hypotheses = self._hypotheses(investigation.id)
            tool_history = self._task_tool_calls(task.id)
            allowed_argument_values = self.policy.allowed_argument_values(
                evidence_items=evidence_items,
                user_input=task.user_input,
            )
            obligation = next_evidence_obligation(
                task,
                allowed_tool_names=available_tool_names,
                allowed_argument_values=allowed_argument_values,
                tool_history=tool_history,
                evidence_items=evidence_items,
            )
            if obligation is not None:
                outcome = self._collect_evidence_obligation(
                    task,
                    investigation,
                    obligation,
                    iteration=iteration,
                    started=started,
                    allowed_tool_names=available_tool_names,
                    evidence_items=evidence_items,
                    signatures=signatures,
                )
                if outcome is not None:
                    return outcome
                continue

            iteration_started_at = utcnow()
            try:
                model_result = self.model.decide(
                    task=task,
                    iteration=iteration,
                    evidence_items=evidence_items,
                    hypotheses=hypotheses,
                    tool_history=tool_history,
                    allowed_tools=allowed_tools,
                    canonical_summary=canonical_summary,
                    remaining_tool_calls=max(
                        0,
                        self.budget.max_tool_calls - self._tool_call_count(task.id),
                    ),
                    final_iteration=iteration == self.budget.max_iterations,
                    allowed_argument_values=allowed_argument_values,
                    controller_policy_feedback=controller_policy_feedback,
                )
            except (ModelNotConfiguredError, ModelCallError) as exc:
                self._record_error_step(
                    investigation,
                    iteration,
                    iteration_started_at,
                    str(exc),
                )
                return self._needs_operator(task, investigation, "MODEL_UNAVAILABLE", canonical_summary)
            except InvestigationDecisionError as exc:
                self._record_error_step(
                    investigation,
                    iteration,
                    iteration_started_at,
                    str(exc),
                )
                return self._stop_inconclusive(
                    task,
                    investigation,
                    "MODEL_DECISION_REJECTED",
                    "模型返回的调查决策未通过结构校验，系统未执行后续工具。",
                )

            decision = bound_investigation_decision_claims(
                model_result.decision,
                evidence_items,
            )
            step = InvestigationStep(
                investigation_id=investigation.id,
                iteration=iteration,
                decision=decision.decision,
                status="DECIDED",
                provider=model_result.provider,
                model=model_result.model,
                prompt_hash=model_result.prompt_hash,
                decision_json=decision.model_dump(mode="json"),
                requested_tool_name=decision.next_tool.tool_name if decision.next_tool else None,
                requested_arguments_json=decision.next_tool.arguments if decision.next_tool else {},
                duration_ms=model_result.duration_ms,
                started_at=iteration_started_at,
            )
            self.session.add(step)
            self.session.flush()
            investigation.current_iteration = iteration
            self.audit.append_event(
                task,
                "INVESTIGATE",
                "investigation_decision",
                f"第 {iteration} 轮调查决策已通过结构校验。",
                {
                    "investigation_id": investigation.id,
                    "step_id": step.id,
                    "iteration": iteration,
                    "decision": decision.decision,
                    "hypothesis_keys": [item.key for item in decision.hypotheses],
                    "requested_tool_name": step.requested_tool_name,
                    "prompt_hash": step.prompt_hash,
                    "model": step.model,
                    "duration_ms": step.duration_ms,
                    "context_manifest": model_result.context_manifest,
                },
            )

            if _elapsed_ms(started) >= self.budget.max_elapsed_ms:
                return self._reject_step_and_stop(
                    task,
                    investigation,
                    step,
                    "ELAPSED_BUDGET_EXHAUSTED",
                    "模型返回后已达到调查墙钟时间预算。",
                )

            try:
                apply_hypothesis_updates(
                    self.session,
                    investigation,
                    decision,
                    iteration=iteration,
                )
            except EvidenceBindingError as exc:
                return self._reject_step_and_stop(
                    task,
                    investigation,
                    step,
                    "EVIDENCE_BINDING_REJECTED",
                    str(exc),
                )

            if decision.decision == "CONCLUDE":
                confirmed_hypotheses = [
                    hypothesis
                    for hypothesis in self._hypotheses(investigation.id)
                    if hypothesis.status == "SUPPORTED"
                    and hypothesis.confidence_level == "HIGH"
                ]
                if not confirmed_hypotheses:
                    self._mark_independent_evidence_gap(investigation.id)
                    return self._reject_step_and_stop(
                        task,
                        investigation,
                        step,
                        "INSUFFICIENT_INDEPENDENT_EVIDENCE",
                        "模型请求形成根因结论，但当前没有得到两个独立证据源支持的高置信候选根因。",
                    )
                return self._conclude(
                    task,
                    investigation,
                    step,
                    model_result,
                    decision.conclusion,
                    max(confirmed_hypotheses, key=lambda item: item.confidence_score),
                    stop_reason=decision.stop_reason,
                )

            if iteration == self.budget.max_iterations:
                return self._reject_step_and_stop(
                    task,
                    investigation,
                    step,
                    "FINAL_ITERATION_REQUIRES_CONCLUSION",
                    "最后一轮仍请求补充工具，控制器拒绝超出轮次预算。",
                )

            assert decision.next_tool is not None
            try:
                validated = self.policy.validate_tool_request(
                    decision.next_tool,
                    allowed_tools=available_tool_names,
                    existing_signatures=signatures,
                    total_tool_calls=self._tool_call_count(task.id),
                    elapsed_ms=_elapsed_ms(started),
                    iteration=iteration,
                    budget=self.budget,
                    evidence_items=evidence_items,
                    user_input=task.user_input,
                )
            except InvestigationPolicyError as exc:
                if (
                    exc.code in _RECOVERABLE_MODEL_POLICY_REJECTIONS
                    and iteration < self.budget.max_iterations
                    and _elapsed_ms(started) < self.budget.max_elapsed_ms
                ):
                    controller_policy_feedback.append(
                        self._reject_step_for_retry(
                            task,
                            investigation,
                            step,
                            exc.code,
                            str(exc),
                        )
                    )
                    continue
                return self._reject_step_and_stop(
                    task,
                    investigation,
                    step,
                    exc.code,
                    str(exc),
                )

            self._check_cancelled(task, investigation)
            call = self.observation_executor.execute(
                task,
                validated.tool_name,
                validated.arguments,
                reason=validated.reason,
                source="investigation",
                iteration=iteration,
            )
            ingest_tool_call(self.session, investigation, call)
            self._record_quarantined_evidence(
                task,
                investigation,
                self._evidence_items(investigation.id),
            )
            signatures.add(validated.signature)
            step.tool_call_id = call.id
            step.status = "COMPLETED"
            step.completed_at = utcnow()
            self.session.flush()
            self.audit.append_event(
                task,
                "INVESTIGATE",
                "investigation_evidence_collected",
                f"第 {iteration} 轮补充证据已持久化。",
                {
                    "investigation_id": investigation.id,
                    "step_id": step.id,
                    "tool_call_id": call.id,
                    "tool_name": call.tool_name,
                    "tool_status": call.status,
                    "signature": validated.signature,
                },
            )
            self._check_cancelled(task, investigation)

        return self._stop_inconclusive(
            task,
            investigation,
            "ITERATION_BUDGET_EXHAUSTED",
            "调查已达到最大轮次。",
        )

    def _reject_step_for_retry(
        self,
        task: Task,
        investigation: Investigation,
        step: InvestigationStep,
        reason_code: str,
        detail: str,
    ) -> dict[str, Any]:
        feedback = {
            "iteration": step.iteration,
            "tool_name": step.requested_tool_name,
            "arguments": step.requested_arguments_json,
            "reason_code": reason_code,
            "reason": detail[:500],
        }
        decision_json = (
            dict(step.decision_json)
            if isinstance(step.decision_json, dict)
            else {}
        )
        step.decision_json = {
            **decision_json,
            "controller_rejection": feedback,
        }
        step.status = "REJECTED"
        step.rejection_reason = detail[:1000]
        step.completed_at = utcnow()
        self.session.flush()
        self.audit.append_event(
            task,
            "INVESTIGATE",
            "investigation_proposal_rejected",
            "模型工具提议已被控制器拒绝，调查将在剩余预算内继续收敛。",
            {
                "investigation_id": investigation.id,
                "step_id": step.id,
                **feedback,
            },
        )
        return feedback

    def fail_active_investigation(
        self,
        task: Task,
        *,
        reason_code: str,
        detail: str,
    ) -> bool:
        investigation = self.session.scalar(
            select(Investigation).where(
                Investigation.task_id == task.id,
                Investigation.status == "RUNNING",
            )
        )
        if investigation is None:
            return False
        mark_open_hypotheses_inconclusive(self.session, investigation)
        investigation.status = "FAILED"
        investigation.stop_reason = reason_code
        investigation.completed_at = utcnow()
        self.session.flush()
        self.audit.append_event(
            task,
            "INVESTIGATE",
            "investigation_failed",
            "调查因内部校验失败而停止，未保留运行中状态。",
            {
                "investigation_id": investigation.id,
                "stop_reason": reason_code,
                "detail": detail[:500],
                "iteration": investigation.current_iteration,
            },
        )
        return True

    def _collect_evidence_obligation(
        self,
        task: Task,
        investigation: Investigation,
        obligation: EvidenceObligation,
        *,
        iteration: int,
        started: float,
        allowed_tool_names: set[str],
        evidence_items: list[EvidenceItem],
        signatures: set[str],
    ) -> InvestigationOutcome | None:
        requested_at = utcnow()
        request = {
            "tool_name": obligation.tool_name,
            "arguments": obligation.arguments,
            "reason": obligation.reason,
        }
        try:
            validated = self.policy.validate_tool_request(
                InvestigationToolRequest.model_validate(request),
                allowed_tools=allowed_tool_names,
                existing_signatures=signatures,
                total_tool_calls=self._tool_call_count(task.id),
                elapsed_ms=_elapsed_ms(started),
                iteration=iteration,
                budget=self.budget,
                evidence_items=evidence_items,
                user_input=task.user_input,
            )
        except InvestigationPolicyError as exc:
            self._record_error_step(
                investigation,
                iteration,
                requested_at,
                str(exc),
            )
            return self._stop_inconclusive(task, investigation, exc.code, str(exc))

        step = InvestigationStep(
            investigation_id=investigation.id,
            iteration=iteration,
            decision="COLLECT",
            status="DECIDED",
            provider="opscouncil-controller",
            model="evidence-obligation.v1",
            decision_json={
                "decision": "COLLECT",
                "controller": "evidence-obligation.v1",
                "obligation": obligation.to_dict(),
            },
            requested_tool_name=validated.tool_name,
            requested_arguments_json=validated.arguments,
            duration_ms=0,
            started_at=requested_at,
        )
        self.session.add(step)
        self.session.flush()
        investigation.current_iteration = iteration
        self.audit.append_event(
            task,
            "INVESTIGATE",
            "evidence_obligation_enforced",
            f"结论前强制补齐证据：{obligation.title}。",
            {
                "investigation_id": investigation.id,
                "step_id": step.id,
                "iteration": iteration,
                "obligation": obligation.to_dict(),
                "signature": validated.signature,
            },
        )
        self._check_cancelled(task, investigation)
        call = self.observation_executor.execute(
            task,
            validated.tool_name,
            validated.arguments,
            reason=validated.reason,
            source="evidence_obligation",
            iteration=iteration,
        )
        ingest_tool_call(self.session, investigation, call)
        self._record_quarantined_evidence(
            task,
            investigation,
            self._evidence_items(investigation.id),
        )
        signatures.add(validated.signature)
        step.tool_call_id = call.id
        step.status = "COMPLETED"
        step.duration_ms = max(call.duration_ms, 0)
        step.completed_at = utcnow()
        self.session.flush()
        self.audit.append_event(
            task,
            "INVESTIGATE",
            "investigation_evidence_collected",
            f"第 {iteration} 轮证据义务已完成。",
            {
                "investigation_id": investigation.id,
                "step_id": step.id,
                "tool_call_id": call.id,
                "tool_name": call.tool_name,
                "tool_status": call.status,
                "signature": validated.signature,
                "obligation_key": obligation.key,
            },
        )
        self._check_cancelled(task, investigation)
        return None

    def _record_quarantined_evidence(
        self,
        task: Task,
        investigation: Investigation,
        evidence_items: list[EvidenceItem],
    ) -> None:
        quarantined = [
            item for item in evidence_items if item.trust_level == "QUARANTINED"
        ]
        if not quarantined:
            return
        existing = self.session.scalar(
            select(SafetyReview).where(
                SafetyReview.task_id == task.id,
                SafetyReview.review_type == "untrusted_evidence",
            )
        )
        if existing is not None:
            return

        matched_rules: list[dict[str, Any]] = []
        for item in quarantined:
            payload = item.payload_json if isinstance(item.payload_json, dict) else {}
            safety = payload.get("content_safety")
            threats = safety.get("threats", []) if isinstance(safety, dict) else []
            for threat in threats:
                if not isinstance(threat, dict):
                    continue
                matched_rules.append(
                    {
                        "rule_id": str(threat.get("rule_id") or "untrusted_evidence"),
                        "label": str(threat.get("label") or "非可信证据指令"),
                        "risk_level": RiskLevel.R4.value,
                        "detail": item.source_ref,
                    }
                )
        if not matched_rules:
            matched_rules.append(
                {
                    "rule_id": "untrusted_evidence",
                    "label": "非可信证据指令",
                    "risk_level": RiskLevel.R4.value,
                    "detail": quarantined[0].source_ref,
                }
            )

        task.risk_level = max_risk(RiskLevel(task.risk_level), RiskLevel.R4).value
        content_policy = untrusted_content_policy_identity()
        content_hashes = sorted(
            {
                str(safety["content_sha256"])
                for item in quarantined
                if isinstance(item.payload_json, dict)
                for safety in [item.payload_json.get("content_safety")]
                if isinstance(safety, dict) and safety.get("content_sha256")
            }
        )
        review = SafetyReview(
            task_id=task.id,
            review_type="untrusted_evidence",
            risk_level=RiskLevel.R4.value,
            decision="REJECT",
            matched_rules_json=matched_rules,
            reason="工具或知识证据中发现疑似提示词注入，命中内容已隔离并禁止进入模型上下文。",
            policy_version=content_policy["version"],
            policy_digest=content_policy["digest"],
            subject_json={
                "kind": "untrusted_evidence_set",
                "evidence_ids": [item.id for item in quarantined],
                "source_refs": sorted(item.source_ref for item in quarantined),
                "content_sha256": content_hashes,
            },
        )
        self.session.add(review)
        self.session.flush()
        self.audit.append_event(
            task,
            "DYNAMIC_REVIEW",
            "evidence_quarantined",
            "非可信证据内容已隔离，调查仅使用剩余可信观测。",
            {
                "investigation_id": investigation.id,
                "safety_review_id": review.id,
                "evidence_ids": [item.id for item in quarantined],
                "source_refs": [item.source_ref for item in quarantined],
                "matched_rule_ids": list(
                    dict.fromkeys(item["rule_id"] for item in matched_rules)
                ),
                "model_context_exposure": False,
            },
        )

    def _conclude(
        self,
        task: Task,
        investigation: Investigation,
        step: InvestigationStep,
        model_result: Any,
        conclusion: Any,
        confirmed_hypothesis: Hypothesis,
        *,
        stop_reason: str,
    ) -> InvestigationOutcome:
        if conclusion is None:
            return self._reject_step_and_stop(
                task,
                investigation,
                step,
                "MODEL_DECISION_REJECTED",
                "CONCLUDE 决策缺少结构化结论。",
            )
        evidence_items = [
            item
            for item in self._evidence_items(investigation.id)
            if item.trust_level != "QUARANTINED"
        ]
        observed_tool_names = {call.tool_name for call in self._task_tool_calls(task.id)}
        relation_priority = {"SUPPORTS": 0, "CONTEXT": 1, "REFUTES": 2}
        preferred_evidence_ids = [
            link.evidence_item_id
            for link in sorted(
                confirmed_hypothesis.evidence_links,
                key=lambda item: (
                    relation_priority.get(item.relation, 3),
                    item.evidence_item_id,
                ),
            )
        ]
        try:
            grounded, analysis_model_result = self._ground_final_analysis_with_repair(
                task=task,
                investigation=investigation,
                model_result=model_result,
                conclusion=conclusion,
                confirmed_hypothesis=confirmed_hypothesis,
                evidence_items=evidence_items,
                observed_tool_names=observed_tool_names,
                preferred_evidence_ids=preferred_evidence_ids,
            )
        except (InvestigationDecisionError, ModelCallError, ModelNotConfiguredError):
            return self._reject_step_and_stop(
                task,
                investigation,
                step,
                "MODEL_ANALYSIS_REJECTED",
                "模型最终研判未通过事实校验，系统未写入不合规结论。",
            )
        analysis = AIAnalysis(
            task_id=task.id,
            provider=analysis_model_result.provider,
            model=analysis_model_result.model,
            status="ok",
            prompt_hash=analysis_model_result.prompt_hash,
            result_json=grounded.model_dump(mode="json"),
            evidence_json=grounded.evidence_used,
        )
        self.session.add(analysis)
        step.status = "COMPLETED"
        step.completed_at = utcnow()
        investigation.status = "CONCLUDED"
        investigation.stop_reason = stop_reason
        investigation.completed_at = utcnow()
        self.session.flush()
        self.audit.append_event(
            task,
            "AI_ANALYSIS",
            "ai_analysis_created",
            "调查闭环生成了基于持久证据的模型辅助研判。",
            {
                "investigation_id": investigation.id,
                "analysis_id": analysis.id,
                "provider": analysis.provider,
                "model": analysis.model,
                "prompt_hash": analysis.prompt_hash,
                "risk_level": grounded.risk_level,
                "evidence_ids": [int(item["evidence_id"]) for item in grounded.evidence_used],
            },
        )
        self.audit.append_event(
            task,
            "INVESTIGATE",
            "investigation_concluded",
            "证据驱动调查已形成结论。",
            {
                "investigation_id": investigation.id,
                "iteration": investigation.current_iteration,
                "stop_reason": investigation.stop_reason,
                "analysis_id": analysis.id,
            },
        )
        return InvestigationOutcome(
            status=investigation.status,
            stop_reason=investigation.stop_reason or "CONCLUDED",
            investigation=investigation,
            analysis=analysis,
        )

    def _ground_final_analysis_with_repair(
        self,
        *,
        task: Task,
        investigation: Investigation,
        model_result: Any,
        conclusion: AIAnalysisResult,
        confirmed_hypothesis: Hypothesis,
        evidence_items: list[EvidenceItem],
        observed_tool_names: set[str],
        preferred_evidence_ids: list[int],
    ) -> tuple[AIAnalysisResult, Any]:
        grounding_arguments = {
            "task_risk_level": task.risk_level,
            "evidence_items": evidence_items,
            "observed_tool_names": observed_tool_names,
            "preferred_evidence_ids": preferred_evidence_ids,
            "task_intent": task.intent,
        }
        try:
            return ground_final_analysis(conclusion, **grounding_arguments), model_result
        except ValueError as exc:
            self.audit.append_event(
                task,
                "AI_ANALYSIS",
                "analysis_grounding_rejected",
                "模型研判触发确定性事实边界，已进入一次受限修正。",
                {
                    "investigation_id": investigation.id,
                    "validation_code": _analysis_validation_code(exc),
                    "detail": str(exc)[:500],
                    "original_prompt_hash": model_result.prompt_hash,
                },
            )
            repair = getattr(self.model, "repair_analysis", None)
            if not callable(repair):
                raise InvestigationDecisionError(
                    "analysis repair is unavailable after grounding rejection"
                ) from exc
            repaired = repair(
                task=task,
                invalid_analysis=conclusion,
                validation_error=str(exc),
                evidence_items=evidence_items,
                confirmed_hypothesis=confirmed_hypothesis,
            )
            try:
                grounded = ground_final_analysis(repaired.analysis, **grounding_arguments)
            except ValueError as repair_exc:
                self.audit.append_event(
                    task,
                    "AI_ANALYSIS",
                    "analysis_repair_rejected",
                    "受限修正仍未通过确定性事实边界，未写入模型结论。",
                    {
                        "investigation_id": investigation.id,
                        "validation_code": _analysis_validation_code(repair_exc),
                        "detail": str(repair_exc)[:500],
                        "repair_prompt_hash": repaired.prompt_hash,
                    },
                )
                raise InvestigationDecisionError(
                    f"repaired analysis failed grounding: {repair_exc}"
                ) from repair_exc
            self.audit.append_event(
                task,
                "AI_ANALYSIS",
                "analysis_grounding_repaired",
                "模型研判已依据同一持久化证据完成受限修正并通过复核。",
                {
                    "investigation_id": investigation.id,
                    "repair_prompt_hash": repaired.prompt_hash,
                    "provider": repaired.provider,
                    "model": repaired.model,
                },
            )
            return grounded, repaired

    def _ingest_knowledge(
        self,
        task: Task,
        investigation: Investigation,
        canonical_summary: str,
    ) -> None:
        query = f"{task.user_input}\n{task.intent}\n{canonical_summary}"
        try:
            hits = self.knowledge.search(query, limit=4)
        except KnowledgeRetrievalUnavailableError as exc:
            self.audit.append_event(
                task,
                "INVESTIGATE",
                "knowledge_rag_unavailable",
                "知识检索不可用，本次调查明确标记为未使用知识证据。",
                {"stage": exc.stage, "reason": str(exc)[:500]},
            )
            return
        host_scope, service_scope = self._task_memory_scope(task.id)
        memory_hits = []
        try:
            memory_hits = self.memory.search_confirmed(
                query,
                host_scope=host_scope,
                service_scope=service_scope,
                limit=2,
            )
        except KnowledgeRetrievalUnavailableError as exc:
            self.audit.append_event(
                task,
                "INVESTIGATE",
                "operational_memory_unavailable",
                "运维经验检索不可用，本次调查未使用历史经验。",
                {"stage": exc.stage, "reason": str(exc)[:500]},
            )
        ingest_knowledge_hits(self.session, investigation, [*hits, *memory_hits])
        self.audit.append_event(
            task,
            "INVESTIGATE",
            "knowledge_evidence_retrieved",
            f"调查检索到 {len(hits)} 条静态知识和 {len(memory_hits)} 条确认经验。",
            {
                "investigation_id": investigation.id,
                "document_hit_count": len(hits),
                "memory_hit_count": len(memory_hits),
                "host_scope": host_scope,
                "service_scope": service_scope,
                "evidence_ids": [
                    item.id
                    for item in self._evidence_items(investigation.id)
                    if item.source_type == "KNOWLEDGE"
                ],
            },
        )

    def _task_memory_scope(self, task_id: int) -> tuple[str | None, str | None]:
        snapshot = self.session.scalar(
            select(SystemSnapshot)
            .where(SystemSnapshot.task_id == task_id)
            .order_by(SystemSnapshot.id.desc())
            .limit(1)
        )
        host_scope: str | None = None
        if snapshot is not None:
            observations = (snapshot.payload_json or {}).get("observations")
            if isinstance(observations, list) and observations and isinstance(observations[0], dict):
                hostname = observations[0].get("hostname")
                host_scope = str(hostname).strip() if hostname else None

        service_scope: str | None = None
        for call in reversed(self._task_tool_calls(task_id)):
            observations = (call.output_json or {}).get("observations")
            if not isinstance(observations, list):
                continue
            for observation in observations:
                if not isinstance(observation, dict):
                    continue
                value = observation.get("unit") or observation.get("service") or observation.get("service_name")
                if value:
                    service_scope = str(value).strip()
                    break
            if service_scope:
                break
        return host_scope, service_scope

    def _registered_tools(
        self,
        names: set[str],
    ) -> tuple[list[Any], list[dict[str, Any]]]:
        tools: list[Any] = []
        unavailable: list[dict[str, Any]] = []
        for name in sorted(names):
            try:
                tool = self.registry.get(name)
            except ToolNotFoundError:
                continue
            availability = self.registry.tool_availability(name)
            if availability["available"]:
                tools.append(tool)
            else:
                unavailable.append(
                    {
                        "tool_name": name,
                        "required_capabilities": availability[
                            "required_capabilities"
                        ],
                        "reasons": availability["reasons"],
                    }
                )
        return tools, unavailable

    def _existing_signatures(self, calls: list[ToolCall]) -> set[str]:
        signatures: set[str] = set()
        for call in calls:
            arguments = call.input_json if isinstance(call.input_json, dict) else {}
            try:
                tool = self.registry.get(call.tool_name)
                arguments = tool.input_model.model_validate(arguments).model_dump(mode="json")
            except (ToolNotFoundError, ValueError):
                pass
            signatures.add(tool_call_signature(call.tool_name, arguments))
        return signatures

    def _record_error_step(
        self,
        investigation: Investigation,
        iteration: int,
        started_at,
        error: str,
    ) -> None:  # type: ignore[no-untyped-def]
        self.session.add(
            InvestigationStep(
                investigation_id=investigation.id,
                iteration=iteration,
                decision=None,
                status="ERROR",
                rejection_reason=error[:1000],
                duration_ms=0,
                started_at=started_at,
                completed_at=utcnow(),
            )
        )
        investigation.current_iteration = iteration
        self.session.flush()

    def _mark_independent_evidence_gap(self, investigation_id: int) -> None:
        controller_gap = "缺少第二个独立证据源（系统观测），当前只能保留为中低置信候选。"
        for hypothesis in self._hypotheses(investigation_id):
            if hypothesis.status == "REJECTED" or hypothesis.confidence_level == "HIGH":
                continue
            existing = hypothesis.evidence_gap.strip()
            if existing and existing not in {"无", "暂无", "-"}:
                hypothesis.evidence_gap = f"{controller_gap} 原候选缺口：{existing}"[:300]
            else:
                hypothesis.evidence_gap = controller_gap
            hypothesis.updated_at = utcnow()
        self.session.flush()

    def _reject_step_and_stop(
        self,
        task: Task,
        investigation: Investigation,
        step: InvestigationStep,
        reason_code: str,
        detail: str,
    ) -> InvestigationOutcome:
        step.status = "REJECTED"
        step.rejection_reason = detail[:1000]
        step.completed_at = utcnow()
        self.session.flush()
        return self._stop_inconclusive(task, investigation, reason_code, detail)

    def _stop_inconclusive(
        self,
        task: Task,
        investigation: Investigation,
        reason_code: str,
        detail: str,
    ) -> InvestigationOutcome:
        mark_open_hypotheses_inconclusive(self.session, investigation)
        investigation.status = "INCONCLUSIVE"
        investigation.stop_reason = reason_code
        investigation.completed_at = utcnow()
        self.session.flush()
        self.audit.append_event(
            task,
            "INVESTIGATE",
            "investigation_stopped",
            "调查已停止，系统未生成未经证据支持的根因结论。",
            {
                "investigation_id": investigation.id,
                "status": investigation.status,
                "stop_reason": reason_code,
                "detail": detail[:500],
                "iteration": investigation.current_iteration,
            },
        )
        return InvestigationOutcome(
            status=investigation.status,
            stop_reason=reason_code,
            investigation=investigation,
            analysis=None,
        )

    def _needs_operator(
        self,
        task: Task,
        investigation: Investigation,
        reason_code: str,
        canonical_summary: str,
    ) -> InvestigationOutcome:
        mark_open_hypotheses_inconclusive(self.session, investigation)
        investigation.status = "NEEDS_OPERATOR"
        investigation.stop_reason = reason_code
        investigation.completed_at = utcnow()
        task.status = TaskStatus.NEEDS_OPERATOR.value
        task.summary = (
            f"{canonical_summary} 模型研判未完成，需运维人员根据已采集证据继续处理。"
        ).strip()
        task.updated_at = utcnow()
        self.session.flush()
        self.audit.append_event(
            task,
            TaskStatus.NEEDS_OPERATOR.value,
            "investigation_needs_operator",
            "模型服务不可用，任务保留真实证据并转人工处理。",
            {
                "investigation_id": investigation.id,
                "stop_reason": reason_code,
                "evidence_count": len(self._evidence_items(investigation.id)),
            },
        )
        return InvestigationOutcome(
            status=investigation.status,
            stop_reason=reason_code,
            investigation=investigation,
            analysis=None,
        )

    def _check_cancelled(self, task: Task, investigation: Investigation) -> None:
        try:
            self.cancellation_check()
        except Exception:
            investigation.status = "CANCELLED"
            investigation.stop_reason = "CANCELLED_AT_SAFE_BOUNDARY"
            investigation.completed_at = utcnow()
            self.session.flush()
            self.audit.append_event(
                task,
                "INVESTIGATE",
                "investigation_cancelled",
                "调查已在安全边界停止。",
                {"investigation_id": investigation.id},
            )
            raise

    def _task_tool_calls(self, task_id: int) -> list[ToolCall]:
        return list(
            self.session.scalars(
                select(ToolCall).where(ToolCall.task_id == task_id).order_by(ToolCall.id.asc())
            )
        )

    def _tool_call_count(self, task_id: int) -> int:
        return int(
            self.session.scalar(
                select(func.count(ToolCall.id)).where(ToolCall.task_id == task_id)
            )
            or 0
        )

    def _evidence_items(self, investigation_id: int) -> list[EvidenceItem]:
        return list(
            self.session.scalars(
                select(EvidenceItem)
                .where(EvidenceItem.investigation_id == investigation_id)
                .order_by(EvidenceItem.id.asc())
            )
        )

    def _hypotheses(self, investigation_id: int) -> list[Hypothesis]:
        return list(
            self.session.scalars(
                select(Hypothesis)
                .where(Hypothesis.investigation_id == investigation_id)
                .order_by(Hypothesis.id.asc())
            )
        )


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _analysis_validation_code(exc: ValueError) -> str:
    detail = str(exc).lower()
    if "ungrounded infrastructure" in detail:
        return "UNGROUNDED_INFRASTRUCTURE_IDENTIFIER"
    if "schema validation" in detail:
        return "ANALYSIS_SCHEMA_INVALID"
    return "ANALYSIS_FACT_BOUNDARY_REJECTED"
