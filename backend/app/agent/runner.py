from __future__ import annotations

from datetime import timezone
from pathlib import Path
import re
import time
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.agent.evidence_risk import assess_evidence_risk
from backend.app.agent.health_contract import general_health_core_requirements
from backend.app.agent.intent import IntentResolver
from backend.app.agent.planner import Planner
from backend.app.agent.process_summary import summarize_process_health
from backend.app.agent.responder import AgentResponder
from backend.app.agent.skills import SkillPolicyError, validate_plan_against_skill
from backend.app.ai.client import BailianClient, ModelCallError, ModelNotConfiguredError
from backend.app.ai.telemetry import ModelInvocationRecorder
from backend.app.audit.service import AuditService
from backend.app.channels.feishu.outbox import NotificationOutboxService
from backend.app.config_baseline.service import ConfigBaselineService, LAB_SCOPE, LIVE_SCOPE
from backend.app.core.config import settings
from backend.app.executor.config_policy import (
    ALLOWED_CONFIG_MODES,
    validate_repairable_config_path,
)
from backend.app.executor.policy import ExecutionDeniedError, authorize_execution
from backend.app.executor.systemd_policy import validate_restartable_unit
from backend.app.executor.verification import (
    ActionVerificationDecision,
    post_action_verification_input,
    pre_action_verification_input,
    validate_post_action_evidence,
    validate_pre_action_evidence,
    verification_tool_name,
)
from backend.app.investigation.engine import InvestigationEngine
from backend.app.investigation.depth import select_investigation_depth
from backend.app.investigation.tool_executor import MCPObservationExecutor, tool_schema_evidence
from backend.app.mcp.registry import ToolRegistry
from backend.app.models.entities import (
    ActionProposal,
    Approval,
    ConfigBaseline,
    ExecutionRecord,
    Task,
    ToolCall,
    utcnow,
)
from backend.app.perception.network_scope import classify_listener_scope
from backend.app.perception.service_impact import (
    verify_service_change_impact,
    verify_service_change_impact_precondition,
)
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.safety_case import (
    ActionSafetyCaseService,
    SafetyCaseIntegrityError,
)
from backend.app.schemas.enums import RiskLevel, ReviewDecision, TaskStatus, max_risk


class TaskCancelledError(RuntimeError):
    """Raised when a worker observes cancellation at a declared safe boundary."""


class AgentRunner:
    def __init__(
        self,
        session: Session,
        registry: ToolRegistry,
        *,
        cancellation_probe: Callable[[], bool] | None = None,
        event_checkpoint: Callable[[], None] | None = None,
    ):
        self.session = session
        self.registry = registry
        notification_outbox = NotificationOutboxService(
            session,
            default_chat_id=settings.feishu_default_chat_id,
        )
        self.audit = AuditService(
            session,
            after_append=event_checkpoint,
            event_sink=notification_outbox.enqueue_task_event,
        )
        self.observation_executor = MCPObservationExecutor(session, registry, self.audit)
        self.safety = SafetyEngine(session)
        self.safety_cases = ActionSafetyCaseService(session)
        self.intent_resolver = IntentResolver()
        self.planner = Planner()
        self.responder = AgentResponder()
        self.cancellation_probe = cancellation_probe or (lambda: False)
        self.investigation_depth_selector = select_investigation_depth
        self.investigation_engine = InvestigationEngine(
            session,
            registry,
            self.audit,
            cancellation_check=self._check_cancelled,
        )

    def _attach_model_observability(self, task: Task) -> None:
        recorder = ModelInvocationRecorder(self.session, task)
        candidates = [
            getattr(self.intent_resolver, "model_client", None),
            getattr(getattr(self.investigation_engine, "model", None), "model_client", None),
            getattr(getattr(self.investigation_engine, "knowledge", None), "model_client", None),
            getattr(getattr(self.investigation_engine, "memory", None), "model_client", None),
        ]
        seen: set[int] = set()
        for client in candidates:
            if not isinstance(client, BailianClient) or id(client) in seen:
                continue
            seen.add(id(client))
            if client.invocation_sink is None:
                client.invocation_sink = recorder

    def run(self, task: Task, conversation_context: list[dict[str, object]] | None = None) -> None:
        self._attach_model_observability(task)
        try:
            self._check_cancelled()
            self._transition(task, TaskStatus.STATIC_REVIEW, "执行安全意图静态校验。")
            review = self.safety.review_user_request(task, task.user_input)
            self.audit.append_event(
                task,
                TaskStatus.STATIC_REVIEW.value,
                "safety_review",
                review.reason,
                {
                    "decision": review.decision,
                    "risk_level": review.risk_level,
                    "matched_rules": review.matched_rules_json,
                },
            )
            if review.decision == ReviewDecision.REJECT.value:
                task.summary = "请求命中禁止级规则，系统未执行任何工具或系统变更。"
                self._transition(task, TaskStatus.REJECTED, "请求命中禁止规则，任务拒绝。")
                return

            if review.decision == ReviewDecision.APPROVAL_REQUIRED.value:
                self.audit.append_event(
                    task,
                    TaskStatus.APPROVAL_REQUIRED.value,
                    "approval_gate",
                    "高风险请求进入审批门禁；系统先完成只读取证，副作用方案仍需独立人工审批。",
                    {},
                )

            self._transition(task, TaskStatus.PLAN, "调用模型解析结构化运维意图。")
            self._check_cancelled()
            try:
                resolved_intent = self.intent_resolver.resolve(task.user_input, conversation_context or [])
            except ModelNotConfiguredError:
                task.intent = "model_unconfigured"
                task.summary = "模型服务未配置，系统未进行意图识别、未调用感知工具、未执行任何变更。"
                self._transition(task, TaskStatus.FAILED, "模型服务未配置，无法完成自然语言意图解析。")
                self.audit.append_event(
                    task,
                    TaskStatus.FAILED.value,
                    "intent_model_unconfigured",
                    task.summary,
                    {"provider": "bailian"},
                )
                return
            except (ModelCallError, ValueError) as exc:
                task.intent = "model_intent_failed"
                task.summary = f"模型意图解析失败：{exc}。系统未调用感知工具、未执行任何变更。"
                self._transition(task, TaskStatus.FAILED, "模型意图解析失败，任务停止。")
                self.audit.append_event(
                    task,
                    TaskStatus.FAILED.value,
                    "intent_model_failed",
                    "模型意图解析失败，系统停止任务。",
                    {"provider": "bailian", "error": str(exc)},
                )
                return
            self.audit.append_event(
                task,
                TaskStatus.PLAN.value,
                "intent_resolved",
                "模型完成结构化意图解析。",
                {
                    "provider": resolved_intent.provider,
                    "model": resolved_intent.model,
                    "prompt_hash": resolved_intent.prompt_hash,
                    "context_task_ids": [item.get("task_id") for item in (conversation_context or [])],
                    "decision": resolved_intent.decision.model_dump(mode="json"),
                },
            )
            plan = self.planner.create_plan(
                resolved_intent.decision,
                user_input=task.user_input,
            )
            task.intent = plan.intent
            try:
                skill_context = validate_plan_against_skill(plan, self.registry)
            except SkillPolicyError as exc:
                task.summary = f"Agent 计划未通过能力包工具边界校验：{exc}。系统未调用工具、未执行任何变更。"
                self._transition(task, TaskStatus.FAILED, "Agent 能力包策略拒绝执行计划。")
                used_tools = list(dict.fromkeys(item.tool_name for item in plan.tool_calls))
                rejected_tools = exc.rejected_tools or used_tools
                self.audit.append_event(
                    task,
                    TaskStatus.FAILED.value,
                    "skill_policy_rejected",
                    "Planner 生成的工具序列超出所选能力包边界，任务停止。",
                    {
                        "intent": plan.intent,
                        "used_tools": used_tools,
                        "rejected_tools": rejected_tools,
                        "reason": str(exc),
                    },
                )
                return
            self.audit.append_event(
                task,
                TaskStatus.PLAN.value,
                "skill_selected",
                f"选择运维能力包：{skill_context['skill_name']}。",
                skill_context,
            )
            self.audit.append_event(
                task,
                TaskStatus.PLAN.value,
                "plan_created",
                plan.rationale,
                {
                    "intent": plan.intent,
                    "tool_calls": [
                        {
                            "tool_name": item.tool_name,
                            "arguments": item.arguments,
                            "reason": item.reason,
                        }
                        for item in plan.tool_calls
                    ],
                },
            )

            if not plan.tool_calls:
                self.audit.append_event(
                    task,
                    TaskStatus.PLAN.value,
                    "tool_plan_empty",
                    "当前请求不需要系统感知工具。",
                    {"intent": plan.intent},
                )
                self._transition(task, TaskStatus.SUMMARIZE, "汇总 Agent 能力说明。")
                canonical_summary = self._summarize(task, [], proposal_context=None)
                task.summary = self.responder.compose(task, None, canonical_summary)
                self.audit.append_event(
                    task,
                    TaskStatus.SUMMARIZE.value,
                    "summary_created",
                    task.summary,
                    {
                        "intent": task.intent,
                        "risk_level": task.risk_level,
                        "analysis_id": None,
                    },
                )
                self._transition(task, TaskStatus.SEALED, "任务审计链封存。")
                task.sealed_at = utcnow()
                return

            self._transition(task, TaskStatus.PERCEIVE, "调用 MCP 感知工具采集证据。")
            observations: list[dict] = []
            for planned in plan.tool_calls:
                self._check_cancelled()
                call = self.observation_executor.execute(
                    task,
                    planned.tool_name,
                    planned.arguments,
                    reason=planned.reason,
                    source="baseline",
                )
                if "observations" in call.output_json:
                    observations.append(
                        {
                            "tool_name": call.tool_name,
                            "reason": planned.reason,
                            "result": call.output_json,
                        }
                    )

            self._transition(task, TaskStatus.SUMMARIZE, "汇总感知证据与安全结论。")
            self._check_cancelled()
            self._reconcile_evidence_risk(task, observations)
            canonical_summary = self._summarize(task, observations, proposal_context=None)
            task.summary = canonical_summary
            self.session.flush()
            self._check_cancelled()
            depth = self.investigation_depth_selector(task.intent, task.user_input)
            self.audit.append_event(
                task,
                "INVESTIGATE",
                "investigation_depth_selected",
                depth.reason,
                {
                    "mode": depth.mode,
                    "intent": task.intent,
                },
            )
            analysis = None
            investigation_id = None
            investigation_status = depth.mode
            investigation_stop_reason = "DIRECT_EVIDENCE_COMPLETE"
            if depth.mode == "ITERATIVE_RCA":
                outcome = self.investigation_engine.run(task, skill_context, canonical_summary)
                if outcome.status == TaskStatus.NEEDS_OPERATOR.value:
                    return
                persisted_observations = self._load_task_observations(task.id)
                if len(persisted_observations) > len(observations):
                    observations = persisted_observations
                    self._reconcile_evidence_risk(
                        task,
                        observations,
                        event_type="investigation_evidence_risk_assessed",
                    )
                analysis = outcome.analysis
                investigation_id = outcome.investigation.id
                investigation_status = outcome.status
                investigation_stop_reason = outcome.stop_reason
            proposal_context = self._create_action_proposals(task, observations)
            canonical_summary = self._summarize(
                task,
                observations,
                proposal_context=proposal_context,
                investigation_status=investigation_status,
                investigation_stop_reason=investigation_stop_reason,
            )
            analysis_result = analysis.result_json if analysis is not None else None
            task.summary = self.responder.compose(task, analysis_result, canonical_summary)
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "summary_created",
                task.summary,
                {
                    "intent": task.intent,
                    "risk_level": task.risk_level,
                    "analysis_id": analysis.id if analysis is not None else None,
                    "investigation_id": investigation_id,
                    "investigation_status": investigation_status,
                    "investigation_stop_reason": investigation_stop_reason,
                },
            )
            self._transition(task, TaskStatus.SEALED, "任务审计链封存。")
            task.sealed_at = utcnow()
        except TaskCancelledError:
            task.updated_at = utcnow()
            raise
        except Exception as exc:
            self.investigation_engine.fail_active_investigation(
                task,
                reason_code="INVESTIGATION_PIPELINE_FAILED",
                detail=str(exc),
            )
            task.summary = f"任务失败：{exc}"
            self._transition(task, TaskStatus.FAILED, "任务执行失败。")
            raise
        finally:
            task.updated_at = utcnow()

    def _load_task_observations(self, task_id: int) -> list[dict]:
        calls = self.session.scalars(
            select(ToolCall).where(ToolCall.task_id == task_id).order_by(ToolCall.id.asc())
        ).all()
        return [
            {
                "tool_name": call.tool_name,
                "reason": "持久化 MCP 观测",
                "result": call.output_json,
            }
            for call in calls
            if isinstance(call.output_json, dict) and "observations" in call.output_json
        ]

    def _reconcile_evidence_risk(
        self,
        task: Task,
        observations: list[dict],
        *,
        event_type: str = "evidence_risk_assessed",
    ) -> None:
        assessment = assess_evidence_risk(observations)
        previous_risk = RiskLevel(task.risk_level)
        final_risk = max_risk(previous_risk, assessment.risk_level)
        task.risk_level = final_risk.value
        self.audit.append_event(
            task,
            TaskStatus.SUMMARIZE.value,
            event_type,
            f"根据 MCP 证据将任务风险协调为 {final_risk.value}。",
            {
                "previous_risk_level": previous_risk.value,
                "evidence_risk_level": assessment.risk_level.value,
                "final_risk_level": final_risk.value,
                "reasons": list(assessment.reasons),
                "tool_names": list(assessment.tool_names),
            },
        )

    def _transition(self, task: Task, status: TaskStatus, message: str) -> None:
        task.status = status.value
        task.updated_at = utcnow()
        self.audit.append_event(task, status.value, "state_transition", message, {"status": status.value})
        self.session.flush()

    def _check_cancelled(self) -> None:
        if self.cancellation_probe():
            raise TaskCancelledError

    def approve_and_execute_proposal(
        self,
        proposal_id: int,
        operator: str = "local-admin",
        comment: str | None = None,
    ) -> Task:
        proposal = self.session.scalar(
            select(ActionProposal)
            .where(ActionProposal.id == proposal_id)
            .with_for_update()
        )
        if proposal is None:
            raise LookupError("proposal not found")

        task = get_task(self.session, proposal.task_id)
        if task is None:
            raise LookupError("task not found")
        if proposal.status != "PENDING_APPROVAL":
            raise ValueError("proposal is not pending approval")

        try:
            safety_case = self.safety_cases.assert_ready(proposal)
            bound_action = self.safety_cases.bound_action(safety_case, proposal)
        except SafetyCaseIntegrityError as exc:
            proposal.status = "BLOCKED"
            proposal.updated_at = utcnow()
            task.summary = str(exc)
            self.audit.append_event(
                task,
                TaskStatus.BLOCKED.value,
                "action_safety_case_blocked",
                str(exc),
                {
                    "proposal_id": proposal.id,
                    "tool_name": proposal.tool_name,
                },
            )
            self._transition(task, TaskStatus.BLOCKED, "执行依据未通过完整性校验。")
            return task
        bound_tool_name = str(bound_action["tool_name"])
        bound_input = dict(bound_action["input"])
        bound_risk_level = str(bound_action["risk_level"])

        approval = Approval(
            task_id=task.id,
            status="APPROVED",
            operator=operator,
            comment=comment,
        )
        self.session.add(approval)
        self.session.flush()
        self.safety_cases.record_approval(
            safety_case,
            operator=operator,
            comment=comment,
        )
        self.audit.append_event(
            task,
            TaskStatus.APPROVAL_REQUIRED.value,
            "approval_recorded",
            "管理员确认执行回滚。" if bound_tool_name == "restore_log_backup" else "管理员确认执行建议处置。",
            {
                "proposal_id": proposal.id,
                "operator": operator,
                "comment": comment,
                "action_fingerprint": safety_case.action_fingerprint,
            },
        )

        self._transition(task, TaskStatus.DYNAMIC_REVIEW, "执行结构化动作动态安全校验。")
        review = self.safety.review_tool_action(task, bound_tool_name, bound_input)
        self.session.flush()
        self.audit.append_event(
            task,
            TaskStatus.DYNAMIC_REVIEW.value,
            "safety_review",
            review.reason,
            {
                "decision": review.decision,
                "risk_level": review.risk_level,
                "matched_rules": review.matched_rules_json,
            },
        )
        if review.decision == ReviewDecision.REJECT.value:
            self.safety_cases.mark_blocked(
                safety_case,
                stage="dynamic_safety_review",
                reason=review.reason,
            )
            proposal.status = "REJECTED"
            proposal.updated_at = utcnow()
            task.summary = "建议处置未通过动态安全校验，系统没有执行任何变更。"
            self._transition(task, TaskStatus.BLOCKED, "动态安全校验拒绝执行。")
            return task

        tool = self.registry.get(bound_tool_name)
        try:
            execution_context = authorize_execution(
                bound_tool_name,
                bound_risk_level,
                bound_input,
            )
        except ExecutionDeniedError as exc:
            self._record_execution(task, proposal, None, exc.context)
            self.safety_cases.mark_blocked(
                safety_case,
                stage="execution_policy",
                reason=exc.context["reason"],
            )
            proposal.status = "BLOCKED"
            proposal.updated_at = utcnow()
            task.summary = "审批动作未通过受限执行策略，系统没有执行任何变更。"
            self.audit.append_event(
                task,
                TaskStatus.BLOCKED.value,
                "execution_policy_denied",
                exc.context["reason"],
                {
                    "proposal_id": proposal.id,
                    "tool_name": proposal.tool_name,
                    "executor": exc.context,
                },
            )
            self._transition(task, TaskStatus.BLOCKED, "受限执行策略拒绝执行。")
            return task

        (
            pre_verifier_call,
            pre_verification,
            impact_precondition_call,
            impact_precondition,
        ) = self._verify_action_precondition(
            task,
            proposal,
            bound_action,
        )
        if impact_precondition_call is not None and impact_precondition is not None:
            self.safety_cases.record_impact_precondition(
                safety_case,
                call_id=impact_precondition_call.id,
                verification=impact_precondition,
            )
        self.safety_cases.record_precondition(
            safety_case,
            call_id=pre_verifier_call.id if pre_verifier_call is not None else None,
            valid=pre_verification.valid,
            reason=pre_verification.reason,
            details=pre_verification.details,
        )
        if not pre_verification.valid:
            proposal.status = "BLOCKED"
            proposal.updated_at = utcnow()
            task.summary = "审批动作缺少完整的执行前独立校验证据，系统没有执行任何变更。"
            self._transition(task, TaskStatus.BLOCKED, "执行前独立校验未通过。")
            return task

        self._transition(task, TaskStatus.EXECUTE, "通过受限执行代理运行审批动作。")
        self.safety_cases.record_execution_started(safety_case)
        started = time.monotonic()
        call = ToolCall(
            task_id=task.id,
            tool_name=tool.name,
            tool_version=tool.version,
            input_json=bound_input,
            risk_level=tool.risk_level.value,
            status="running",
        )
        self.session.add(call)
        self.session.flush()
        execution_record = self._record_execution(task, proposal, call, execution_context)

        try:
            self._check_cancelled()
            self.safety_cases.bound_action(safety_case, proposal)
            result = self.registry.call(tool.name, call.input_json)
            call.status = result.status
            call.output_json = result.model_dump(mode="json")
        except Exception as exc:
            call.status = "unknown"
            call.output_json = {
                "status": "unknown",
                "warnings": [str(exc)],
                "outcome": "UNKNOWN",
            }
            self.safety_cases.record_execution(
                safety_case,
                call_id=call.id,
                outcome="UNKNOWN",
                output=call.output_json,
                reason=str(exc),
            )
            proposal.status = "NEEDS_OPERATOR"
            proposal.updated_at = utcnow()
            task.summary = (
                "审批动作返回前出现异常，系统无法确认副作用是否发生。"
                "该动作已进入人工核验，系统不会自动重试。"
            )
            self.audit.append_event(
                task,
                TaskStatus.EXECUTE.value,
                "tool_call_outcome_unknown",
                "受限执行代理未能确认动作结果，已禁止自动重试。",
                {
                    "proposal_id": proposal.id,
                    "tool_call_id": call.id,
                    "tool_name": tool.name,
                    "tool_version": tool.version,
                    **tool_schema_evidence(tool),
                    "input": call.input_json,
                    "executor": execution_context,
                    "action_fingerprint": safety_case.action_fingerprint,
                    "outcome": "UNKNOWN",
                    "automatic_retry": False,
                    "error": str(exc),
                },
            )
            self._transition(
                task,
                TaskStatus.NEEDS_OPERATOR,
                "动作结果不确定，等待人工核验且不自动重试。",
            )
            return task
        finally:
            call.ended_at = utcnow()
            call.duration_ms = int((time.monotonic() - started) * 1000)

        self.safety_cases.record_execution(
            safety_case,
            call_id=call.id,
            outcome="SUCCEEDED",
            output=call.output_json,
        )
        self.audit.append_event(
            task,
            TaskStatus.EXECUTE.value,
            "tool_call",
            f"执行工具 {tool.name} 完成，状态 {call.status}。",
            {
                "proposal_id": proposal.id,
                "tool_call_id": call.id,
                "tool_name": tool.name,
                "tool_version": tool.version,
                **tool_schema_evidence(tool),
                "input": call.input_json,
                "output": call.output_json,
                "duration_ms": call.duration_ms,
                "executor": execution_context,
                "execution_record_id": execution_record.id,
            },
        )

        self._transition(task, TaskStatus.VERIFY, "使用独立只读工具核验执行前后状态。")
        (
            post_verifier_call,
            post_verification,
            impact_verifier_call,
            impact_verification,
        ) = self._verify_action_postcondition(
            task,
            proposal,
            bound_action,
            pre_verifier_call,
            call,
        )
        if impact_verifier_call is not None and impact_verification is not None:
            self.safety_cases.record_impact_verification(
                safety_case,
                call_id=impact_verifier_call.id,
                verification=impact_verification,
            )
        self.safety_cases.record_postcondition(
            safety_case,
            call_id=post_verifier_call.id if post_verifier_call is not None else None,
            valid=post_verification.valid,
            reason=post_verification.reason,
            details=post_verification.details,
        )
        if not post_verification.valid:
            proposal.status = "BLOCKED"
            proposal.updated_at = utcnow()
            task.summary = "审批动作已经运行，但独立校验未通过；系统已保留执行证据并转人工处理。"
            self._transition(task, TaskStatus.NEEDS_OPERATOR, "执行后独立校验未通过。")
            return task

        proposal.status = "EXECUTED"
        proposal.updated_at = utcnow()
        if bound_tool_name == "safe_log_rotate":
            self._create_rollback_proposal(task, call.output_json)
        task.summary = self._summarize_execution(bound_tool_name, call.output_json)
        self.audit.append_event(
            task,
            TaskStatus.SUMMARIZE.value,
            "summary_created",
            task.summary,
            {"proposal_id": proposal.id, "risk_level": task.risk_level},
        )
        self._transition(task, TaskStatus.SEALED, "审批执行链路已封存。")
        task.sealed_at = utcnow()
        return task

    def reject_proposal(
        self,
        proposal_id: int,
        operator: str = "local-admin",
        comment: str | None = None,
    ) -> Task:
        proposal = self.session.get(ActionProposal, proposal_id)
        if proposal is None:
            raise LookupError("proposal not found")

        task = get_task(self.session, proposal.task_id)
        if task is None:
            raise LookupError("task not found")
        if proposal.status != "PENDING_APPROVAL":
            raise ValueError("proposal is not pending approval")

        approval = Approval(
            task_id=task.id,
            status="REJECTED",
            operator=operator,
            comment=comment,
        )
        self.session.add(approval)
        safety_case = self.safety_cases.get_for_proposal(proposal.id)
        if safety_case is not None:
            self.safety_cases.mark_rejected(
                safety_case,
                operator=operator,
                comment=comment,
            )
        proposal.status = "REJECTED"
        proposal.updated_at = utcnow()
        rejecting_rollback = proposal.tool_name == "restore_log_backup"
        task.summary = (
            "管理员选择保留当前处置结果，本次回滚未执行，审批结果已写入审计链。"
            if rejecting_rollback
            else "管理员已拒绝执行建议处置。系统未运行副作用工具，审批结果已写入审计链。"
        )
        task.updated_at = utcnow()
        self.session.flush()
        self.audit.append_event(
            task,
            TaskStatus.APPROVAL_REQUIRED.value,
            "approval_recorded",
            "管理员选择保留当前处置结果，不执行回滚。" if rejecting_rollback else "管理员拒绝执行建议处置。",
            {
                "proposal_id": proposal.id,
                "operator": operator,
                "comment": comment,
                "decision": "REJECTED",
            },
        )
        self._transition(task, TaskStatus.SEALED, "审批拒绝链路已封存。")
        task.sealed_at = utcnow()
        return task

    def _verify_action_precondition(
        self,
        task: Task,
        proposal: ActionProposal,
        bound_action: dict,
    ) -> tuple[
        ToolCall | None,
        ActionVerificationDecision,
        ToolCall | None,
        dict | None,
    ]:
        verifier_call: ToolCall | None = None
        impact_verifier_call: ToolCall | None = None
        impact_verification: dict | None = None
        tool_name = str(bound_action["tool_name"])
        action_input = dict(bound_action["input"])
        try:
            arguments = pre_action_verification_input(
                tool_name,
                action_input,
            )
            verifier_call = self.observation_executor.execute(
                task,
                verification_tool_name(tool_name),
                arguments,
                reason=(
                    "记录受控服务重启前的独立 systemd 状态证据。"
                    if tool_name == "restart_managed_service"
                    else (
                        "记录配置权限恢复前的权限、属主和完整内容哈希。"
                        if tool_name == "restore_config_mode"
                        else "记录副作用动作执行前的文件完整性证据。"
                    )
                ),
                source="action_precondition",
                stage=TaskStatus.DYNAMIC_REVIEW.value,
            )
            decision = validate_pre_action_evidence(
                tool_name,
                action_input,
                verifier_call.output_json,
            )
        except Exception as exc:
            decision = ActionVerificationDecision(
                valid=False,
                reason=f"执行前独立校验失败：{exc}",
                details={},
            )
        if tool_name == "restart_managed_service" and decision.valid:
            try:
                safety_case = self.safety_cases.get_for_proposal(proposal.id)
                if safety_case is None:
                    raise ValueError("missing action safety case")
                frozen_impact = safety_case.scope_json.get("change_impact")
                if not isinstance(frozen_impact, dict):
                    raise ValueError("missing frozen change-impact scope")
                unit = str(action_input["unit"])
                impact_verifier_call = self.observation_executor.execute(
                    task,
                    "service_dependency_snapshot",
                    {
                        "focus_units": [unit],
                        "change_action": "restart",
                    },
                    reason="执行前重新采样服务关系，核对审批后是否发生范围漂移。",
                    source="action_impact_precondition",
                    stage=TaskStatus.DYNAMIC_REVIEW.value,
                )
                observations = impact_verifier_call.output_json.get(
                    "observations",
                    [],
                )
                current_observation = (
                    observations[0]
                    if isinstance(observations, list)
                    and observations
                    and isinstance(observations[0], dict)
                    else {}
                )
                impact_verification = verify_service_change_impact_precondition(
                    frozen_impact,
                    current_observation,
                )
            except Exception as exc:
                impact_verification = {
                    "valid": False,
                    "outcome": "DIVERGED",
                    "reason": f"执行前影响范围复核失败：{exc}",
                    "details": {
                        "prediction_error_count": 1,
                        "evidence_gaps": ["PRE_IMPACT_VERIFICATION_FAILED"],
                    },
                }
            decision = ActionVerificationDecision(
                valid=decision.valid
                and bool(impact_verification.get("valid")),
                reason=(
                    decision.reason
                    if impact_verification.get("valid")
                    else str(impact_verification.get("reason") or decision.reason)
                ),
                details={
                    **decision.details,
                    "impact_precondition": impact_verification,
                },
            )
        self.audit.append_event(
            task,
            TaskStatus.DYNAMIC_REVIEW.value,
            "verification_precondition",
            decision.reason,
            {
                "proposal_id": proposal.id,
                "valid": decision.valid,
                "verifier_tool_call_id": verifier_call.id if verifier_call else None,
                "impact_verifier_tool_call_id": (
                    impact_verifier_call.id if impact_verifier_call else None
                ),
                "details": decision.details,
            },
        )
        return (
            verifier_call,
            decision,
            impact_verifier_call,
            impact_verification,
        )

    def _verify_action_postcondition(
        self,
        task: Task,
        proposal: ActionProposal,
        bound_action: dict,
        pre_verifier_call: ToolCall | None,
        action_call: ToolCall,
    ) -> tuple[
        ToolCall | None,
        ActionVerificationDecision,
        ToolCall | None,
        dict | None,
    ]:
        verifier_call: ToolCall | None = None
        impact_verifier_call: ToolCall | None = None
        impact_verification: dict | None = None
        tool_name = str(bound_action["tool_name"])
        action_input = dict(bound_action["input"])
        try:
            if pre_verifier_call is None:
                raise ValueError("missing pre-action verifier evidence")
            arguments = post_action_verification_input(
                tool_name,
                action_input,
                action_call.output_json,
            )
            verifier_call = self.observation_executor.execute(
                task,
                verification_tool_name(tool_name),
                arguments,
                reason=(
                    "独立核验受控服务重启后的活动状态和主进程。"
                    if tool_name == "restart_managed_service"
                    else (
                        "独立核验配置权限已恢复且内容、属主保持不变。"
                        if tool_name == "restore_config_mode"
                        else "独立核验副作用动作执行后的文件状态与内容哈希。"
                    )
                ),
                source="action_postcondition",
                stage=TaskStatus.VERIFY.value,
            )
            decision = validate_post_action_evidence(
                tool_name,
                action_input,
                pre_verifier_call.output_json,
                action_call.output_json,
                verifier_call.output_json,
            )
        except Exception as exc:
            decision = ActionVerificationDecision(
                valid=False,
                reason=f"执行后独立校验失败：{exc}",
                details={},
            )
        if tool_name == "restart_managed_service":
            try:
                safety_case = self.safety_cases.get_for_proposal(proposal.id)
                if safety_case is None:
                    raise ValueError("missing action safety case")
                frozen_impact = safety_case.scope_json.get("change_impact")
                if not isinstance(frozen_impact, dict):
                    raise ValueError("missing frozen change-impact scope")
                unit = str(action_input["unit"])
                impact_verifier_call = self.observation_executor.execute(
                    task,
                    "service_dependency_snapshot",
                    {
                        "focus_units": [unit],
                        "change_action": "restart",
                    },
                    reason="复验服务关系范围、期望状态与 systemd 传播结果。",
                    source="action_impact_verification",
                    stage=TaskStatus.VERIFY.value,
                )
                observations = impact_verifier_call.output_json.get(
                    "observations",
                    [],
                )
                post_observation = (
                    observations[0]
                    if isinstance(observations, list)
                    and observations
                    and isinstance(observations[0], dict)
                    else {}
                )
                impact_verification = verify_service_change_impact(
                    frozen_impact,
                    post_observation,
                )
            except Exception as exc:
                impact_verification = {
                    "valid": False,
                    "outcome": "DIVERGED",
                    "reason": f"执行后影响复验失败：{exc}",
                    "details": {
                        "prediction_error_count": 1,
                        "evidence_gaps": ["POST_IMPACT_VERIFICATION_FAILED"],
                    },
                }
            decision = ActionVerificationDecision(
                valid=decision.valid
                and bool(impact_verification.get("valid")),
                reason=(
                    decision.reason
                    if not decision.valid
                    or impact_verification.get("valid")
                    else str(
                        impact_verification.get("reason")
                        or decision.reason
                    )
                ),
                details={
                    **decision.details,
                    "impact_verification": impact_verification,
                },
            )
        verifier_ids = [
            call.id
            for call in (
                pre_verifier_call,
                verifier_call,
                impact_verifier_call,
            )
            if call is not None
        ]
        self.audit.append_event(
            task,
            TaskStatus.VERIFY.value,
            "verify_result",
            decision.reason,
            {
                "proposal_id": proposal.id,
                "valid": decision.valid,
                "action_tool_call_id": action_call.id,
                "verifier_tool_call_ids": verifier_ids,
                "details": decision.details,
                "artifacts": action_call.output_json.get("artifacts", []),
                "evidence_refs": action_call.output_json.get("evidence_refs", []),
            },
        )
        return (
            verifier_call,
            decision,
            impact_verifier_call,
            impact_verification,
        )

    def _record_execution(
        self,
        task: Task,
        proposal: ActionProposal,
        call: ToolCall | None,
        context: dict,
    ) -> ExecutionRecord:
        record = ExecutionRecord(
            task_id=task.id,
            proposal_id=proposal.id,
            tool_call_id=call.id if call is not None else None,
            tool_name=proposal.tool_name,
            risk_level=proposal.risk_level,
            executor_mode=context["executor_mode"],
            runtime_user=context["runtime_user"],
            runtime_uid=context["runtime_uid"],
            target_user=context["target_user"],
            allowed=context["allowed"],
            reason=context["reason"],
            scope_json=context["scope"],
        )
        self.session.add(record)
        self.session.flush()
        return record

    def _summarize(
        self,
        task: Task,
        observations: list[dict],
        proposal_context: dict | None = None,
        *,
        investigation_status: str | None = None,
        investigation_stop_reason: str | None = None,
    ) -> str:
        if task.status == TaskStatus.REJECTED.value:
            return "任务已拒绝，未执行工具。"
        if task.intent == "agent_capability_help":
            return (
                "我可以处理磁盘空间分析、日志与服务排查、网络暴露面检查、配置漂移核验、"
                "服务退化根因诊断、进程健康分析和系统巡检。所有任务会先做安全校验；默认只读感知，涉及删除、重启、"
                "权限修改或日志轮转时必须进入审批和受限执行。"
            )
        if task.intent == "disk_pressure_analysis":
            large_file_scan_performed, large_files = _collect_large_file_observations(
                observations
            )
            deleted_file_scan_performed, deleted_open_files = (
                _collect_deleted_open_file_observations(observations)
            )
            capacity_context = _summarize_disk_capacity(observations)
            journal_context = _summarize_journal_storage(observations)
            mount_context = _summarize_filesystem_mount(observations)
            prefix = (
                "已完成磁盘压力只读分析。"
                + capacity_context
                + journal_context
                + mount_context
            )
            mount_focused_request = bool(
                mount_context
                and any(
                    keyword in str(task.user_input or "")
                    for keyword in ("挂载点", "挂载选项", "文件系统类型", "单独挂载")
                )
            )
            if deleted_open_files:
                top = deleted_open_files[0]
                retained_bytes = sum(
                    _file_size(item) for item in deleted_open_files
                )
                owner = top.get("systemd_unit") or top.get("process") or top.get("pid")
                return (
                    f"{prefix}发现 {len(deleted_open_files)} 个已删除但仍由进程持有的文件，"
                    f"共保留约 {round(retained_bytes / 1024 / 1024, 2)} MiB；"
                    f"最大项原路径为 {top.get('path')}，持有方为 {owner or '待确认'}。"
                    "删除目录项不会立即释放这部分空间，应先核对进程和服务影响，"
                    "再通过独立审批任务决定是否重启或滚动处置。本轮未执行系统变更。"
                )
            if large_files:
                top = large_files[0]
                if proposal_context:
                    proposed_path = proposal_context.get("path")
                    proposed_size = proposal_context.get("size_bytes", 0)
                    return (
                        f"{prefix}发现可安全轮转的大文件 "
                        f"{proposed_path}，大小约 {round(float(proposed_size or 0) / 1024 / 1024, 2)} MB。"
                        "本阶段未执行系统变更，已生成需审批的安全轮转建议。"
                    )
                return (
                    f"{prefix}发现较大文件 "
                    f"{top.get('path')}，大小约 {round(top.get('size_bytes', 0) / 1024 / 1024, 2)} MB。"
                    "该候选不在安全轮转边界内，本阶段未执行系统变更，未生成处置建议。"
                )
            if mount_focused_request:
                return f"{prefix}本轮未执行系统变更。"
            if not deleted_file_scan_performed:
                prefix += "未取得已删除未释放文件的扫描证据。"
            if not large_file_scan_performed:
                if investigation_status == "DIRECT_EVIDENCE":
                    return (
                        f"{prefix}本次仅查询容量，未扫描文件目录；"
                        "如需定位占用来源，可继续要求检查大文件或日志。"
                    )
                if investigation_status == "INCONCLUSIVE":
                    return (
                        f"{prefix}本轮未取得大文件定位证据，"
                        "暂不能判断具体占用来源或提出清理方案。"
                    )
                return (
                    f"{prefix}尚未执行大文件定位，"
                    "需补充只读文件扫描后才能判断具体占用来源。"
                )
            return f"{prefix}未在允许扫描范围内发现超过阈值的大文件。"
        if task.intent == "network_exposure_analysis":
            network_result: dict = {}
            catalog_result: dict = {}
            socket_contexts: list[dict] = []
            for item in observations:
                if item["tool_name"] == "network_listeners":
                    network_result = item["result"]
                if item["tool_name"] == "service_catalog_snapshot":
                    catalog_result = item["result"]
                if item["tool_name"] == "socket_process_context":
                    raw_contexts = item["result"].get("observations", [])
                    if raw_contexts and isinstance(raw_contexts[0], dict):
                        socket_contexts.extend(
                            context
                            for context in raw_contexts
                            if isinstance(context, dict)
                        )
            targeted_contexts = [
                context
                for context in socket_contexts
                if _request_targets_socket(task.user_input, context)
            ]
            if network_result and _request_asks_for_unattributed_listeners(
                task.user_input
            ):
                return _with_service_catalog_context(
                    _summarize_unattributed_listeners(network_result),
                    network_result,
                    catalog_result,
                )
            if targeted_contexts:
                return _with_target_service_catalog_context(
                    _summarize_targeted_sockets(targeted_contexts),
                    catalog_result,
                    targeted_contexts,
                )
            if network_result:
                return _with_service_catalog_context(
                    _summarize_network_exposure(network_result),
                    network_result,
                    catalog_result,
                )
            if socket_contexts:
                return _summarize_targeted_socket(socket_contexts[-1])
            return _summarize_network_exposure(network_result)
        if task.intent == "process_health_analysis":
            snapshot: dict = {}
            processes = []
            handles = []
            runtime_details = []
            for item in observations:
                if item["tool_name"] == "system_snapshot":
                    snapshots = item["result"].get("observations", [])
                    if snapshots and isinstance(snapshots[0], dict):
                        snapshot = snapshots[0]
                if item["tool_name"] == "process_list":
                    processes = item["result"].get("observations", [])
                if item["tool_name"] == "process_file_handles":
                    handles = item["result"].get("observations", [])
                if item["tool_name"] == "process_runtime_detail":
                    runtime_details.extend(item["result"].get("observations", []))
            return summarize_process_health(snapshot, processes, handles, runtime_details)
        if task.intent == "log_analysis":
            service_states = _collect_service_observations(observations)
            impact_summary = _summarize_service_change_impact(observations)
            if proposal_context and proposal_context.get("action") == "service_restart":
                unit = proposal_context.get("unit")
                active_state = proposal_context.get("active_state") or "未知"
                if impact_summary:
                    impact_text = impact_summary.removesuffix("本轮未执行系统变更。")
                    return (
                        f"{impact_text}已冻结 {unit} 的单次重启动作契约，等待人工审批；"
                        "审批后仍会重新采集运行关系，范围发生变化即撤销执行。"
                        "执行失败不自动重试，保留前后证据并转人工处理。"
                    )
                return (
                    f"已核验 {unit}，当前活动状态为 {active_state}。"
                    "该服务同时满足用户明确请求、真实状态观测和精确白名单三项条件；"
                    "本阶段未修改系统，已生成待人工审批的单次重启方案。"
                )
            if impact_summary:
                return impact_summary
            if service_states:
                first = service_states[0]
                summary = (
                    f"已完成服务状态只读分析：{first['unit']} 当前为 "
                    f"{first.get('active_state') or '未知'}/{first.get('sub_state') or '未知'}。"
                )
                if investigation_status == "INCONCLUSIVE":
                    return (
                        f"{summary}现有证据尚不足以证明根因；建议补采该单元专属日志、"
                        "退出上下文和同期变更记录后再处置。本轮未执行系统变更。"
                    )
                return (
                    f"{summary}本轮未执行系统变更，也未生成越过白名单的重启方案。"
                )
            summary = "已完成日志与服务状态只读分析，已采集近期系统日志并检查失败服务。"
            if investigation_status == "INCONCLUSIVE":
                return (
                    f"{summary}现有证据尚不足以证明根因；建议补采目标服务的专属日志、"
                    "退出上下文和同期变更记录。本轮未执行系统变更。"
                )
            return f"{summary}未执行系统变更。"
        if task.intent == "service_degradation_analysis":
            return _summarize_service_degradation(observations)
        if task.intent == "config_integrity_analysis":
            if proposal_context and proposal_context.get("action") == "config_mode_restore":
                return (
                    f"已确认 {proposal_context['path']} 仅发生权限位漂移，文件内容和属主仍与"
                    f"基线一致；建议恢复为 {proposal_context['target_mode']}。"
                    "方案已绑定本次基线核验记录，等待人工审批，本阶段未修改系统。"
                )
            return _summarize_config_integrity(observations)
        if task.intent == "general_system_health":
            return _summarize_general_health(observations)
        return f"已完成只读分析，调用 {len(observations)} 个感知工具。未执行系统变更。"

    def _summarize_execution(self, tool_name: str, output: dict) -> str:
        if tool_name == "restore_config_mode":
            observations = output.get("observations", [])
            observation = observations[0] if observations and isinstance(observations[0], dict) else {}
            path = observation.get("path")
            target_mode = observation.get("target_mode")
            if path and target_mode:
                return (
                    f"已按审批结果将 {path} 的权限恢复为 {target_mode}；独立配置扫描确认"
                    "内容哈希和属主未变化，执行与验证证据已写入审计链。"
                )
            return "已完成审批后的配置权限恢复与独立完整性核验，证据已写入审计链。"
        if tool_name == "restart_managed_service":
            observations = output.get("observations", [])
            observation = observations[0] if observations and isinstance(observations[0], dict) else {}
            unit = observation.get("unit")
            return (
                f"已按审批结果向 {unit} 提交一次受控重启，并由独立服务状态工具确认恢复；"
                "执行与验证证据已写入审计链。"
                if unit
                else "已完成审批后的受控服务重启与独立状态核验，证据已写入审计链。"
            )
        if tool_name == "restore_log_backup":
            observations = output.get("observations", [])
            observation = observations[0] if observations and isinstance(observations[0], dict) else {}
            target = observation.get("restore_target")
            snapshot = observation.get("pre_restore_snapshot_path")
            if target and snapshot:
                return (
                    f"已完成审批后的日志回滚，备份内容已恢复到 {target}；"
                    f"恢复前内容已保存为 {snapshot}，执行证据已写入审计链。"
                )
            return "已完成审批后的日志回滚，恢复结果已写入审计链。"
        artifacts = output.get("artifacts", [])
        if artifacts:
            artifact = artifacts[0]
            artifact_path = artifact.get("path") if isinstance(artifact, dict) else None
            if artifact_path:
                reclaimed = 0
                observations = output.get("observations", [])
                if observations and isinstance(observations[0], dict):
                    reclaimed = int(observations[0].get("reclaimed_bytes") or 0)
                reclaimed_text = f"，释放约 {round(reclaimed / 1024 / 1024, 2)} MB" if reclaimed else ""
                return (
                    "已完成审批后的可逆处置。系统生成备份产物 "
                    f"{artifact_path}，并截断源日志{reclaimed_text}；执行证据已写入审计链。"
                )
        return "已完成审批后的可逆处置。执行结果已写入审计链。"

    def _create_rollback_proposal(self, task: Task, output: dict) -> ActionProposal | None:
        existing = self.session.execute(
            select(ActionProposal).where(
                ActionProposal.task_id == task.id,
                ActionProposal.tool_name == "restore_log_backup",
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing

        artifacts = output.get("artifacts", [])
        artifact = next(
            (
                item
                for item in artifacts
                if isinstance(item, dict)
                and item.get("type") == "backup"
                and isinstance(item.get("path"), str)
                and isinstance(item.get("restore_target"), str)
            ),
            None,
        )
        if artifact is None:
            self.audit.append_event(
                task,
                TaskStatus.VERIFY.value,
                "rollback_proposal_skipped",
                "执行结果未返回可验证备份产物，未生成回滚建议。",
                {},
            )
            return None

        dry_run_input = {
            "artifact_path": artifact["path"],
            "restore_target": artifact["restore_target"],
            "dry_run": True,
        }
        try:
            self._check_cancelled()
            dry_run = self.registry.call("restore_log_backup", dry_run_input)
        except Exception as exc:
            self.audit.append_event(
                task,
                TaskStatus.VERIFY.value,
                "rollback_proposal_skipped",
                "备份产物未通过恢复工具 dry-run 校验，未生成回滚建议。",
                {"error": str(exc), **dry_run_input},
            )
            return None

        proposal = ActionProposal(
            task_id=task.id,
            tool_name="restore_log_backup",
            input_json={**dry_run_input, "dry_run": False},
            risk_level="R2",
            reason="日志轮转已完成，可在审批后从真实备份恢复；恢复前会再次保存当前日志内容。",
            status="PENDING_APPROVAL",
            dry_run_result_json=dry_run.model_dump(mode="json"),
        )
        self.session.add(proposal)
        self.session.flush()
        self._reconcile_proposal_risk(task, proposal)
        self.audit.append_event(
            task,
            TaskStatus.VERIFY.value,
            "rollback_proposal_created",
            "根据真实备份产物生成可审批的日志回滚方案。",
            {
                "proposal_id": proposal.id,
                "tool_name": proposal.tool_name,
                "risk_level": proposal.risk_level,
                "input": proposal.input_json,
                "dry_run": proposal.dry_run_result_json,
            },
        )
        return proposal

    def _create_action_proposals(self, task: Task, observations: list[dict]) -> dict | None:
        if task.risk_level == RiskLevel.R4.value:
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "任务已升级为禁止级风险，不生成任何副作用处置方案。",
                {"risk_level": task.risk_level},
            )
            return None

        if task.intent == "log_analysis" and _requests_service_restart(task.user_input):
            return self._create_service_restart_proposal(task, observations)
        if task.intent == "config_integrity_analysis" and _requests_config_mode_restore(task.user_input):
            return self._create_config_mode_restore_proposal(task)
        if task.intent != "disk_pressure_analysis":
            return None

        _, large_files = _collect_large_file_observations(observations)

        if not large_files:
            return None

        candidate = next(
            (item for item in large_files if _is_safe_rotation_candidate(item.get("path"))),
            None,
        )
        if candidate is None:
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "未找到符合安全轮转边界的大文件候选。",
                {"candidate_count": len(large_files)},
            )
            return None
        path = candidate.get("path")
        if not isinstance(path, str):
            return None

        dry_run_input = {"path": path, "backup": True, "compress": True, "keep_days": 30, "dry_run": True}
        try:
            self._check_cancelled()
            dry_run = self.registry.call("safe_log_rotate", dry_run_input)
        except Exception as exc:
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "候选文件未通过安全处置工具的参数校验。",
                {"path": path, "error": str(exc)},
            )
            return None

        proposal = ActionProposal(
            task_id=task.id,
            tool_name="safe_log_rotate",
            input_json={**dry_run_input, "dry_run": False},
            risk_level="R2",
            reason="发现较大日志文件，建议审批后先备份压缩，再截断源日志释放空间；可通过备份产物恢复。",
            status="PENDING_APPROVAL",
            dry_run_result_json=dry_run.model_dump(mode="json"),
        )
        self.session.add(proposal)
        self.session.flush()
        self._reconcile_proposal_risk(task, proposal)
        self.audit.append_event(
            task,
            TaskStatus.SUMMARIZE.value,
            "action_proposal_created",
            "生成可审批的安全处置方案：safe_log_rotate。",
            {
                "proposal_id": proposal.id,
                "tool_name": proposal.tool_name,
                "risk_level": proposal.risk_level,
                "input": proposal.input_json,
                "dry_run": proposal.dry_run_result_json,
            },
        )
        return {"path": path, "size_bytes": candidate.get("size_bytes", 0), "proposal_id": proposal.id}

    def _create_service_restart_proposal(
        self,
        task: Task,
        observations: list[dict],
    ) -> dict | None:
        candidates = _collect_restartable_service_observations(observations)
        if not candidates:
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "未取得同时满足只读观测和精确白名单的服务单元，不生成重启方案。",
                {},
            )
            return None

        request_text = str(task.user_input or "").lower()
        named = [
            item
            for item in candidates
            if str(item["unit"]).removesuffix(".service").lower() in request_text
        ]
        selectable = named or candidates
        if len(selectable) != 1:
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "发现多个可恢复服务但当前请求未唯一指定目标，未生成重启方案。",
                {"candidate_count": len(selectable)},
            )
            return None

        candidate = selectable[0]
        unit = candidate["unit"]
        desired_state = _desired_service_state(observations, unit)
        if (
            desired_state is None
            or desired_state.get("expected_active_state") != "active"
        ):
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "目标服务缺少经审批的 active 期望状态，不生成重启方案。",
                {"unit": unit},
            )
            return None
        change_impact = _service_change_impact(observations, unit, action="restart")
        if change_impact is None or change_impact.get("status") not in {
            "ASSESSED",
            "PARTIAL",
        }:
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "目标服务缺少可核验的重启影响评估，不生成重启方案。",
                {"unit": unit},
            )
            return None
        dry_run_input = {"unit": unit, "dry_run": True}
        try:
            self._check_cancelled()
            dry_run = self.registry.call("restart_managed_service", dry_run_input)
        except Exception as exc:
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "目标服务未通过受控重启工具 dry-run 校验。",
                {"unit": unit, "error": str(exc)},
            )
            return None

        proposal = ActionProposal(
            task_id=task.id,
            tool_name="restart_managed_service",
            input_json={"unit": unit, "dry_run": False},
            risk_level="R3",
            reason=(
                f"用户明确请求重启 {unit}；该单元已由 service_status 观测、"
                f"服务目录登记为 {desired_state.get('criticality') or '未分级'}，"
                f"影响评估识别 {change_impact.get('propagated_unit_count', 0)} 个传播单元和 "
                f"{change_impact.get('possible_client_count', 0)} 个当前连接方。"
                "批准后只提交一次重启，结果由独立状态工具核验。"
            ),
            status="PENDING_APPROVAL",
            dry_run_result_json=dry_run.model_dump(mode="json"),
        )
        self.session.add(proposal)
        self.session.flush()
        self._reconcile_proposal_risk(task, proposal)
        self.audit.append_event(
            task,
            TaskStatus.SUMMARIZE.value,
            "action_proposal_created",
            "根据已观测服务证据生成可审批的受控重启方案。",
            {
                "proposal_id": proposal.id,
                "tool_name": proposal.tool_name,
                "risk_level": proposal.risk_level,
                "input": proposal.input_json,
                "dry_run": proposal.dry_run_result_json,
            },
        )
        return {
            "action": "service_restart",
            "unit": unit,
            "active_state": candidate.get("active_state"),
            "impact_status": change_impact.get("status"),
            "propagated_unit_count": change_impact.get("propagated_unit_count", 0),
            "possible_client_count": change_impact.get("possible_client_count", 0),
            "proposal_id": proposal.id,
        }

    def _create_config_mode_restore_proposal(self, task: Task) -> dict | None:
        configured_paths: list[str] = []
        raw_paths = tuple(getattr(settings, "repairable_config_paths", ()))
        for raw_path in raw_paths:
            try:
                configured_paths.append(validate_repairable_config_path(raw_path, raw_paths))
            except ValueError:
                continue
        configured_paths = list(dict.fromkeys(configured_paths))
        if not configured_paths:
            return None

        baselines = list(
            self.session.scalars(
                select(ConfigBaseline)
                .order_by(ConfigBaseline.id.desc())
            )
        )
        baseline_by_path: dict[str, ConfigBaseline] = {}
        for baseline in baselines:
            for snapshot in baseline.snapshot_json:
                path = snapshot.get("path") if isinstance(snapshot, dict) else None
                expected_scope = (
                    LAB_SCOPE
                    if isinstance(path, str) and _is_lab_config_path(path)
                    else LIVE_SCOPE
                )
                if (
                    path in configured_paths
                    and baseline.scope == expected_scope
                    and path not in baseline_by_path
                ):
                    baseline_by_path[path] = baseline

        request_text = str(task.user_input or "")
        named_paths = [path for path in configured_paths if path in request_text]
        selectable = named_paths or list(baseline_by_path)
        if len(selectable) != 1:
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "当前请求没有唯一对应到一份可恢复配置，未生成权限恢复方案。",
                {"candidate_count": len(selectable)},
            )
            return None

        path = selectable[0]
        baseline = baseline_by_path.get(path)
        if baseline is None:
            return None
        check = ConfigBaselineService(self.session, self.registry).compare(baseline.id)
        change = next(
            (
                item
                for item in check.changes_json
                if isinstance(item, dict) and item.get("path") == path
            ),
            None,
        )
        if not _is_repairable_config_mode_change(change):
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "配置基线核验未证明目标仅发生可恢复的权限位漂移，未生成处置方案。",
                {"path": path, "baseline_id": baseline.id, "baseline_check_id": check.id},
            )
            return None

        assert change is not None
        baseline_state = change["baseline"]
        current_state = change["current"]
        target_mode = baseline_state["mode"]
        expected_hash = baseline_state["sha256"]
        dry_run_input = {
            "path": path,
            "target_mode": target_mode,
            "expected_sha256": expected_hash,
            "baseline_id": baseline.id,
            "baseline_check_id": check.id,
            "dry_run": True,
        }
        try:
            self._check_cancelled()
            dry_run = self.registry.call("restore_config_mode", dry_run_input)
        except Exception as exc:
            self.audit.append_event(
                task,
                TaskStatus.SUMMARIZE.value,
                "proposal_skipped",
                "配置权限恢复工具未通过 dry-run 校验，未生成处置方案。",
                {"path": path, "error": str(exc)},
            )
            return None

        proposal = ActionProposal(
            task_id=task.id,
            tool_name="restore_config_mode",
            input_json={**dry_run_input, "dry_run": False},
            risk_level="R3",
            reason=(
                f"{path} 的内容哈希、UID 和 GID 与已确认基线一致，仅权限从 "
                f"{baseline_state['mode']} 漂移为 {current_state['mode']}。批准后仅恢复权限位，"
                "并由独立配置扫描复验。"
            ),
            status="PENDING_APPROVAL",
            dry_run_result_json=dry_run.model_dump(mode="json"),
        )
        self.session.add(proposal)
        self.session.flush()
        self._reconcile_proposal_risk(task, proposal)
        self.audit.append_event(
            task,
            TaskStatus.SUMMARIZE.value,
            "action_proposal_created",
            "根据已确认配置基线生成可审批的权限恢复方案。",
            {
                "proposal_id": proposal.id,
                "tool_name": proposal.tool_name,
                "risk_level": proposal.risk_level,
                "input": proposal.input_json,
                "dry_run": proposal.dry_run_result_json,
            },
        )
        return {
            "action": "config_mode_restore",
            "path": path,
            "target_mode": target_mode,
            "baseline_id": baseline.id,
            "baseline_check_id": check.id,
            "proposal_id": proposal.id,
        }

    def _reconcile_proposal_risk(self, task: Task, proposal: ActionProposal) -> None:
        safety_case = self.safety_cases.create_for_proposal(proposal)
        self.audit.append_event(
            task,
            TaskStatus.SUMMARIZE.value,
            "action_safety_case_created",
            "处置方案已绑定执行范围、前后置验证条件和失败收口策略。",
            {
                "safety_case_id": safety_case.id,
                "proposal_id": proposal.id,
                "tool_name": proposal.tool_name,
                "status": safety_case.status,
                "verifier_tool": safety_case.verifier_tool,
                "case_hash": safety_case.case_hash,
                "scope": safety_case.scope_json,
                "rollback_strategy": safety_case.rollback_strategy_json,
            },
        )
        previous = RiskLevel(task.risk_level)
        proposal_risk = RiskLevel(proposal.risk_level)
        reconciled = max_risk(previous, proposal_risk)
        if reconciled == previous:
            return
        task.risk_level = reconciled.value
        self.audit.append_event(
            task,
            TaskStatus.SUMMARIZE.value,
            "action_risk_reconciled",
            f"处置方案将任务风险归并为 {reconciled.value}。",
            {
                "previous_risk_level": previous.value,
                "proposal_risk_level": proposal_risk.value,
                "final_risk_level": reconciled.value,
                "proposal_id": proposal.id,
                "tool_name": proposal.tool_name,
            },
        )


def get_task(session: Session, task_id: int) -> Task | None:
    return session.execute(select(Task).where(Task.id == task_id)).scalar_one_or_none()


def _collect_large_file_observations(
    observations: list[dict],
) -> tuple[bool, list[dict]]:
    scan_performed = False
    by_path: dict[str, dict] = {}
    for item in observations:
        if item.get("tool_name") != "find_large_files":
            continue
        scan_performed = True
        result = item.get("result")
        if not isinstance(result, dict):
            continue
        raw_items = result.get("observations", [])
        if not isinstance(raw_items, list):
            continue
        for raw_item in raw_items:
            if not isinstance(raw_item, dict):
                continue
            path = raw_item.get("path")
            if not isinstance(path, str) or not path:
                continue
            existing = by_path.get(path)
            if existing is None or _file_size(raw_item) > _file_size(existing):
                by_path[path] = raw_item
    return scan_performed, sorted(by_path.values(), key=_file_size, reverse=True)


def _collect_deleted_open_file_observations(
    observations: list[dict],
) -> tuple[bool, list[dict]]:
    scan_performed = False
    by_inode: dict[tuple[int, int], dict] = {}
    for item in observations:
        if item.get("tool_name") != "deleted_open_files":
            continue
        scan_performed = True
        result = item.get("result")
        if not isinstance(result, dict):
            continue
        raw_items = result.get("observations", [])
        if not isinstance(raw_items, list):
            continue
        for raw_item in raw_items:
            if not isinstance(raw_item, dict):
                continue
            size_bytes = raw_item.get("size_bytes")
            inode = raw_item.get("inode")
            device = raw_item.get("device")
            if (
                not isinstance(size_bytes, (int, float))
                or isinstance(size_bytes, bool)
                or size_bytes <= 0
                or not isinstance(inode, int)
                or not isinstance(device, int)
            ):
                continue
            key = (device, inode)
            existing = by_inode.get(key)
            if existing is None or _file_size(raw_item) > _file_size(existing):
                by_inode[key] = raw_item
    return scan_performed, sorted(
        by_inode.values(),
        key=_file_size,
        reverse=True,
    )


def _summarize_disk_capacity(observations: list[dict]) -> str:
    rows: list[dict] = []
    for item in observations:
        if item.get("tool_name") != "disk_usage":
            continue
        result = item.get("result")
        if not isinstance(result, dict):
            continue
        raw_rows = result.get("observations")
        if isinstance(raw_rows, list):
            rows.extend(row for row in raw_rows if isinstance(row, dict))
    candidates = [
        row
        for row in rows
        if isinstance(row.get("used_percent"), (int, float))
        and not isinstance(row.get("used_percent"), bool)
    ]
    if not candidates:
        return ""
    highest = max(candidates, key=lambda row: float(row["used_percent"]))
    path = str(highest.get("path") or "未知路径")
    details = [
        f"监测路径中 {path} 使用率最高，为 {float(highest['used_percent']):.1f}%"
    ]
    free_bytes = highest.get("free_bytes")
    if isinstance(free_bytes, (int, float)) and not isinstance(free_bytes, bool):
        details.append(f"可用约 {_format_binary_size(float(free_bytes))}")
    inode_percent = highest.get("inode_used_percent")
    if isinstance(inode_percent, (int, float)) and not isinstance(inode_percent, bool):
        details.append(f"inode 使用率 {float(inode_percent):.1f}%")
    return "，".join(details) + "。"


def _format_binary_size(value: float) -> str:
    if value >= 1024**3:
        return f"{value / 1024**3:.1f} GiB"
    return f"{value / 1024**2:.1f} MiB"


def _requests_service_restart(value: str | None) -> bool:
    if not value:
        return False
    return bool(
        re.search(r"(?:帮我|请|立即|执行|批准后|可以)?\s*重启", value, flags=re.IGNORECASE)
        or re.search(r"\brestart\b", value, flags=re.IGNORECASE)
    )


def _requests_config_mode_restore(value: str | None) -> bool:
    if not value:
        return False
    return bool(
        re.search(r"(?:恢复|修复|纠正|还原).{0,12}(?:权限|模式位|mode)", value, flags=re.IGNORECASE)
        or re.search(r"(?:权限|模式位|mode).{0,12}(?:恢复|修复|纠正|还原)", value, flags=re.IGNORECASE)
    )


def _is_lab_config_path(path: str) -> bool:
    return path == "/tmp/opscouncil-lab" or path.startswith("/tmp/opscouncil-lab/")


def _is_repairable_config_mode_change(change: object) -> bool:
    if not isinstance(change, dict):
        return False
    change_types = change.get("change_types")
    baseline = change.get("baseline")
    current = change.get("current")
    if not isinstance(change_types, list) or not isinstance(baseline, dict) or not isinstance(current, dict):
        return False
    if "permission_changed" not in change_types or not set(change_types).issubset(
        {"permission_changed", "metadata_changed"}
    ):
        return False
    expected_hash = baseline.get("sha256")
    return bool(
        baseline.get("exists") is True
        and current.get("exists") is True
        and baseline.get("file_type") == "file"
        and current.get("file_type") == "file"
        and baseline.get("hash_truncated") is False
        and current.get("hash_truncated") is False
        and isinstance(expected_hash, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected_hash)
        and current.get("sha256") == expected_hash
        and baseline.get("uid") == current.get("uid")
        and baseline.get("gid") == current.get("gid")
        and baseline.get("mode") in ALLOWED_CONFIG_MODES
        and current.get("mode") != baseline.get("mode")
    )


def _collect_restartable_service_observations(observations: list[dict]) -> list[dict]:
    by_unit: dict[str, dict] = {}
    for row in _collect_service_observations(observations):
        try:
            unit = validate_restartable_unit(
                row["unit"],
                getattr(settings, "restartable_systemd_units", ()),
            )
        except ValueError:
            continue
        by_unit[unit] = {**row, "unit": unit}
    return list(by_unit.values())


def _collect_service_observations(observations: list[dict]) -> list[dict]:
    by_unit: dict[str, dict] = {}
    for item in observations:
        if item.get("tool_name") != "service_status":
            continue
        result = item.get("result")
        rows = result.get("observations") if isinstance(result, dict) else None
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            raw_unit = row.get("Id") or row.get("unit")
            if not isinstance(raw_unit, str):
                continue
            by_unit[raw_unit] = {
                "unit": raw_unit,
                "load_state": row.get(
                    "load_state",
                    row.get("LoadState", row.get("load")),
                ),
                "active_state": row.get(
                    "active_state",
                    row.get("ActiveState", row.get("active")),
                ),
                "sub_state": row.get(
                    "sub_state",
                    row.get("SubState", row.get("sub")),
                ),
                "main_pid": row.get("main_pid", row.get("ExecMainPID")),
                "result": row.get("result", row.get("Result")),
            }
    return list(by_unit.values())


def _desired_service_state(
    observations: list[dict],
    unit: str,
) -> dict | None:
    for row in reversed(_tool_observation_rows(observations, "service_desired_state")):
        if row.get("unit") == unit:
            return row
    return None


def _service_change_impact(
    observations: list[dict],
    unit: str,
    *,
    action: str,
) -> dict | None:
    for row in reversed(
        _tool_observation_rows(observations, "service_dependency_snapshot")
    ):
        impact = row.get("change_impact")
        if not isinstance(impact, dict):
            continue
        target_units = impact.get("target_units", [])
        if (
            impact.get("action") == action
            and isinstance(target_units, list)
            and unit in target_units
        ):
            return impact
    return None


def _summarize_service_change_impact(observations: list[dict]) -> str:
    relationship_rows = _tool_observation_rows(
        observations,
        "service_dependency_snapshot",
    )
    for row in reversed(relationship_rows):
        impact = row.get("change_impact")
        if not isinstance(impact, dict):
            continue
        action = str(impact.get("action") or "")
        if action == "observe":
            continue
        target_units = [
            str(unit)
            for unit in impact.get("target_units", [])
            if isinstance(unit, str) and unit
        ]
        target = target_units[0] if target_units else "目标服务"
        predicted_units = [
            item
            for item in impact.get("predicted_units", [])
            if isinstance(item, dict)
        ]
        propagated = [
            str(item.get("unit"))
            for item in predicted_units
            if item.get("role") == "PROPAGATED" and item.get("unit")
        ]
        mechanisms = sorted(
            {
                str(item.get("mechanism"))
                for item in predicted_units
                if item.get("role") == "PROPAGATED" and item.get("mechanism")
            }
        )
        predicted_ids = {
            str(item.get("node_id"))
            for item in predicted_units
            if item.get("node_id")
        }
        target_ids = {f"service:{unit}" for unit in target_units}
        ordering_only: set[str] = set()
        for edge in row.get("edges", []):
            if not isinstance(edge, dict) or edge.get("relation") not in {"BEFORE", "AFTER"}:
                continue
            source = str(edge.get("source") or "")
            target_id = str(edge.get("target") or "")
            if source in target_ids:
                peer = target_id
            elif target_id in target_ids:
                peer = source
            else:
                continue
            if peer.startswith("service:") and peer not in predicted_ids:
                ordering_only.add(peer.removeprefix("service:"))

        if propagated:
            propagation_text = (
                f"将通过 {'、'.join(mechanisms) or 'systemd 传播关系'} "
                f"传播至 {len(propagated)} 个服务：{'、'.join(propagated[:3])}"
            )
            if len(propagated) > 3:
                propagation_text += f" 等 {len(propagated)} 个"
        else:
            propagation_text = "未发现会随该动作传播的其他服务"

        ordering_text = ""
        if ordering_only:
            ordering_text = (
                f"；另有 {len(ordering_only)} 个仅具启动顺序关系的单元未计入影响范围"
            )
        client_count = int(impact.get("possible_client_count") or 0)
        gap_count = len(
            [
                item
                for item in impact.get("evidence_gaps", [])
                if isinstance(item, dict)
            ]
        )
        coverage_text = (
            f"当前仍有 {gap_count} 项关系证据缺口，影响范围按部分证据评估，不能据此自动执行"
            if gap_count or impact.get("coverage") != "FULL"
            else "当前关系证据完整"
        )
        action_label = {
            "restart": "重启",
            "stop": "停止",
            "reload": "重载",
        }.get(action, "变更")
        return (
            f"影响预演：{action_label} {target} {propagation_text}{ordering_text}；"
            f"观测到可能受中断影响的当前连接方 {client_count} 个。"
            f"{coverage_text}。本轮未执行系统变更。"
        )
    return ""


def _summarize_service_degradation(observations: list[dict]) -> str:
    health_rows = _tool_observation_rows(observations, "service_health_probe")
    log_rows = _tool_observation_rows(observations, "application_log_query")
    config_rows = _tool_observation_rows(observations, "config_integrity_scan")
    listener_rows = _tool_observation_rows(observations, "network_listeners")
    relationship_rows = _tool_observation_rows(
        observations,
        "service_dependency_snapshot",
    )
    runtime_rows = _tool_observation_rows(observations, "process_runtime_detail")
    health = health_rows[-1] if health_rows else {}
    body = health.get("body_summary")
    body = body if isinstance(body, dict) else {}

    status_code = health.get("status_code")
    latency_ms = health.get("latency_ms")
    service = str(body.get("service") or "目标服务")
    symptom = (
        f"{service} 返回 HTTP {status_code}"
        if isinstance(status_code, int)
        else f"{service} 健康检查未通过"
    )
    if isinstance(latency_ms, int):
        symptom += f"（{latency_ms}ms）"

    records: list[dict] = []
    for row in log_rows:
        raw_records = row.get("records")
        if isinstance(raw_records, list):
            records.extend(item for item in raw_records if isinstance(item, dict))
    timeout_record = next(
        (
            row
            for row in reversed(records)
            if row.get("reason") == "dependency_timeout"
            or row.get("event") == "request_failed"
        ),
        None,
    )
    dependency = str(
        (timeout_record or {}).get("dependency")
        or body.get("dependency")
        or "下游依赖"
    )
    timeout_ms = (timeout_record or {}).get("dependency_timeout_ms")
    observed_ms = (timeout_record or {}).get("observed_latency_ms")

    if timeout_record is not None:
        timing = ""
        if isinstance(observed_ms, (int, float)) and isinstance(timeout_ms, (int, float)):
            observed_value = int(observed_ms)
            timeout_value = int(timeout_ms)
            timing = (
                f"：实际等待 {observed_value}ms，超过 {timeout_value}ms 超时边界"
                if observed_value > timeout_value
                else f"：调用在 {timeout_value}ms 超时边界被中止（计时约 {observed_value}ms）"
            )
        root_cause = f"应用日志把同一请求定位到 {dependency} 依赖超时{timing}"
    else:
        root_cause = "当前尚缺少可关联的应用日志，根因仍需继续补证"

    counter_evidence: list[str] = []
    observed_relationship = any(
        int(row.get("process_count") or 0) > 0
        and int(row.get("listener_count") or 0) > 0
        for row in relationship_rows
    )
    if listener_rows or runtime_rows or observed_relationship:
        counter_evidence.append("进程和监听仍存在，不支持服务进程崩溃")
    config_unchanged = any(
        record.get("event") == "config_metadata_changed"
        and record.get("content_hash_unchanged") is True
        for record in records
    )
    if config_unchanged:
        current_hash_observed = any(
            isinstance(row.get("sha256"), str)
            and len(str(row.get("sha256"))) == 64
            and row.get("hash_truncated") is False
            for row in config_rows
        )
        if current_hash_observed:
            counter_evidence.append(
                "应用日志记录内容哈希未变，独立扫描取得当前 SHA256；"
                "缺少受信任历史基线，现有证据不支持内容漂移但不能完全排除"
            )
        else:
            counter_evidence.append(
                "应用日志记录内容哈希未变，但尚缺独立文件哈希与历史基线核验"
            )

    suffix = "；".join(counter_evidence)
    if suffix:
        suffix = f"。反证显示：{suffix}"
    return f"已复现用户侧症状：{symptom}。{root_cause}{suffix}。本轮仅采集证据，未执行系统变更。"


def _tool_observation_rows(observations: list[dict], tool_name: str) -> list[dict]:
    rows: list[dict] = []
    for item in observations:
        if item.get("tool_name") != tool_name:
            continue
        result = item.get("result")
        raw_rows = result.get("observations") if isinstance(result, dict) else None
        if isinstance(raw_rows, list):
            rows.extend(row for row in raw_rows if isinstance(row, dict))
    return rows


def _summarize_config_integrity(observations: list[dict]) -> str:
    baseline_results = [
        item.get("result")
        for item in observations
        if item.get("tool_name") == "config_baseline_check"
        and isinstance(item.get("result"), dict)
    ]
    baseline_rows = _tool_observation_rows(observations, "config_baseline_check")
    if not baseline_results:
        sampled = [
            row
            for row in _tool_observation_rows(observations, "config_integrity_scan")
            if row.get("exists")
        ]
        if sampled:
            return (
                f"已完成 {len(sampled)} 个配置文件的当前权限、属主、时间戳和 SHA256 安全采样，"
                "但本次证据没有绑定已确认历史基线，不能据此判断是否发生漂移。"
                "建议先核对当前状态并建立确认基线；本轮未返回配置正文，也未执行系统变更。"
            )
        return "当前没有形成可比较的配置证据，暂不能判断漂移；本轮未执行系统变更。"

    summary_fields = [
        result.get("summary_fields")
        for result in baseline_results
        if isinstance(result.get("summary_fields"), dict)
    ]
    unavailable_scopes = [
        str(fields.get("scope") or "LIVE")
        for fields in summary_fields
        if fields.get("baseline_available") is False
    ]
    available_fields = [
        fields
        for fields in summary_fields
        if fields.get("baseline_available") is True
    ]
    sampled_rows = [row for row in baseline_rows if row.get("exists")]
    changed_rows = [
        row
        for row in baseline_rows
        if isinstance(row.get("change_types"), list) and row.get("change_types")
    ]
    material_changes = [
        row
        for row in changed_rows
        if set(row.get("change_types") or [])
        - {"metadata_changed"}
    ]
    metadata_only = [
        row
        for row in changed_rows
        if set(row.get("change_types") or []) == {"metadata_changed"}
    ]

    if material_changes:
        paths = _compact_paths(material_changes)
        content_count = sum(
            "content_changed" in set(row.get("change_types") or [])
            for row in material_changes
        )
        permission_count = sum(
            "permission_changed" in set(row.get("change_types") or [])
            for row in material_changes
        )
        existence_count = sum(
            bool({"added", "missing", "unavailable"} & set(row.get("change_types") or []))
            for row in material_changes
        )
        change_parts = []
        if content_count:
            change_parts.append(f"内容 {content_count} 项")
        if permission_count:
            change_parts.append(f"权限或属主 {permission_count} 项")
        if existence_count:
            change_parts.append(f"存在性 {existence_count} 项")
        return (
            f"已与确认基线比较 {len(sampled_rows)} 个配置文件，发现 {len(material_changes)} 个路径发生实质漂移"
            f"（{'、'.join(change_parts)}）：{paths}。"
            "建议先核对变更单、责任人和生效时间，再决定是否恢复；任何修改仍需重新校验并人工审批。"
            "本轮未返回配置正文，也未执行系统变更。"
        )

    if metadata_only:
        return (
            f"已与确认基线比较 {len(sampled_rows)} 个配置文件，{len(metadata_only)} 个路径仅出现时间戳或解析路径变化："
            f"{_compact_paths(metadata_only)}；内容哈希、权限和属主仍与基线一致。"
            "建议核对系统启动、配置生成或变更记录，当前不建议执行恢复。"
        )

    incomplete = any(fields.get("status") == "incomplete" for fields in available_fields)
    if available_fields and incomplete:
        return (
            f"已与确认基线比较 {len(sampled_rows)} 个配置文件，但部分路径当前不可读取，"
            "证据不完整，暂不判断整体验证通过。建议先恢复只读采集条件后复检；本轮未执行系统变更。"
        )
    if available_fields and not unavailable_scopes:
        return (
            f"已与确认基线比较 {len(sampled_rows)} 个配置文件，内容哈希、权限、属主和存在性均保持一致。"
            "当前无须处置，本轮未返回配置正文，也未执行系统变更。"
        )

    if sampled_rows:
        scope_text = "、".join(dict.fromkeys(unavailable_scopes))
        return (
            f"已完成 {len(sampled_rows)} 个配置文件的当前安全采样，但 {scope_text} 作用域没有覆盖这些路径的确认基线，"
            "因此不能判断漂移。建议由授权运维人员核对当前状态后建立基线；本轮未执行系统变更。"
        )
    return "当前没有形成可比较的配置证据，暂不能判断漂移；本轮未执行系统变更。"


def _compact_paths(rows: list[dict], limit: int = 3) -> str:
    paths = list(
        dict.fromkeys(
            str(row.get("path"))
            for row in rows
            if isinstance(row.get("path"), str) and row.get("path")
        )
    )
    if len(paths) <= limit:
        return "、".join(paths)
    return f"{'、'.join(paths[:limit])} 等 {len(paths)} 个路径"


def _summarize_general_health(observations: list[dict]) -> str:
    results: dict[str, dict] = {}
    for requirement in general_health_core_requirements():
        result = _latest_successful_tool_result(observations, requirement.tool_name)
        if result is not None:
            results[requirement.tool_name] = result
    missing_labels = [
        requirement.label
        for requirement in general_health_core_requirements()
        if requirement.tool_name not in results
    ]
    facts: list[str] = []

    snapshot_rows = _result_rows(results.get("system_snapshot"))
    if snapshot_rows:
        snapshot = snapshot_rows[0]
        memory = snapshot.get("memory")
        memory = memory if isinstance(memory, dict) else {}
        used_percent = memory.get("used_percent")
        loadavg = snapshot.get("loadavg")
        if (
            isinstance(loadavg, (list, tuple))
            and loadavg
            and isinstance(loadavg[0], (int, float))
        ):
            resource = f"1 分钟负载 {float(loadavg[0]):.2f}"
            if isinstance(used_percent, (int, float)) and not isinstance(used_percent, bool):
                resource += f"，内存使用率 {float(used_percent):.1f}%"
            facts.append(resource)

    disk_rows = _result_rows(results.get("disk_usage"))
    root_disk = next((item for item in disk_rows if item.get("path") == "/"), None)
    if root_disk is not None:
        used_percent = root_disk.get("used_percent")
        inode_percent = root_disk.get("inode_used_percent")
        if isinstance(used_percent, (int, float)) and not isinstance(used_percent, bool):
            disk_fact = f"根分区使用率 {float(used_percent):.1f}%"
            if isinstance(inode_percent, (int, float)) and not isinstance(inode_percent, bool):
                disk_fact += f"，inode 使用率 {float(inode_percent):.1f}%"
            facts.append(disk_fact)

    process_rows = _result_rows(results.get("process_list"))
    if "process_list" in results:
        zombie_count = sum(item.get("is_zombie") is True for item in process_rows)
        process_fact = f"僵尸进程 {zombie_count} 个"
        hot_process = max(
            process_rows,
            key=lambda item: _numeric_value(item.get("cpu_percent")),
            default=None,
        )
        if hot_process is not None:
            cpu_percent = _numeric_value(hot_process.get("cpu_percent"))
            command = str(hot_process.get("command") or "未知进程")
            pid = hot_process.get("pid")
            process_fact += f"，当前 CPU 最高为 {command}（PID {pid}，{cpu_percent:.1f}%）"
        facts.append(process_fact)

    service_rows = _tool_observation_rows(observations, "service_status")
    if "service_status" in results:
        sentinel = next(
            (item for item in service_rows if item.get("scope") == "failed_services"),
            None,
        )
        failed_rows = [
            item
            for item in service_rows
            if str(item.get("active_state") or item.get("active") or "").lower()
            == "failed"
        ]
        failed_units = {
            str(item.get("unit"))
            for item in failed_rows
            if isinstance(item.get("unit"), str) and item.get("unit")
        }
        failed_count = (
            int(sentinel.get("failed_count") or 0)
            if sentinel is not None
            else len(failed_units)
        )
        service_fact = f"systemd 失败服务 {failed_count} 个"
        detail = next(
            (
                item
                for item in failed_rows
                if item.get("exec_start_path")
                and isinstance(item.get("exec_main_status"), int)
            ),
            None,
        )
        if detail is not None:
            service_fact += (
                f"；{detail.get('unit')} 的启动入口 {detail.get('exec_start_path')} "
                f"以状态 {detail.get('exec_main_status')} 退出"
            )
            if detail.get("result"):
                service_fact += f"（{detail.get('result')}）"
        facts.append(service_fact)

    network_result = results.get("network_listeners")
    if network_result is not None:
        fields = network_result.get("summary_fields")
        fields = fields if isinstance(fields, dict) else {}
        network_rows = _result_rows(network_result)
        listener_count = _integer_field(fields, "listener_count", len(network_rows))
        exposed_count = sum(
            _integer_field(fields, key, _listener_scope_count(network_rows, scope))
            for key, scope in (
                ("wildcard_listener_count", "wildcard"),
                ("public_listener_count", "public"),
                ("unknown_scope_listener_count", "unknown"),
            )
        )
        unattributed_count = _integer_field(
            fields,
            "unattributed_listener_count",
            sum(item.get("pid") is None for item in network_rows),
        )
        facts.append(
            f"监听端口 {listener_count} 个，其中外部或范围待确认 {exposed_count} 个、"
            f"归属待确认 {unattributed_count} 个"
        )

    time_result = _latest_successful_tool_result(observations, "time_sync_status")
    time_rows = _result_rows(time_result)
    if time_rows:
        synchronized = time_rows[0].get("ntp_synchronized")
        if synchronized is True:
            facts.append("系统时间已同步")
        elif synchronized is False:
            facts.append("系统时间未同步")
        else:
            facts.append("时间同步状态未确认")

    fact_text = "；".join(facts) if facts else "尚未形成有效主机事实摘要"
    if missing_labels:
        missing_text = "、".join(missing_labels)
        return (
            f"已完成部分系统健康只读巡检：{fact_text}。"
            f"{missing_text}未取得有效证据，暂不判断整机健康。未执行系统变更。"
        )
    return f"已完成系统健康只读巡检：{fact_text}。未执行系统变更。"


def _latest_successful_tool_result(
    observations: list[dict],
    tool_name: str,
) -> dict | None:
    for item in reversed(observations):
        if item.get("tool_name") != tool_name:
            continue
        result = item.get("result")
        if not isinstance(result, dict):
            continue
        status = str(result.get("status") or "ok").lower()
        if status not in {"error", "failed", "unavailable", "rejected", "blocked"}:
            return result
    return None


def _result_rows(result: dict | None) -> list[dict]:
    if not isinstance(result, dict):
        return []
    rows = result.get("observations")
    if not isinstance(rows, list):
        return []
    return [item for item in rows if isinstance(item, dict)]


def _numeric_value(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


def _summarize_journal_storage(observations: list[dict]) -> str:
    observation: dict | None = None
    for item in observations:
        if item.get("tool_name") != "journal_storage_status":
            continue
        result = item.get("result")
        if not isinstance(result, dict):
            continue
        raw_observations = result.get("observations")
        if isinstance(raw_observations, list) and raw_observations:
            candidate = raw_observations[0]
            if isinstance(candidate, dict):
                observation = candidate
    if observation is None:
        return ""

    reported_bytes = observation.get("reported_disk_usage_bytes")
    storage = observation.get("storage")
    storage = storage if isinstance(storage, list) else []
    archived_count = sum(
        int(item.get("archived_file_count") or 0)
        for item in storage
        if isinstance(item, dict)
    )
    scan_truncated = any(
        item.get("scan_truncated") is True for item in storage if isinstance(item, dict)
    )
    facts: list[str] = []
    if isinstance(reported_bytes, (int, float)) and not isinstance(reported_bytes, bool):
        facts.append(f"journal 当前占用约 {round(float(reported_bytes) / 1024 / 1024, 2)} MiB")
    facts.append(f"扫描到 {archived_count} 个归档文件" + ("（结果已截断）" if scan_truncated else ""))

    settings_status = observation.get("settings_status")
    settings = observation.get("settings")
    settings = settings if isinstance(settings, dict) else {}
    if settings_status == "no_explicit_settings_found":
        settings_text = "未发现显式留存覆盖，当前证据无法量化默认阈值"
    elif settings:
        selected: list[str] = []
        for key, prefix in (
            ("SystemMaxUse", "持久日志上限"),
            ("RuntimeMaxUse", "运行时日志上限"),
            ("MaxRetentionSec", "最长保留时间"),
        ):
            value = settings.get(key)
            if value:
                selected.append(f"{prefix} {value}")
        settings_text = "；".join(selected) or "已取得显式留存设置"
    else:
        settings_text = "未取得有效留存设置，暂不能判断策略是否符合预期"
    return "，".join(facts) + f"；{settings_text}。"


def _summarize_filesystem_mount(observations: list[dict]) -> str:
    observation: dict | None = None
    for item in observations:
        if item.get("tool_name") != "filesystem_mount_context":
            continue
        result = item.get("result")
        if not isinstance(result, dict):
            continue
        raw_observations = result.get("observations")
        if isinstance(raw_observations, list) and raw_observations:
            candidate = raw_observations[0]
            if isinstance(candidate, dict):
                observation = candidate
    if observation is None:
        return ""
    path = observation.get("resolved_path")
    mount_target = observation.get("mount_target")
    filesystem_type = observation.get("filesystem_type")
    used_percent = observation.get("used_percent")
    if not all(isinstance(value, str) and value for value in (path, mount_target, filesystem_type)):
        return ""
    usage_text = (
        f"，使用率 {float(used_percent):.1f}%"
        if isinstance(used_percent, (int, float)) and not isinstance(used_percent, bool)
        else ""
    )
    network_text = "，网络文件系统" if observation.get("is_network_filesystem") else ""
    readonly_text = "，只读" if observation.get("read_only") else ""
    return (
        f"路径 {path} 位于挂载点 {mount_target}（{filesystem_type}{usage_text}"
        f"{network_text}{readonly_text}）。"
    )


def _file_size(item: dict) -> float:
    value = item.get("size_bytes")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)


def _summarize_network_exposure(result: dict) -> str:
    listeners = result.get("observations", [])
    listeners = listeners if isinstance(listeners, list) else []
    fields = result.get("summary_fields", {})
    fields = fields if isinstance(fields, dict) else {}

    listener_count = _integer_field(fields, "listener_count", len(listeners))
    unattributed_count = _integer_field(
        fields,
        "unattributed_listener_count",
        sum(
            item.get("pid") is None and not str(item.get("process") or "").strip()
            for item in listeners
            if isinstance(item, dict)
        ),
    )
    exposed_count = sum(
        _integer_field(fields, key, _listener_scope_count(listeners, scope))
        for key, scope in (
            ("wildcard_listener_count", "wildcard"),
            ("public_listener_count", "public"),
            ("unknown_scope_listener_count", "unknown"),
        )
    )
    attributed_count = max(0, listener_count - unattributed_count)

    if exposed_count:
        scope_summary = f"发现 {exposed_count} 个公网、全地址或范围未知监听"
    else:
        scope_summary = "当前未发现公网或全地址监听"

    if unattributed_count:
        attribution_summary = (
            f"{listener_count} 个监听中 {attributed_count} 个已关联进程，"
            f"{unattributed_count} 个仍需补充归属"
        )
        next_step = "建议先核对未归属端口的服务来源"
    else:
        attribution_summary = f"{listener_count} 个监听均已关联进程"
        next_step = "建议结合业务清单复核监听必要性"
    return f"{scope_summary}；{attribution_summary}。{next_step}，本轮未修改网络配置。"


def _with_service_catalog_context(
    summary: str,
    network_result: dict,
    catalog_result: dict,
) -> str:
    records = catalog_result.get("observations")
    records = records if isinstance(records, list) else []
    if not records:
        return summary
    listeners = network_result.get("observations")
    listeners = listeners if isinstance(listeners, list) else []
    expected: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        for item in record.get("listener_expectations") or []:
            if not isinstance(item, dict):
                continue
            protocol = str(item.get("protocol") or "").lower()
            port = item.get("port")
            if protocol in {"tcp", "udp"} and isinstance(port, int):
                expected.setdefault((protocol, port), []).append(
                    {
                        **item,
                        "unit_name": record.get("unit_name"),
                    }
                )

    observed: dict[tuple[str, int], list[dict[str, Any]]] = {}
    unmanaged_count = 0
    for listener in listeners:
        if not isinstance(listener, dict):
            continue
        key = _listener_protocol_port(listener)
        if key is None:
            continue
        observed.setdefault(key, []).append(listener)
        if key not in expected:
            unmanaged_count += 1

    in_sync_count = 0
    drift_count = 0
    unknown_count = 0
    for key, expectations in expected.items():
        matched = observed.get(key, [])
        for expectation in expectations:
            if not matched:
                if bool(expectation.get("required", True)):
                    drift_count += 1
                else:
                    in_sync_count += 1
                continue
            expected_unit = str(expectation.get("unit_name") or "")
            owned = [
                item
                for item in matched
                if str(item.get("systemd_unit") or "") == expected_unit
            ]
            if not owned:
                known_other_owner = any(
                    str(item.get("systemd_unit") or "")
                    for item in matched
                )
                if known_other_owner:
                    drift_count += 1
                else:
                    unknown_count += 1
                continue
            allowed_scope = str(expectation.get("allowed_scope") or "")
            actual_scopes = {
                str(item.get("exposure_scope") or "unknown")
                for item in owned
            }
            if "unknown" in actual_scopes:
                unknown_count += 1
            elif any(
                _listener_scope_is_broader(scope, allowed_scope)
                for scope in actual_scopes
            ):
                drift_count += 1
            else:
                in_sync_count += 1

    parts = [f"服务目录核对：{in_sync_count} 个登记监听符合"]
    if drift_count:
        parts.append(f"{drift_count} 个登记要求存在偏差")
    if unknown_count:
        parts.append(f"{unknown_count} 个登记监听归属待确认")
    if unmanaged_count:
        parts.append(f"{unmanaged_count} 个监听尚未纳管")
    catalog_text = "，".join(parts) + "。"
    marker = "本轮未修改网络配置。"
    if summary.endswith(marker):
        return f"{summary[:-len(marker)]}{catalog_text}{marker}"
    return f"{summary} {catalog_text}"


def _with_target_service_catalog_context(
    summary: str,
    catalog_result: dict,
    socket_contexts: list[dict],
) -> str:
    if "observations" not in catalog_result:
        return summary
    targets = {
        (str(item.get("protocol") or "").lower(), int(item["port"]))
        for item in socket_contexts
        if str(item.get("protocol") or "").lower() in {"tcp", "udp"}
        and isinstance(item.get("port"), int)
    }
    records = catalog_result.get("observations")
    records = records if isinstance(records, list) else []
    expectations: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for item in record.get("listener_expectations") or []:
            if not isinstance(item, dict):
                continue
            key = (str(item.get("protocol") or "").lower(), item.get("port"))
            if key in targets:
                expectations.append({**item, "unit_name": record.get("unit_name")})

    if not expectations:
        catalog_text = "服务目录未登记该端口。"
    else:
        results: list[str] = []
        contexts_by_target = {
            (str(item.get("protocol") or "").lower(), item.get("port")): item
            for item in socket_contexts
        }
        for expectation in expectations[:2]:
            protocol = str(expectation.get("protocol") or "").lower()
            port = expectation.get("port")
            unit = str(expectation.get("unit_name") or "登记服务")
            context = contexts_by_target.get((protocol, port), {})
            listeners = context.get("listeners")
            listeners = listeners if isinstance(listeners, list) else []
            if not listeners:
                results.append(
                    f"服务目录期望 {unit} 提供 {protocol.upper()}/{port}，当前未监听"
                )
                continue
            owned = [
                item
                for item in listeners
                if isinstance(item, dict)
                and str(item.get("systemd_unit") or "") == unit
            ]
            allowed_scope = str(expectation.get("allowed_scope") or "")
            scopes = {
                str(item.get("exposure_scope") or "unknown")
                for item in owned
            }
            in_scope = (
                bool(owned)
                and bool(scopes)
                and "unknown" not in scopes
                and not any(
                    _listener_scope_is_broader(scope, allowed_scope)
                    for scope in scopes
                )
            )
            results.append(
                f"{unit} 的 {protocol.upper()}/{port} "
                + ("与服务目录登记一致" if in_scope else "归属或暴露范围与登记不一致")
            )
        catalog_text = "服务目录核对：" + "；".join(results) + "。"

    marker = "本轮未修改网络配置。"
    if summary.endswith(marker):
        return f"{summary[:-len(marker)]}{catalog_text}{marker}"
    return f"{summary} {catalog_text}"


def _listener_protocol_port(
    listener: dict[str, Any],
) -> tuple[str, int] | None:
    protocol = str(listener.get("protocol") or "").lower()
    if protocol.startswith("tcp"):
        protocol = "tcp"
    elif protocol.startswith("udp"):
        protocol = "udp"
    else:
        return None
    address = str(listener.get("local_address") or "")
    if ":" not in address:
        return None
    try:
        port = int(address.rsplit(":", 1)[1])
    except ValueError:
        return None
    return protocol, port


def _listener_scope_is_broader(actual: str, allowed: str) -> bool:
    ranks = {
        "loopback": 0,
        "link_local": 1,
        "private": 2,
        "public": 3,
        "wildcard": 4,
    }
    actual_rank = ranks.get(actual)
    allowed_rank = ranks.get(allowed)
    return (
        actual_rank is not None
        and allowed_rank is not None
        and actual_rank > allowed_rank
    )


def _summarize_targeted_socket(observation: dict) -> str:
    protocol = str(observation.get("protocol") or "").upper()
    port = observation.get("port")
    listener_count = int(observation.get("listener_count") or 0)
    target = f"{protocol}/{port}" if protocol and isinstance(port, int) else "目标端口"
    if listener_count == 0:
        return f"{target} 当前未处于监听状态。本轮未修改网络配置。"

    listeners = observation.get("listeners")
    listeners = listeners if isinstance(listeners, list) else []
    first = listeners[0] if listeners and isinstance(listeners[0], dict) else {}
    scope_labels = {
        "loopback": "回环地址",
        "private": "内网地址",
        "link_local": "链路本地地址",
        "wildcard": "所有地址",
        "public": "公网地址",
        "unknown": "范围未知地址",
    }
    address = first.get("local_address") or "-"
    scope = scope_labels.get(str(first.get("exposure_scope") or "unknown"), "范围未知地址")
    process_name = first.get("process_name")
    pid = first.get("pid")
    user = first.get("user")
    if process_name and isinstance(pid, int):
        owner = f"归属 {process_name}（PID {pid}"
        if user:
            owner += f"，用户 {user}"
        owner += "）"
    else:
        owner = "进程归属尚未完整确认"
    unit = first.get("systemd_unit")
    service = f"服务单元 {unit}" if unit else "未关联 systemd 服务单元"
    count_text = f"，共 {listener_count} 条匹配" if listener_count > 1 else ""
    return (
        f"{target} 当前监听 {address}（{scope}）{count_text}，{owner}，{service}。"
        "本轮未修改网络配置。"
    )


def _summarize_targeted_sockets(observations: list[dict]) -> str:
    rows = [item for item in observations if isinstance(item, dict)]
    active = [item for item in rows if int(item.get("listener_count") or 0) > 0]
    if active:
        return "".join(_summarize_targeted_socket(item) for item in active[:2])

    targets = [
        f"{str(item.get('protocol') or '').upper()}/{item.get('port')}"
        for item in rows
        if item.get("protocol") and isinstance(item.get("port"), int)
    ]
    unique_targets = list(dict.fromkeys(targets))
    if unique_targets:
        return (
            f"{' 与 '.join(unique_targets)} 当前均未处于监听状态。"
            "本轮未修改网络配置。"
        )
    return _summarize_targeted_socket(rows[-1]) if rows else "目标端口未取得有效证据。"


def _request_asks_for_unattributed_listeners(user_input: str | None) -> bool:
    text = re.sub(r"\s+", "", str(user_input or "").lower())
    return "归属" in text and any(
        marker in text
        for marker in ("哪些", "未归属", "没有确认", "未确认", "无法确认")
    )


def _summarize_unattributed_listeners(result: dict) -> str:
    listeners = result.get("observations", [])
    listeners = listeners if isinstance(listeners, list) else []
    unresolved = [
        listener
        for listener in listeners
        if isinstance(listener, dict)
        and listener.get("pid") is None
        and not str(listener.get("process") or "").strip()
    ]
    if not unresolved:
        return "当前监听均已确认进程归属。本轮未修改网络配置。"

    endpoints: list[str] = []
    exposed = False
    for listener in unresolved:
        protocol = str(listener.get("protocol") or "").upper()
        address = str(listener.get("local_address") or "").strip()
        if protocol and address:
            endpoints.append(f"{protocol} {address}")
        exposed = exposed or listener.get("exposure_scope") in {
            "wildcard",
            "public",
            "unknown",
        }
    visible = endpoints[:6]
    suffix = f"等 {len(endpoints)} 条" if len(endpoints) > len(visible) else ""
    endpoint_text = "、".join(visible)
    if suffix:
        endpoint_text = f"{endpoint_text}{suffix}"
    scope_text = (
        "其中存在公网、全地址或范围未知监听，需优先核验"
        if exposed
        else "这些监听均位于内网或回环地址"
    )
    return (
        f"尚未确认进程归属的监听有 {len(unresolved)} 条：{endpoint_text}。"
        f"{scope_text}；建议结合套接字 inode 与宿主网络转发关系继续核验。"
        "本轮未修改网络配置。"
    )


def _request_targets_socket(user_input: str | None, observation: dict) -> bool:
    text = re.sub(r"\s+", "", str(user_input or "").lower())
    port = observation.get("port")
    if isinstance(port, bool) or not isinstance(port, int):
        return False
    port_text = str(port)
    explicit_port = any(
        marker in text
        for marker in (
            f"/{port_text}",
            f":{port_text}",
            f"端口{port_text}",
            f"{port_text}端口",
        )
    )
    if not explicit_port:
        return False
    requested_protocols = {
        protocol for protocol in ("tcp", "udp") if protocol in text
    }
    observed_protocol = str(observation.get("protocol") or "").lower()
    return not requested_protocols or observed_protocol in requested_protocols


def _integer_field(fields: dict, key: str, default: int) -> int:
    value = fields.get(key)
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return max(0, int(value))
    return default


def _listener_scope_count(listeners: list, target_scope: str) -> int:
    return sum(
        str(item.get("exposure_scope") or classify_listener_scope(str(item.get("local_address") or "")))
        == target_scope
        for item in listeners
        if isinstance(item, dict)
    )


def _is_safe_rotation_candidate(path_value: object) -> bool:
    if not isinstance(path_value, str) or not path_value.strip():
        return False
    try:
        path = Path(path_value).resolve()
    except OSError:
        return False
    normalized = str(path)
    protected_prefixes = (
        "/var/log/audit/",
        "/var/log/journal/",
        "/var/log/mysql/",
        "/var/log/mariadb/",
        "/var/log/postgresql/",
        "/var/lib/mysql/",
        "/var/lib/postgresql/",
    )
    if any(normalized == prefix.rstrip("/") or normalized.startswith(prefix) for prefix in protected_prefixes):
        return False
    if normalized.startswith("/tmp/opscouncil-lab/"):
        return True
    return normalized.startswith("/var/log/") and path.suffix == ".log"
