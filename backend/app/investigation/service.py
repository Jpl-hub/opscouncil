from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import (
    AIAnalysis,
    ActionProposal,
    ActionSafetyCase,
    AuditChain,
    EvidenceItem,
    ExecutionRecord,
    Hypothesis,
    HypothesisEvidence,
    Investigation,
    InvestigationStep,
    RiskChainAssessment,
    SafetyReview,
    Task,
    TaskEvent,
    ToolCall,
)
from backend.app.investigation.decision_graph import build_decision_view
from backend.app.safety.safety_case import safety_case_to_dict


def build_investigation_package(session: Session, task_id: int) -> dict[str, Any]:
    task = session.get(Task, task_id)
    if task is None:
        raise LookupError("task not found")

    tool_calls = list(
        session.execute(
            select(ToolCall).where(ToolCall.task_id == task.id).order_by(ToolCall.id.asc())
        ).scalars()
    )
    reviews = list(
        session.execute(
            select(SafetyReview).where(SafetyReview.task_id == task.id).order_by(SafetyReview.id.asc())
        ).scalars()
    )
    proposals = list(
        session.execute(
            select(ActionProposal).where(ActionProposal.task_id == task.id).order_by(ActionProposal.id.asc())
        ).scalars()
    )
    safety_cases = list(
        session.scalars(
            select(ActionSafetyCase)
            .where(ActionSafetyCase.task_id == task.id)
            .order_by(ActionSafetyCase.id.asc())
        )
    )
    safety_cases_by_proposal = {
        item.proposal_id: item for item in safety_cases
    }
    executions = list(
        session.execute(
            select(ExecutionRecord).where(ExecutionRecord.task_id == task.id).order_by(ExecutionRecord.id.asc())
        ).scalars()
    )
    analyses = list(
        session.execute(
            select(AIAnalysis).where(AIAnalysis.task_id == task.id).order_by(AIAnalysis.id.desc())
        ).scalars()
    )
    events = list(
        session.execute(
            select(TaskEvent).where(TaskEvent.task_id == task.id).order_by(TaskEvent.id.asc())
        ).scalars()
    )
    chain = list(
        session.execute(
            select(AuditChain).where(AuditChain.trace_id == task.trace_id).order_by(AuditChain.id.asc())
        ).scalars()
    )
    latest_analysis = analyses[0] if analyses else None
    investigation = session.scalar(
        select(Investigation).where(Investigation.task_id == task.id)
    )
    risk_chain = session.scalar(
        select(RiskChainAssessment).where(
            RiskChainAssessment.task_id == task.id
        )
    )
    investigation_steps: list[InvestigationStep] = []
    evidence_items: list[EvidenceItem] = []
    hypotheses: list[Hypothesis] = []
    if investigation is not None:
        investigation_steps = list(
            session.scalars(
                select(InvestigationStep)
                .where(InvestigationStep.investigation_id == investigation.id)
                .order_by(InvestigationStep.iteration.asc())
            )
        )
        evidence_items = list(
            session.scalars(
                select(EvidenceItem)
                .where(EvidenceItem.investigation_id == investigation.id)
                .order_by(EvidenceItem.id.asc())
            )
        )
        hypotheses = list(
            session.scalars(
                select(Hypothesis)
                .where(Hypothesis.investigation_id == investigation.id)
                .order_by(Hypothesis.confidence_score.desc(), Hypothesis.id.asc())
            )
        )
    tool_calls_by_id = {call.id: call for call in tool_calls}
    rollback_plan = _rollback_plan(task, proposals, executions)
    serialized_evidence = (
        [
            _graph_evidence_to_dict(item, tool_calls_by_id.get(item.tool_call_id))
            for item in evidence_items
        ]
        if investigation is not None
        else [_tool_call_to_evidence(call) for call in tool_calls]
    )
    serialized_hypotheses = (
        _graph_hypotheses(session, task, hypotheses, evidence_items)
        if investigation is not None
        else _hypotheses(task, latest_analysis, tool_calls)
    )
    serialized_actions = [
        _proposal_to_action(
            proposal,
            safety_cases_by_proposal.get(proposal.id),
        )
        for proposal in proposals
    ]
    action_lifecycle = _action_lifecycle(
        proposals,
        executions,
        events,
        rollback_plan,
        safety_cases_by_proposal,
    )
    serialized_task = {
        "id": task.id,
        "trace_id": task.trace_id,
        "user_input": task.user_input,
        "intent": task.intent,
        "status": task.status,
        "summary": task.summary,
    }
    evidence_assurance, decision_graph = build_decision_view(
        task=serialized_task,
        evidence_items=serialized_evidence,
        hypotheses=serialized_hypotheses,
        action_options=serialized_actions,
        action_lifecycle=action_lifecycle,
    )

    return {
        "task": serialized_task,
        "risk_level": task.risk_level,
        "risk_chain": (
            {
                "status": risk_chain.status,
                "risk_score": risk_chain.risk_score,
                "chain_type": risk_chain.chain_type,
                "semantic_events": risk_chain.semantic_events_json,
                "matched_task_ids": risk_chain.matched_task_ids_json,
                "resource_refs": risk_chain.resource_refs_json,
                "reason": risk_chain.reason,
                "policy_version": risk_chain.policy_version,
                "created_at": risk_chain.created_at.isoformat(),
            }
            if risk_chain is not None
            else None
        ),
        "stage_state": _stage_state(task, reviews, proposals, executions),
        "role_trace": _build_role_trace(
            task,
            tool_calls,
            reviews,
            proposals,
            executions,
            analyses,
            events,
            chain,
            investigation,
            investigation_steps,
            hypotheses,
        ),
        "investigation_runtime": _investigation_runtime(investigation),
        "investigation_steps": [
            _investigation_step_to_dict(step) for step in investigation_steps
        ],
        "evidence_items": serialized_evidence,
        "evidence_assurance": evidence_assurance,
        "decision_graph": decision_graph,
        "diagnosis": _diagnosis(task, latest_analysis, tool_calls),
        "hypotheses": serialized_hypotheses,
        "safety_gates": [_review_to_gate(review) for review in reviews],
        "action_options": serialized_actions,
        "action_lifecycle": action_lifecycle,
        "rollback_plan": rollback_plan,
        "audit_anchors": {
            "trace_id": task.trace_id,
            "event_count": len(events),
            "chain_entry_count": len(chain),
            "head_hash": chain[-1].event_hash if chain else "",
            "sealed": task.sealed_at is not None or task.status in {"SEALED", "REJECTED", "BLOCKED"},
        },
        "evaluation_refs": _evaluation_refs(task),
    }


def _build_role_trace(
    task: Task,
    tool_calls: list[ToolCall],
    reviews: list[SafetyReview],
    proposals: list[ActionProposal],
    executions: list[ExecutionRecord],
    analyses: list[AIAnalysis],
    events: list[TaskEvent],
    chain: list[AuditChain],
    investigation: Investigation | None,
    investigation_steps: list[InvestigationStep],
    hypotheses: list[Hypothesis],
) -> list[dict[str, Any]]:
    """Expose the existing controlled roles without inventing a second orchestration path."""
    plan_events = [
        event
        for event in events
        if event.event_type in {"intent_resolved", "skill_selected", "plan_created"}
    ]
    trace: list[dict[str, Any]] = [
        {
            "key": "orchestrator",
            "title": "调度",
            "status": "completed" if task.intent not in {"", "unknown"} else "received",
            "basis": "自然语言请求与受控任务意图。",
            "output": f"任务意图：{task.intent or '待解析'}。",
            "constraint": "只允许能力包声明的 MCP 工具进入执行计划。",
            "references": [f"task:{task.id}", *[f"event:{event.id}" for event in plan_events]],
        }
    ]

    if tool_calls:
        failed_calls = [call for call in tool_calls if call.status != "ok"]
        tool_names = "、".join(dict.fromkeys(call.tool_name for call in tool_calls))
        trace.append(
            {
                "key": "perception",
                "title": "感知",
                "status": "partial" if failed_calls else "completed",
                "basis": "已审批的 MCP 工具计划。",
                "output": f"已采集 {len(tool_calls)} 次工具证据：{tool_names}。",
                "constraint": "默认只读；工具输入、输出和版本均进入审计链。",
                "references": [f"tool_call:{call.id}" for call in tool_calls],
            }
        )

    if investigation is not None:
        diagnosis_status = {
            "CONCLUDED": "model_assisted",
            "INCONCLUSIVE": "inconclusive",
            "NEEDS_OPERATOR": "needs_operator",
            "CANCELLED": "cancelled",
            "FAILED": "failed",
        }.get(investigation.status, "investigating")
        trace.append(
            {
                "key": "diagnosis",
                "title": "研判",
                "status": diagnosis_status,
                "basis": "持久化 MCP 证据、知识证据与支持/反驳关系。",
                "output": (
                    f"已完成 {investigation.current_iteration} 轮调查，"
                    f"记录 {len(hypotheses)} 个根因候选。"
                ),
                "constraint": "每轮仅允许能力包内只读工具，置信等级由证据关系计算。",
                "references": [
                    f"investigation:{investigation.id}",
                    *[f"investigation_step:{step.id}" for step in investigation_steps],
                ],
            }
        )
    elif analyses:
        analysis = analyses[0]
        trace.append(
            {
                "key": "diagnosis",
                "title": "研判",
                "status": "model_assisted",
                "basis": "MCP 证据、安全审查与命中的运维知识。",
                "output": f"已生成模型辅助研判：{analysis.model}。",
                "constraint": "模型结论仅作为建议，不具备工具调用或执行权限。",
                "references": [f"analysis:{analysis.id}"],
            }
        )
    elif tool_calls and task.summary:
        trace.append(
            {
                "key": "diagnosis",
                "title": "研判",
                "status": "evidence_summary",
                "basis": "已采集的 MCP 证据。",
                "output": "已形成基于证据的事实摘要。",
                "constraint": "未生成模型结论，不据此执行任何系统变更。",
                "references": [f"tool_call:{call.id}" for call in tool_calls],
            }
        )

    if reviews:
        decisions = {review.decision for review in reviews}
        if decisions & {"REJECT", "BLOCK"}:
            status = "blocked"
        elif "APPROVAL_REQUIRED" in decisions:
            status = "approval_required"
        else:
            status = "passed"
        trace.append(
            {
                "key": "safety",
                "title": "安全",
                "status": status,
                "basis": "意图风险规则、动态参数校验和权限边界。",
                "output": f"已完成 {len(reviews)} 次安全裁决。",
                "constraint": "禁止级请求立即拒绝；副作用动作必须经过审批。",
                "references": [f"safety_review:{review.id}" for review in reviews],
            }
        )

    if proposals or executions:
        proposal_statuses = {proposal.status for proposal in proposals}
        actual_execution_count = _execution_attempt_count(executions)
        if (
            task.status == "NEEDS_OPERATOR"
            and actual_execution_count
            and proposal_statuses & {"BLOCKED", "NEEDS_OPERATOR"}
        ):
            status = (
                "outcome_unknown"
                if "NEEDS_OPERATOR" in proposal_statuses
                else "verification_failed"
            )
        elif "EXECUTED" in proposal_statuses:
            status = "executed"
        elif "PENDING_APPROVAL" in proposal_statuses:
            status = "approval_required"
        elif proposal_statuses & {"REJECTED", "BLOCKED"}:
            status = "blocked"
        else:
            status = "prepared"
        references = [f"proposal:{proposal.id}" for proposal in proposals]
        references.extend(f"execution:{record.id}" for record in executions)
        trace.append(
            {
                "key": "remediation",
                "title": "处置",
                "status": status,
                "basis": "根因候选与安全裁决。",
                "output": f"已生成 {len(proposals)} 项处置方案，实际执行 {actual_execution_count} 次。",
                "constraint": "受限身份执行，副作用工具必须具备审批、dry-run 或回滚证据。",
                "references": references,
            }
        )

    if events or chain:
        sealed = task.sealed_at is not None or task.status in {"SEALED", "REJECTED", "BLOCKED"}
        trace.append(
            {
                "key": "audit",
                "title": "审计",
                "status": "sealed" if sealed else "recording",
                "basis": "任务事件与前序哈希。",
                "output": f"已记录 {len(events)} 条事件、{len(chain)} 条哈希链记录。",
                "constraint": "审计重放必须通过哈希校验，异常链路不可作为可信执行证据。",
                "references": [
                    *[f"event:{event.id}" for event in events],
                    *[f"audit_chain:{entry.id}" for entry in chain],
                ],
            }
        )

    return trace


def _stage_state(
    task: Task,
    reviews: list[SafetyReview],
    proposals: list[ActionProposal],
    executions: list[ExecutionRecord],
) -> dict[str, str]:
    blocked = task.status in {"REJECTED", "BLOCKED"} or any(review.decision == "REJECT" for review in reviews)
    proposal_statuses = {proposal.status for proposal in proposals}
    actual_execution = _execution_attempt_count(executions) > 0
    if (
        task.status == "NEEDS_OPERATOR"
        and actual_execution
        and proposal_statuses & {"BLOCKED", "NEEDS_OPERATOR"}
    ):
        action_state = (
            "outcome_unknown"
            if "NEEDS_OPERATOR" in proposal_statuses
            else "verification_failed"
        )
    elif "EXECUTED" in proposal_statuses:
        action_state = "executed"
    elif "PENDING_APPROVAL" in proposal_statuses:
        action_state = "approval_required"
    else:
        action_state = "not_required"
    return {
        "perception": "done"
        if task.status not in {"RECEIVED", "STATIC_REVIEW", "PLAN"} and not blocked
        else "skipped"
        if blocked
        else "pending",
        "diagnosis": "done" if task.summary else "pending",
        "safety": "blocked" if blocked else "approval_required" if proposals else "passed",
        "action": action_state,
        "audit": "sealed" if task.status in {"SEALED", "REJECTED", "BLOCKED"} else "open",
    }


def _tool_call_to_evidence(call: ToolCall) -> dict[str, Any]:
    output = call.output_json or {}
    observations = output.get("observations", [])
    warnings = output.get("warnings", [])
    refs = output.get("evidence_refs", [])
    summary_fields = output.get("summary_fields", {})
    risk_hints = output.get("risk_hints", [])
    return {
        "evidence_id": call.id,
        "tool_call_id": call.id,
        "tool_name": call.tool_name,
        "tool_version": call.tool_version,
        "status": call.status,
        "risk_level": call.risk_level,
        "duration_ms": call.duration_ms,
        "observation_count": len(observations) if isinstance(observations, list) else 0,
        "summary": _evidence_summary(call.tool_name, observations, warnings, risk_hints),
        "summary_fields": summary_fields if isinstance(summary_fields, dict) else {},
        "risk_hints": risk_hints if isinstance(risk_hints, list) else [],
        "evidence_refs": refs if isinstance(refs, list) else [],
        "warnings": warnings if isinstance(warnings, list) else [],
        "source_type": "MCP",
        "source_key": call.tool_name,
        "title": _TOOL_LABELS.get(call.tool_name, call.tool_name),
        "trust_level": "SYSTEM_OBSERVATION",
    }


def _investigation_runtime(investigation: Investigation | None) -> dict[str, Any] | None:
    if investigation is None:
        return None
    return {
        "id": investigation.id,
        "status": investigation.status,
        "current_iteration": investigation.current_iteration,
        "max_iterations": investigation.max_iterations,
        "max_tool_calls": investigation.max_tool_calls,
        "max_elapsed_ms": investigation.max_elapsed_ms,
        "stop_reason": investigation.stop_reason,
        "started_at": investigation.started_at.isoformat(),
        "completed_at": (
            investigation.completed_at.isoformat()
            if investigation.completed_at is not None
            else None
        ),
    }


def _investigation_step_to_dict(step: InvestigationStep) -> dict[str, Any]:
    decision_json = step.decision_json if isinstance(step.decision_json, dict) else {}
    hypothesis_updates = decision_json.get("hypotheses", [])
    hypothesis_keys = [
        str(item.get("key"))
        for item in hypothesis_updates
        if isinstance(item, dict) and item.get("key")
    ]
    return {
        "id": step.id,
        "iteration": step.iteration,
        "decision": step.decision,
        "status": step.status,
        "provider": step.provider,
        "model": step.model,
        "prompt_hash": step.prompt_hash,
        "hypothesis_keys": hypothesis_keys,
        "requested_tool_name": step.requested_tool_name,
        "requested_arguments": step.requested_arguments_json,
        "tool_call_id": step.tool_call_id,
        "rejection_reason": step.rejection_reason,
        "duration_ms": step.duration_ms,
        "started_at": step.started_at.isoformat(),
        "completed_at": step.completed_at.isoformat() if step.completed_at else None,
    }


def _graph_evidence_to_dict(
    item: EvidenceItem,
    tool_call: ToolCall | None,
) -> dict[str, Any]:
    payload = item.payload_json if isinstance(item.payload_json, dict) else {}
    evidence_ref = payload.get("evidence_ref") or payload.get("source_uri")
    is_observation = ":observation:" in item.source_ref
    return {
        "evidence_id": item.id,
        "tool_call_id": item.tool_call_id,
        "tool_name": tool_call.tool_name if tool_call is not None else None,
        "tool_version": tool_call.tool_version if tool_call is not None else None,
        "status": tool_call.status if tool_call is not None else "ok",
        "risk_level": tool_call.risk_level if tool_call is not None else "R0",
        "duration_ms": tool_call.duration_ms if tool_call is not None else 0,
        "observation_count": 1 if is_observation else 0,
        "summary": item.summary,
        "summary_fields": payload,
        "risk_hints": [],
        "evidence_refs": [str(evidence_ref)] if evidence_ref else [item.source_ref],
        "warnings": payload.get("warnings", []) if isinstance(payload.get("warnings"), list) else [],
        "source_type": item.source_type,
        "source_key": item.source_key,
        "title": item.title,
        "trust_level": item.trust_level,
        "observed_at": item.observed_at.isoformat(),
    }


def _graph_hypotheses(
    session: Session,
    task: Task,
    hypotheses: list[Hypothesis],
    evidence_items: list[EvidenceItem],
) -> list[dict[str, Any]]:
    evidence_by_id = {item.id: item for item in evidence_items}
    result: list[dict[str, Any]] = []
    for hypothesis in hypotheses:
        links = list(
            session.scalars(
                select(HypothesisEvidence)
                .where(HypothesisEvidence.hypothesis_id == hypothesis.id)
                .order_by(HypothesisEvidence.evidence_item_id.asc())
            )
        )
        linked_evidence: list[dict[str, Any]] = []
        for link in links:
            evidence = evidence_by_id.get(link.evidence_item_id)
            if evidence is None:
                continue
            linked_evidence.append(
                {
                    "evidence_id": evidence.id,
                    "relation": link.relation,
                    "rationale": link.rationale,
                    "source": evidence.source_ref,
                    "title": evidence.title,
                    "summary": evidence.summary,
                }
            )
        result.append(
            {
                "key": hypothesis.key,
                "title": hypothesis.title,
                "root_cause": hypothesis.rationale,
                "rationale": hypothesis.rationale,
                "evidence_gap": hypothesis.evidence_gap,
                "status": hypothesis.status,
                "confidence": hypothesis.confidence_level,
                "confidence_score": hypothesis.confidence_score,
                "risk_level": task.risk_level,
                "first_seen_iteration": hypothesis.first_seen_iteration,
                "last_updated_iteration": hypothesis.last_updated_iteration,
                "evidence": linked_evidence,
            }
        )
    return result


def _evidence_summary(
    tool_name: str,
    observations: Any,
    warnings: Any,
    risk_hints: Any,
) -> str:
    count = len(observations) if isinstance(observations, list) else 0
    warning_count = len(warnings) if isinstance(warnings, list) else 0
    if isinstance(risk_hints, list) and risk_hints:
        return str(risk_hints[0])
    tool_label = _TOOL_LABELS.get(tool_name, tool_name)
    if warning_count:
        return f"{tool_label}返回 {count} 条观测，{warning_count} 条提示。"
    return f"{tool_label}返回 {count} 条观测。"


_TOOL_LABELS = {
    "platform_capability_profile": "主机能力画像",
    "system_snapshot": "系统快照",
    "disk_usage": "磁盘用量",
    "find_large_files": "大文件定位",
    "process_list": "进程列表",
    "process_file_handles": "文件句柄检查",
    "process_runtime_detail": "进程运行详情",
    "journal_query": "系统日志查询",
    "journal_storage_status": "日志存储状态",
    "deleted_open_files": "已删除未释放文件",
    "service_status": "服务状态",
    "service_desired_state": "服务期望状态",
    "service_catalog_snapshot": "服务目录快照",
    "network_listeners": "网络监听",
    "socket_process_context": "端口进程归属",
    "service_dependency_snapshot": "服务关系快照",
    "filesystem_mount_context": "文件系统挂载",
    "service_health_probe": "服务健康检查",
    "application_log_query": "应用日志",
    "time_sync_status": "时间同步状态",
    "config_integrity_scan": "配置完整性检查",
    "config_baseline_check": "配置基线比较",
    "file_integrity_state": "文件完整性校验",
    "safe_log_rotate": "日志安全轮转",
    "restore_log_backup": "日志备份恢复",
    "restart_managed_service": "受控服务重启",
    "restore_config_mode": "配置权限恢复",
}


def _hypotheses(task: Task, analysis: AIAnalysis | None, tool_calls: list[ToolCall]) -> list[dict[str, Any]]:
    if analysis is not None:
        result = analysis.result_json or {}
        return [
            {
                "title": str(result.get("conclusion") or task.summary or "任务已完成"),
                "root_cause": str(result.get("root_cause") or task.summary or "暂无模型根因结论"),
                "confidence": "model_assisted",
                "risk_level": str(result.get("risk_level") or task.risk_level),
                "evidence": result.get("evidence_used", []),
            }
        ]
    if task.summary:
        evidence = [
            {
                "evidence_id": call.id,
                "relation": _summary_evidence_relation(call),
                "rationale": _tool_call_to_evidence(call)["summary"],
                "source": f"tool_call:{call.id}",
            }
            for call in tool_calls
        ]
        return [
            {
                "key": "evidence_summary",
                "title": _summary_claim_title(task.intent),
                "root_cause": task.summary,
                "rationale": task.summary,
                "evidence_gap": _summary_evidence_gap(tool_calls),
                "confidence": "rule_based",
                "risk_level": task.risk_level,
                "evidence": evidence,
            }
        ]
    return []


_SUMMARY_CONTEXT_TOOLS = frozenset(
    {
        "platform_capability_profile",
        "system_snapshot",
        "safe_log_rotate",
        "restore_log_backup",
        "restart_managed_service",
        "restore_config_mode",
    }
)
_SUMMARY_CLAIM_TITLES = {
    "disk_pressure_analysis": "磁盘容量与占用来源核对结果",
    "network_exposure_analysis": "实时监听与服务目录核对结果",
    "process_health_analysis": "进程运行状态核对结果",
    "config_integrity_analysis": "关键配置完整性核对结果",
    "log_analysis": "服务状态与日志核对结果",
    "service_degradation_analysis": "服务退化证据核对结果",
}


def _summary_evidence_relation(call: ToolCall) -> str:
    if call.status != "ok" or call.tool_name in _SUMMARY_CONTEXT_TOOLS:
        return "CONTEXT"
    return "SUPPORTS"


def _summary_claim_title(intent: str) -> str:
    return _SUMMARY_CLAIM_TITLES.get(intent, "只读证据核对结果")


def _summary_evidence_gap(tool_calls: list[ToolCall]) -> str:
    has_warning = any(
        isinstance(call.output_json, dict)
        and (
            bool(call.output_json.get("warnings"))
            or bool(call.output_json.get("risk_hints"))
        )
        for call in tool_calls
    )
    if has_warning:
        return "工具提示项仍需定向补证或由责任方核对。"
    return "结论仅覆盖本次采样窗口，持续性变化需结合趋势复核。"


def _diagnosis(
    task: Task,
    analysis: AIAnalysis | None,
    tool_calls: list[ToolCall],
) -> dict[str, Any]:
    if analysis is not None:
        result = analysis.result_json or {}
        return {
            "status": "model_assisted",
            "analysis_id": analysis.id,
            "model": analysis.model,
            "created_at": analysis.created_at.isoformat(),
            "conclusion": str(result.get("conclusion") or task.summary or ""),
            "root_cause": str(result.get("root_cause") or task.summary or ""),
            "risk_level": str(result.get("risk_level") or task.risk_level),
            "reasoning_summary": result.get("reasoning_summary", []),
            "counter_evidence": result.get("counter_evidence", []),
            "evidence": result.get("evidence_used", []),
            "recommended_actions": result.get("recommended_actions", []),
            "residual_risk": str(result.get("residual_risk") or ""),
        }

    blocked = task.status in {"REJECTED", "BLOCKED"}
    evidence = [
        {
            "source": call.tool_name,
            "summary": _tool_call_to_evidence(call)["summary"],
        }
        for call in _prioritize_diagnosis_evidence(task.intent, tool_calls)
    ]
    return {
        "status": "blocked" if blocked else "evidence_summary" if task.summary else "unavailable",
        "analysis_id": None,
        "model": None,
        "created_at": None,
        "conclusion": task.summary or "",
        "root_cause": task.summary or "",
        "risk_level": task.risk_level,
        "reasoning_summary": [],
        "counter_evidence": [],
        "evidence": evidence,
        "recommended_actions": [],
        "residual_risk": "安全护栏已给出最终裁决。" if blocked else "",
    }


_DIAGNOSIS_EVIDENCE_PRIORITY: dict[str, tuple[str, ...]] = {
    "disk_pressure_analysis": (
        "deleted_open_files",
        "find_large_files",
        "journal_storage_status",
        "disk_usage",
        "filesystem_mount_context",
    ),
    "network_exposure_analysis": (
        "socket_process_context",
        "network_listeners",
        "service_catalog_snapshot",
        "service_status",
    ),
    "process_health_analysis": (
        "process_runtime_detail",
        "process_file_handles",
        "process_list",
        "service_status",
    ),
    "config_integrity_analysis": (
        "config_integrity_scan",
        "config_baseline_check",
        "file_integrity_state",
        "service_status",
    ),
    "log_analysis": (
        "service_dependency_snapshot",
        "service_desired_state",
        "service_status",
        "application_log_query",
        "journal_query",
    ),
    "service_degradation_analysis": (
        "service_health_probe",
        "application_log_query",
        "service_dependency_snapshot",
        "service_status",
        "journal_query",
    ),
}


def _prioritize_diagnosis_evidence(
    intent: str,
    tool_calls: list[ToolCall],
    *,
    limit: int = 4,
) -> list[ToolCall]:
    preferred = _DIAGNOSIS_EVIDENCE_PRIORITY.get(intent, ())
    priority = {tool_name: index for index, tool_name in enumerate(preferred)}
    default_rank = len(priority)
    ranked = sorted(
        enumerate(tool_calls),
        key=lambda item: (
            0 if item[1].status != "ok" else 1,
            priority.get(item[1].tool_name, default_rank),
            item[0],
        ),
    )
    return [call for _, call in ranked[:limit]]


def _review_to_gate(review: SafetyReview) -> dict[str, Any]:
    return {
        "id": review.id,
        "review_type": review.review_type,
        "risk_level": review.risk_level,
        "decision": review.decision,
        "reason": review.reason,
        "matched_rules": review.matched_rules_json,
        "created_at": review.created_at.isoformat(),
    }


def _proposal_to_action(
    proposal: ActionProposal,
    safety_case: ActionSafetyCase | None,
) -> dict[str, Any]:
    return {
        "id": proposal.id,
        "tool_name": proposal.tool_name,
        "risk_level": proposal.risk_level,
        "status": proposal.status,
        "reason": proposal.reason,
        "input": proposal.input_json,
        "dry_run_result": proposal.dry_run_result_json,
        "created_at": proposal.created_at.isoformat(),
        "requires_approval": proposal.status == "PENDING_APPROVAL",
        "safety_case": (
            safety_case_to_dict(safety_case)
            if safety_case is not None
            else None
        ),
    }


def _action_lifecycle(
    proposals: list[ActionProposal],
    executions: list[ExecutionRecord],
    events: list[TaskEvent],
    rollback_plan: dict[str, Any],
    safety_cases_by_proposal: dict[int, ActionSafetyCase],
) -> dict[str, Any]:
    primary = next(
        (
            proposal
            for proposal in reversed(proposals)
            if proposal.tool_name != "restore_log_backup"
        ),
        None,
    )
    if primary is None:
        return {"status": "not_required", "tool_name": None, "steps": []}

    safety_case = safety_cases_by_proposal.get(primary.id)
    safety_case_step = _safety_case_step(safety_case)
    pre_event = _proposal_event(events, primary.id, "verification_precondition")
    post_event = _proposal_event(events, primary.id, "verify_result")
    execution = next(
        (record for record in reversed(executions) if record.proposal_id == primary.id),
        None,
    )
    pre_step = _verification_step(
        key="precondition",
        title="执行前校验",
        event=pre_event,
        verifier_payload_key="verifier_tool_call_id",
        pending=primary.status == "PENDING_APPROVAL",
        pending_summary="等待审批后执行独立前置校验。",
    )
    execution_step = _execution_step(primary, execution)
    post_step = _verification_step(
        key="postcondition",
        title="执行后核验",
        event=post_event,
        verifier_payload_key="verifier_tool_call_ids",
        pending=execution is not None and execution.allowed == "true",
        pending_summary="副作用动作已有执行记录，等待独立后置核验。",
    )
    rollback_step = {
        "key": "rollback",
        "title": "回滚证据",
        "status": str(rollback_plan.get("status") or "not_required"),
        "summary": str(rollback_plan.get("summary") or "当前动作无需回滚。"),
        "references": (
            [f"proposal:{rollback_plan['proposal_id']}"]
            if isinstance(rollback_plan.get("proposal_id"), int)
            else []
        ),
        "details": {
            key: rollback_plan[key]
            for key in ("artifact_path", "restore_target")
            if isinstance(rollback_plan.get(key), str)
        },
    }

    if post_event is not None:
        lifecycle_status = "verified" if bool(post_event.payload_json.get("valid")) else "verification_failed"
    elif execution is not None and execution.allowed == "true":
        lifecycle_status = "executed_unverified"
    elif primary.status == "PENDING_APPROVAL":
        lifecycle_status = "approval_required"
    elif primary.status == "NEEDS_OPERATOR":
        lifecycle_status = "outcome_unknown"
    elif primary.status in {"REJECTED", "BLOCKED"}:
        lifecycle_status = "blocked"
    else:
        lifecycle_status = "prepared"
    return {
        "status": lifecycle_status,
        "tool_name": primary.tool_name,
        "proposal_id": primary.id,
        "steps": [
            safety_case_step,
            pre_step,
            execution_step,
            post_step,
            rollback_step,
        ],
    }


def _safety_case_step(
    safety_case: ActionSafetyCase | None,
) -> dict[str, Any]:
    if safety_case is None:
        return {
            "key": "safety_case",
            "title": "执行依据",
            "status": "failed",
            "summary": "处置方案缺少完整执行依据，系统已禁止执行。",
            "references": [],
            "details": {},
        }
    failed = safety_case.status in {
        "BLOCKED",
        "FAILED",
        "NEEDS_OPERATOR",
        "REVOKED",
    }
    declined = safety_case.status == "REJECTED"
    if failed:
        status = "failed"
        summary = "执行依据未通过，系统已停止自动执行。"
    elif declined:
        status = "declined"
        summary = "处置已被拒绝，系统保持原状且未执行变更。"
    else:
        status = "passed"
        summary = "执行范围、前后校验条件和异常处理方式均已确认。"
    return {
        "key": "safety_case",
        "title": "执行依据",
        "status": status,
        "summary": summary,
        "references": [
            f"safety_case:{safety_case.id}",
            f"case_hash:{safety_case.case_hash}",
        ],
        "details": {
            "status": safety_case.status,
            "policy_version": safety_case.policy_version,
            "verifier_tool": safety_case.verifier_tool,
            "scope": safety_case.scope_json,
            "rollback_strategy": safety_case.rollback_strategy_json,
        },
    }


def _proposal_event(
    events: list[TaskEvent],
    proposal_id: int,
    event_type: str,
) -> TaskEvent | None:
    return next(
        (
            event
            for event in reversed(events)
            if event.event_type == event_type
            and isinstance(event.payload_json, dict)
            and event.payload_json.get("proposal_id") == proposal_id
        ),
        None,
    )


def _verification_step(
    *,
    key: str,
    title: str,
    event: TaskEvent | None,
    verifier_payload_key: str,
    pending: bool,
    pending_summary: str,
) -> dict[str, Any]:
    if event is None:
        return {
            "key": key,
            "title": title,
            "status": "pending" if pending else "not_started",
            "summary": pending_summary if pending else "未生成该阶段的持久化证据。",
            "references": [],
            "details": {},
        }
    payload = event.payload_json if isinstance(event.payload_json, dict) else {}
    valid = bool(payload.get("valid"))
    raw_verifier_ids = payload.get(verifier_payload_key)
    verifier_ids = (
        [raw_verifier_ids]
        if isinstance(raw_verifier_ids, int)
        else [item for item in raw_verifier_ids if isinstance(item, int)]
        if isinstance(raw_verifier_ids, list)
        else []
    )
    details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    return {
        "key": key,
        "title": title,
        "status": "passed" if valid else "failed",
        "summary": event.message,
        "references": [f"event:{event.id}", *[f"tool_call:{item}" for item in verifier_ids]],
        "details": {"valid": valid, **details},
    }


def _execution_step(
    proposal: ActionProposal,
    execution: ExecutionRecord | None,
) -> dict[str, Any]:
    if execution is None:
        pending = proposal.status == "PENDING_APPROVAL"
        return {
            "key": "execution",
            "title": "受限执行",
            "status": "pending" if pending else "not_run",
            "summary": "等待人工审批。" if pending else "没有副作用执行记录。",
            "references": [f"proposal:{proposal.id}"],
            "details": {},
        }
    allowed = execution.allowed == "true"
    references = [f"execution:{execution.id}"]
    if execution.tool_call_id is not None:
        references.append(f"tool_call:{execution.tool_call_id}")
    return {
        "key": "execution",
        "title": "受限执行",
        "status": "completed" if allowed else "blocked",
        "summary": execution.reason,
        "references": references,
        "details": {
            "executor_mode": execution.executor_mode,
            "runtime_user": execution.runtime_user,
            "runtime_uid": execution.runtime_uid,
            "target_user": execution.target_user,
            "scope": execution.scope_json if isinstance(execution.scope_json, dict) else {},
        },
    }


def _rollback_plan(
    task: Task,
    proposals: list[ActionProposal],
    executions: list[ExecutionRecord],
) -> dict[str, Any]:
    actual_execution_count = _execution_attempt_count(executions)
    primary_proposal = next(
        (proposal for proposal in reversed(proposals) if proposal.tool_name != "restore_log_backup"),
        None,
    )
    rollback_proposal = next(
        (proposal for proposal in reversed(proposals) if proposal.tool_name == "restore_log_backup"),
        None,
    )
    if rollback_proposal is not None:
        status_map = {
            "PENDING_APPROVAL": "available",
            "EXECUTED": "restored",
            "REJECTED": "declined",
            "BLOCKED": "blocked",
            "NEEDS_OPERATOR": "needs_operator",
        }
        summary_map = {
            "available": "已生成真实备份和恢复 dry-run，等待人工确认是否回滚。",
            "restored": "备份内容已恢复到目标日志，恢复前内容已另行保存。",
            "declined": "运维人员选择保留当前处置结果，本次回滚未执行。",
            "blocked": "回滚未通过安全校验或受限执行策略，目标日志未被恢复。",
            "needs_operator": "恢复动作结果尚未确认，系统不会自动重试；需核对目标与快照证据。",
        }
        status = status_map.get(rollback_proposal.status, "available")
        if status == "blocked" and task.status == "NEEDS_OPERATOR" and actual_execution_count:
            status = "needs_operator"
            summary_map[status] = "恢复动作已经运行但独立验证未通过，需要运维人员核对目标与快照。"
        return {
            "status": status,
            "summary": summary_map[status],
            "execution_count": actual_execution_count,
            "proposal_id": rollback_proposal.id,
            "artifact_path": rollback_proposal.input_json.get("artifact_path"),
            "restore_target": rollback_proposal.input_json.get("restore_target"),
        }
    if primary_proposal is not None and primary_proposal.tool_name == "restart_managed_service":
        if task.status == "NEEDS_OPERATOR" and actual_execution_count:
            return {
                "status": "needs_operator",
                "summary": "服务重启后未通过独立状态核验，系统不会自动重复重启，需人工接管。",
                "execution_count": actual_execution_count,
            }
        return {
            "status": "not_required",
            "summary": (
                "服务已通过独立状态核验；重启动作不生成自动回滚，避免二次变更。"
                if actual_execution_count
                else "服务重启尚未执行；审批拒绝或策略阻断时不会产生系统变更。"
            ),
            "execution_count": actual_execution_count,
        }
    if primary_proposal is not None and primary_proposal.tool_name == "restore_config_mode":
        if task.status == "NEEDS_OPERATOR" and actual_execution_count:
            return {
                "status": "needs_operator",
                "summary": "配置权限修改后未通过独立完整性核验，系统不会恢复到漂移状态，需人工接管。",
                "execution_count": actual_execution_count,
            }
        return {
            "status": "not_required",
            "summary": (
                "权限已恢复到已确认基线；该基线即目标状态，不生成反向回滚。"
                if actual_execution_count
                else "配置权限恢复尚未执行；审批拒绝或策略阻断时不会产生系统变更。"
            ),
            "execution_count": actual_execution_count,
        }
    if (
        task.status == "NEEDS_OPERATOR"
        and actual_execution_count
        and any(
            proposal.status in {"BLOCKED", "NEEDS_OPERATOR"}
            for proposal in proposals
        )
    ):
        return {
            "status": "needs_operator",
            "summary": "副作用动作已经运行但独立验证未通过，不能自动声明回滚路径可用。",
            "execution_count": actual_execution_count,
        }
    if actual_execution_count:
        return {
            "status": "available",
            "summary": "已记录受限执行上下文和备份证据，可复核恢复路径。",
            "execution_count": actual_execution_count,
        }
    if proposals:
        return {
            "status": "approval_required",
            "summary": "动作尚未执行；审批前可查看 dry-run 结果，审批后必须保留备份产物。",
            "execution_count": 0,
        }
    return {"status": "not_required", "summary": "当前任务未执行副作用动作。", "execution_count": 0}


def _execution_attempt_count(executions: list[ExecutionRecord]) -> int:
    return sum(record.allowed == "true" for record in executions)


def _evaluation_refs(task: Task) -> list[dict[str, str]]:
    mapping = {
        "disk_pressure_analysis": ("disk-large-log-e2e", "磁盘大日志定位与处置建议"),
        "network_exposure_analysis": ("network-listener-e2e", "网络暴露面只读分析"),
        "config_integrity_analysis": ("config-drift-e2e", "关键配置漂移只读采样"),
    }
    if task.intent not in mapping:
        return []
    case_id, title = mapping[task.intent]
    return [{"case_id": case_id, "title": title, "source": "lab_evaluation"}]
