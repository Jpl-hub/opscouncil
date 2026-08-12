from __future__ import annotations

from typing import Any, Iterable, Mapping


STAGE_GROUPS = [
    {
        "key": "receive",
        "label": "接收指令",
        "stages": {"RECEIVED"},
        "description": "记录原始自然语言请求和会话入口。",
    },
    {
        "key": "safety",
        "label": "安全校验",
        "stages": {"STATIC_REVIEW", "DYNAMIC_REVIEW", "APPROVAL_REQUIRED", "REJECTED", "BLOCKED"},
        "description": "复核意图风险、审批门禁和动态执行策略。",
    },
    {
        "key": "plan",
        "label": "意图规划",
        "stages": {"PLAN"},
        "description": "模型解析意图并生成受控工具计划。",
    },
    {
        "key": "perceive",
        "label": "环境感知",
        "stages": {"PERCEIVE"},
        "description": "通过 MCP 工具采集操作系统实时证据。",
    },
    {
        "key": "investigate",
        "label": "根因调查",
        "stages": {"INVESTIGATE"},
        "description": "在预算约束内检索知识、验证假设并补充证据。",
    },
    {
        "key": "execute",
        "label": "代理执行",
        "stages": {"DRY_RUN", "EXECUTE", "VERIFY", "ROLLED_BACK"},
        "description": "在最小权限边界内执行、核验和回滚。",
    },
    {
        "key": "seal",
        "label": "总结封存",
        "stages": {"SUMMARIZE", "SEALED", "FAILED", "NEEDS_OPERATOR", "CANCELLED", "AI_ANALYSIS"},
        "description": "汇总结果、智能研判并封存可验证审计链。",
    },
]


EVENT_LABELS = {
    "task_created": "请求接收",
    "state_transition": "阶段切换",
    "safety_review": "安全校验",
    "approval_gate": "审批门禁",
    "approval_recorded": "审批记录",
    "intent_resolved": "意图解析",
    "skill_selected": "能力包治理",
    "skill_policy_rejected": "能力包拒绝",
    "plan_created": "计划生成",
    "tool_call": "工具调用",
    "summary_created": "结果总结",
    "assistant_reply_created": "对话答复",
    "analysis_created": "智能研判",
    "ai_analysis_created": "智能研判",
    "ai_analysis_failed": "智能研判失败",
    "evidence_risk_assessed": "证据风险协调",
    "investigation_evidence_risk_assessed": "调查证据风险协调",
    "risk_level_raised": "风险上调",
    "action_risk_reconciled": "处置风险协调",
    "proposal_created": "处置建议",
    "action_proposal_created": "处置建议",
    "proposal_skipped": "无需处置",
    "rollback_proposal_created": "回滚方案",
    "rollback_proposal_skipped": "回滚跳过",
    "trace_sealed": "审计封存",
    "worker_started": "任务执行器开始处理",
    "worker_execution_failed": "任务执行器处理失败",
    "worker_lease_expired": "任务执行器租约过期",
    "task_cancel_requested": "请求取消任务",
    "task_cancelled": "任务已取消",
    "tool_call_failed": "工具调用失败",
    "tool_call_outcome_unknown": "执行结果待核验",
    "execution_policy_denied": "执行策略拒绝",
    "verification_precondition": "执行前校验",
    "verify_result": "执行后校验",
    "investigation_started": "开始调查",
    "investigation_depth_selected": "选择研判深度",
    "investigation_decision": "调查决策",
    "evidence_obligation_enforced": "结论前补证",
    "investigation_evidence_collected": "补充证据",
    "investigation_concluded": "形成根因",
    "investigation_stopped": "停止调查",
    "investigation_needs_operator": "转人工处理",
    "investigation_cancelled": "取消调查",
    "evidence_quarantined": "隔离非可信证据",
    "knowledge_evidence_retrieved": "检索运维知识",
    "knowledge_rag_unavailable": "知识检索不可用",
    "operational_memory_unavailable": "运维经验不可用",
    "memory_draft_created": "运维经验草案",
    "memory_confirmed": "运维经验确认",
    "memory_correction_drafted": "运维经验修订",
    "operator_feedback_recorded": "运维反馈",
    "patrol_incident_created": "巡检事件接入",
    "tool_plan_empty": "无需调用工具",
    "benchmark_proposal_retired": "评测建议回收",
    "intent_model_failed": "模型异常",
    "intent_model_unconfigured": "模型未配置",
    "diagnostic_bundle_exported": "诊断包导出",
}


TOOL_LABELS = {
    "system_snapshot": "系统快照",
    "disk_usage": "磁盘用量",
    "find_large_files": "大文件定位",
    "process_list": "进程列表",
    "process_file_handles": "文件句柄",
    "journal_query": "日志查询",
    "journal_scan": "日志扫描",
    "service_status": "服务状态",
    "network_listeners": "网络监听",
    "service_dependency_snapshot": "服务关系快照",
    "port_scan": "监听端口",
    "config_integrity_scan": "配置完整性",
    "config_baseline_check": "配置基线比较",
    "config_integrity": "配置完整性",
    "performance_baseline": "工具性能采样",
    "safe_log_rotate": "日志安全轮转",
    "restore_log_backup": "日志备份恢复",
    "restart_managed_service": "受控服务重启",
    "restore_config_mode": "配置权限恢复",
    "file_integrity_state": "文件完整性校验",
    "process_runtime_detail": "进程运行详情",
    "journal_storage_status": "日志存储状态",
    "socket_process_context": "端口进程归属",
    "filesystem_mount_context": "文件系统挂载",
    "time_sync_status": "时间同步状态",
    "service_health_probe": "服务健康检查",
    "application_log_query": "应用日志",
}


INTENT_LABELS = {
    "disk_pressure_analysis": "磁盘空间分析",
    "process_health_analysis": "进程健康检查",
    "log_analysis": "系统日志分析",
    "network_exposure_analysis": "网络暴露面分析",
    "config_integrity_analysis": "配置完整性检查",
    "general_system_health": "系统健康巡检",
    "service_degradation_analysis": "服务退化诊断",
    "agent_capability_help": "能力咨询",
    "model_unconfigured": "模型服务未配置",
    "model_intent_failed": "模型意图解析失败",
    "unknown": "未识别请求",
}


VALUE_LABELS = {
    "ALLOW": "允许",
    "REJECT": "拒绝",
    "BLOCK": "阻断",
    "APPROVAL_REQUIRED": "等待审批",
    "NEEDS_OPERATOR": "等待人工处理",
    "SEALED": "已封存",
    "FAILED": "失败",
    "CANCELLED": "已取消",
    "PENDING_APPROVAL": "等待审批",
    "ok": "正常",
    "error": "异常",
    "running": "执行中",
    "COLLECT": "继续取证",
    "CONCLUDE": "形成结论",
}


COMPONENT_BY_EVENT = {
    "task_created": "运维工作台",
    "safety_review": "安全护栏",
    "approval_gate": "审批门禁",
    "approval_recorded": "审批门禁",
    "intent_resolved": "模型意图解析",
    "skill_selected": "Agent Skill",
    "skill_policy_rejected": "Agent Skill",
    "plan_created": "Agent Planner",
    "summary_created": "运维 Agent",
    "assistant_reply_created": "对话引擎",
    "analysis_created": "智能研判",
    "ai_analysis_created": "智能研判",
    "ai_analysis_failed": "智能研判",
    "evidence_risk_assessed": "安全护栏",
    "investigation_evidence_risk_assessed": "安全护栏",
    "risk_level_raised": "安全护栏",
    "action_risk_reconciled": "安全护栏",
    "state_transition": "状态机",
    "worker_started": "任务执行器",
    "worker_execution_failed": "任务执行器",
    "worker_lease_expired": "任务执行器",
    "task_cancel_requested": "任务队列",
    "task_cancelled": "任务队列",
    "investigation_started": "调查控制器",
    "investigation_depth_selected": "调查控制器",
    "investigation_decision": "调查控制器",
    "evidence_obligation_enforced": "证据义务控制器",
    "investigation_evidence_collected": "调查控制器",
    "investigation_concluded": "调查控制器",
    "investigation_stopped": "调查控制器",
    "investigation_needs_operator": "调查控制器",
    "investigation_cancelled": "调查控制器",
    "evidence_quarantined": "证据隔离器",
    "knowledge_evidence_retrieved": "知识检索",
    "knowledge_rag_unavailable": "知识检索",
    "operational_memory_unavailable": "运维经验",
    "memory_draft_created": "运维经验库",
    "memory_confirmed": "运维经验库",
    "memory_correction_drafted": "运维经验库",
    "operator_feedback_recorded": "运维经验库",
    "patrol_incident_created": "自动巡检",
    "tool_plan_empty": "Agent Planner",
    "benchmark_proposal_retired": "OpsBench",
    "diagnostic_bundle_exported": "证据管理",
}


def build_audit_replay(
    trace_id: str,
    events: Iterable[Mapping[str, Any]],
    verification: Mapping[str, Any] | None,
) -> dict[str, Any]:
    event_list = list(events)
    verification = verification or {}
    verification_entries = {
        int(entry["event_id"]): entry
        for entry in verification.get("entries", [])
        if isinstance(entry, Mapping) and "event_id" in entry
    }

    rows = [
        _event_to_replay_row(index + 1, event, verification_entries.get(int(event["id"])))
        for index, event in enumerate(event_list)
    ]
    stages = [_build_stage(group, rows) for group in STAGE_GROUPS]
    failed_event_count = sum(1 for entry in verification_entries.values() if entry.get("valid") is False)

    return {
        "trace_id": trace_id,
        "current_stage": _current_stage(rows),
        "integrity": {
            "valid": bool(verification.get("valid", False)) if verification else False,
            "entry_count": int(verification.get("entry_count", 0) or 0),
            "event_count": len(event_list),
            "failed_event_count": failed_event_count,
            "head_hash": verification.get("head_hash", ""),
        },
        "stages": stages,
        "decision_points": _decision_points(rows),
    }


def _event_to_replay_row(
    order: int,
    event: Mapping[str, Any],
    verification_entry: Mapping[str, Any] | None,
) -> dict[str, Any]:
    event_type = str(event.get("event_type", ""))
    payload = event.get("payload", {})
    payload = payload if isinstance(payload, Mapping) else {}
    return {
        "order": order,
        "event_id": event.get("id"),
        "stage": str(event.get("stage", "")),
        "event_type": event_type,
        "label": EVENT_LABELS.get(event_type, "系统事件"),
        "component": _component(event_type, payload),
        "message": str(event.get("message", "")),
        "payload": dict(payload),
        "created_at": event.get("created_at"),
        "valid": verification_entry.get("valid") if verification_entry else None,
        "hash": _short_hash(verification_entry.get("stored_event_hash") if verification_entry else None),
    }


def _build_stage(group: Mapping[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    stage_names = group["stages"]
    events = [row for row in rows if row["stage"] in stage_names]
    return {
        "key": group["key"],
        "label": group["label"],
        "description": group["description"],
        "status": _stage_status(group, events, rows),
        "event_count": len(events),
        "events": events,
    }


def _stage_status(
    group: Mapping[str, Any],
    events: list[dict[str, Any]],
    all_rows: list[dict[str, Any]],
) -> str:
    if not events:
        if group["key"] == "investigate" and any(
            row["stage"] in {"DRY_RUN", "EXECUTE", "VERIFY", "SUMMARIZE", "AI_ANALYSIS", "SEALED"}
            for row in all_rows
        ):
            return "skipped"
        if group["key"] == "execute" and any(
            row["stage"] in {"SUMMARIZE", "AI_ANALYSIS", "SEALED"} for row in all_rows
        ):
            return "skipped"
        return "pending"
    valid_states = [event["valid"] for event in events]
    if any(valid is False for valid in valid_states):
        return "failed"
    if all(valid is True for valid in valid_states):
        return "passed"
    return "pending"


def _current_stage(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "等待事件"
    latest_stage = rows[-1]["stage"]
    for group in STAGE_GROUPS:
        if latest_stage in group["stages"]:
            return str(group["label"])
    return latest_stage


def _decision_points(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for row in rows:
        payload = row["payload"]
        if row["event_type"] not in {
            "safety_review",
            "approval_gate",
            "approval_recorded",
            "intent_resolved",
            "skill_selected",
            "skill_policy_rejected",
            "plan_created",
            "evidence_risk_assessed",
            "investigation_evidence_risk_assessed",
            "investigation_decision",
            "evidence_obligation_enforced",
            "investigation_concluded",
            "investigation_stopped",
            "investigation_needs_operator",
            "proposal_created",
            "action_proposal_created",
            "rollback_proposal_created",
            "analysis_created",
            "ai_analysis_created",
        }:
            continue
        selected.append(
            {
                "order": row["order"],
                "label": row["label"],
                "component": row["component"],
                "decision": _decision_text(row["event_type"], payload),
                "risk_level": payload.get("risk_level") or payload.get("final_risk_level") or "-",
                "message": row["message"],
                "hash": row["hash"],
                "valid": row["valid"],
            }
        )
    return selected[:10]


def _component(event_type: str, payload: Mapping[str, Any]) -> str:
    tool_name = payload.get("tool_name")
    if isinstance(tool_name, str) and tool_name:
        return TOOL_LABELS.get(tool_name, tool_name)
    return COMPONENT_BY_EVENT.get(event_type, "运维 Agent")


def _decision_text(event_type: str, payload: Mapping[str, Any]) -> str:
    if event_type == "intent_resolved":
        decision = payload.get("decision")
        if isinstance(decision, Mapping):
            return _display_value(decision.get("intent") or decision.get("action") or decision.get("decision"))
    if event_type == "skill_selected":
        return _string_value(payload.get("skill_name") or payload.get("skill_id") or "-")
    if event_type == "skill_policy_rejected":
        return _string_value(payload.get("reason") or payload.get("intent") or "-")
    if event_type == "plan_created":
        return _display_value(payload.get("intent") or payload.get("plan") or "-")
    if event_type in {"evidence_risk_assessed", "investigation_evidence_risk_assessed"}:
        return _display_value(payload.get("final_risk_level") or payload.get("evidence_risk_level") or "-")
    if event_type == "investigation_decision":
        return _display_value(payload.get("decision") or "-")
    if event_type == "evidence_obligation_enforced":
        obligation = payload.get("obligation")
        if isinstance(obligation, Mapping):
            return _string_value(obligation.get("title") or obligation.get("key") or "-")
        return "补齐独立证据"
    if event_type == "investigation_concluded":
        return "形成结论"
    if event_type == "investigation_stopped":
        return "调查停止"
    if event_type == "investigation_needs_operator":
        return "转人工处理"
    if event_type in {"proposal_created", "action_proposal_created", "rollback_proposal_created"}:
        return _display_value(payload.get("tool_name") or payload.get("action") or "-")
    if event_type in {"analysis_created", "ai_analysis_created"}:
        return _string_value(payload.get("model") or payload.get("provider") or "-")
    return _display_value(payload.get("decision") or payload.get("status") or payload.get("tool_name") or "-")


def _display_value(value: Any) -> str:
    if isinstance(value, str) and value:
        return INTENT_LABELS.get(value) or TOOL_LABELS.get(value) or VALUE_LABELS.get(value) or value
    return _string_value(value)


def _string_value(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    if value is None:
        return "-"
    if isinstance(value, (int, float, bool)):
        return str(value)
    return "-"


def _short_hash(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "-"
    return value[:12]
