from __future__ import annotations

import json
import re
from typing import Any

from backend.app.models.entities import ActionProposal, Task, TaskEvent


MAX_NOTIFICATION_BYTES = 8 * 1024
PROHIBITED_KEY_PARTS = (
    "password",
    "secret",
    "token",
    "authorization",
    "prompt",
    "tool_input",
    "tool_output",
    "arguments",
    "raw",
    "artifact",
    "config_body",
    "log_body",
)
ACTION_LABELS = {
    "safe_log_rotate": "安全轮转日志",
    "restore_log_backup": "从备份恢复日志",
    "restart_managed_service": "重启白名单服务",
    "restore_config_mode": "恢复配置权限",
}
TITLE_BY_KIND = {
    "TASK_ACCEPTED": "运维任务已受理",
    "TASK_RESULT": "运维任务结果",
    "INCIDENT": "巡检发现新事件",
    "INVESTIGATION": "调查形成结论",
    "APPROVAL_REQUEST": "安全处置待审批",
    "EXECUTION": "处置状态更新",
    "VERIFICATION": "独立验证完成",
    "ROLLBACK": "回滚方案待审批",
    "CHANNEL_NOTICE": "协同通道通知",
}


class NotificationPayloadRejectedError(ValueError):
    pass


def redact_text(value: str | None, *, max_chars: int = 500) -> str:
    text = str(value or "")
    text = re.sub(
        r"(?i)\bauthorization\s*[:=]\s*(?:bearer\s+)?[^\s,;]+",
        "Authorization=[已脱敏]",
        text,
    )
    text = re.sub(r"(?i)\bbearer\s+[^\s,;]+", "Bearer [已脱敏]", text)
    text = re.sub(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+",
        lambda match: f"{match.group(1)}=[已脱敏]",
        text,
    )
    text = re.sub(
        r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9_.@+-]+/)*[A-Za-z0-9_.@+-]+",
        "[受保护路径]",
        text,
    )
    text = re.sub(
        r"(?i)(?<![A-Za-z0-9])[A-Z]:\\(?:[^\s\\]+\\)*[^\s\\]+",
        "[受保护路径]",
        text,
    )
    compact = " ".join(text.split())
    if len(compact) <= max_chars:
        return compact
    return f"{compact[: max_chars - 3].rstrip()}..."


def build_task_notification_payload(
    task: Task,
    event: TaskEvent | None,
    *,
    kind: str,
    proposal: ActionProposal | None = None,
) -> dict[str, Any]:
    summary_source = (
        _proposal_evidence_summary(proposal)
        if proposal is not None
        else task.summary
        or (
            "任务已进入持久队列，处理进度可在运维工作台查看。"
            if kind == "TASK_ACCEPTED"
            else "任务状态已更新。"
        )
    )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": kind,
        "title": TITLE_BY_KIND[kind],
        "task_id": task.id,
        "trace_id": task.trace_id,
        "task_status": task.status,
        "risk_level": task.risk_level,
        "summary": redact_text(summary_source, max_chars=360),
        "occurred_at": (event.created_at if event is not None else task.created_at).isoformat(),
    }
    if proposal is not None:
        payload.update(
            {
                "proposal_id": proposal.id,
                "action_label": ACTION_LABELS.get(proposal.tool_name, "受控运维处置"),
                "action_risk_level": proposal.risk_level,
                "action_reason": redact_text(proposal.reason, max_chars=240),
            }
        )
    assert_safe_notification_payload(payload)
    return payload


def _proposal_evidence_summary(proposal: ActionProposal) -> str:
    dry_run = proposal.dry_run_result_json
    if not isinstance(dry_run, dict) or dry_run.get("status") != "ok":
        return "处置建议已形成，当前尚未执行系统变更；批准后仍会重新校验目标与动作指纹。"

    fields = dry_run.get("summary_fields")
    summary_fields = fields if isinstance(fields, dict) else {}
    if proposal.tool_name == "safe_log_rotate":
        reclaim_bytes = summary_fields.get("estimated_reclaim_bytes")
        if isinstance(reclaim_bytes, (int, float)) and not isinstance(reclaim_bytes, bool):
            reclaim_mib = max(float(reclaim_bytes), 0.0) / 1024 / 1024
            return (
                f"干运行已验证日志可备份、压缩并轮转，预计释放约 {reclaim_mib:.1f} MiB；"
                "当前未修改源文件。"
            )
        return "日志轮转方案已通过干运行边界校验；当前未修改源文件。"
    if proposal.tool_name == "restart_managed_service":
        return "重启目标已通过受管范围干运行校验；当前未向 systemd 提交重启。"
    if proposal.tool_name == "restore_config_mode":
        return "配置权限恢复方案已完成基线绑定与干运行校验；当前未修改权限位。"
    if proposal.tool_name == "restore_log_backup":
        return "回滚方案已完成备份产物与目标边界干运行校验；当前未恢复文件。"
    return "处置方案已通过干运行边界校验；当前尚未执行系统变更。"


def assert_safe_notification_payload(payload: dict[str, Any]) -> None:
    _validate_value(payload, path="payload")
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(encoded.encode("utf-8")) > MAX_NOTIFICATION_BYTES:
        raise NotificationPayloadRejectedError("notification payload exceeds 8 KiB")


def _validate_value(value: Any, *, path: str) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            if any(part in normalized for part in PROHIBITED_KEY_PARTS):
                raise NotificationPayloadRejectedError(f"prohibited field at {path}.{key}")
            _validate_value(item, path=f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(item, path=f"{path}[{index}]")
        return
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    raise NotificationPayloadRejectedError(f"unsupported value at {path}")
