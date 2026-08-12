from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    ExecutionRecord,
    Finding,
    Hypothesis,
    Incident,
    Investigation,
    Task,
    TaskEvent,
)


ACTION_TOOLS = frozenset(
    {
        "safe_log_rotate",
        "restore_log_backup",
        "restart_managed_service",
        "restore_config_mode",
    }
)

EVENT_PRESENTATION: dict[str, tuple[str, str, str]] = {
    "investigation_started": ("INVESTIGATION", "调查启动", "RUNNING"),
    "host_capability_gaps": ("INVESTIGATION", "主机能力缺口", "WARNING"),
    "evidence_quarantined": ("INVESTIGATION", "不可信证据已隔离", "BLOCKED"),
    "investigation_concluded": ("INVESTIGATION", "调查形成结论", "COMPLETED"),
    "investigation_needs_operator": ("INVESTIGATION", "调查转人工处理", "WARNING"),
    "action_safety_case_created": ("DECISION", "执行依据已确认", "COMPLETED"),
    "action_proposal_created": ("DECISION", "处置方案待审批", "PENDING"),
    "rollback_proposal_created": ("DECISION", "回滚方案待审批", "PENDING"),
    "approval_recorded": ("DECISION", "人工审批已记录", "COMPLETED"),
    "execution_policy_denied": ("CHANGE", "受限执行策略已阻断", "BLOCKED"),
    "tool_call_failed": ("CHANGE", "处置执行失败", "FAILED"),
    "verification_precondition": ("VERIFICATION", "执行前证据校验", "COMPLETED"),
    "verify_result": ("VERIFICATION", "执行后独立核验", "COMPLETED"),
}


class IncidentTimelineService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def read(self, incident_id: int) -> dict[str, Any]:
        incident = self.session.get(Incident, incident_id)
        if incident is None:
            raise LookupError("incident not found")
        findings = list(
            self.session.scalars(
                select(Finding)
                .where(Finding.incident_id == incident.id)
                .order_by(Finding.first_observed_at.asc(), Finding.id.asc())
            )
        )
        task = (
            self.session.get(Task, incident.task_id)
            if incident.task_id is not None
            else None
        )
        task_events = (
            list(
                self.session.scalars(
                    select(TaskEvent)
                    .where(TaskEvent.task_id == task.id)
                    .order_by(TaskEvent.created_at.asc(), TaskEvent.id.asc())
                )
            )
            if task is not None
            else []
        )
        proposals = (
            list(
                self.session.scalars(
                    select(ActionProposal)
                    .where(ActionProposal.task_id == task.id)
                    .order_by(ActionProposal.created_at.asc(), ActionProposal.id.asc())
                )
            )
            if task is not None
            else []
        )
        safety_cases = (
            list(
                self.session.scalars(
                    select(ActionSafetyCase)
                    .where(ActionSafetyCase.task_id == task.id)
                    .order_by(ActionSafetyCase.created_at.asc(), ActionSafetyCase.id.asc())
                )
            )
            if task is not None
            else []
        )
        executions = (
            list(
                self.session.scalars(
                    select(ExecutionRecord)
                    .where(ExecutionRecord.task_id == task.id)
                    .order_by(ExecutionRecord.created_at.asc(), ExecutionRecord.id.asc())
                )
            )
            if task is not None
            else []
        )
        hypothesis = self._primary_hypothesis(task)
        events = self._events(
            incident,
            findings,
            task,
            task_events,
            hypothesis,
        )
        actual_executions = [
            item for item in executions if item.allowed == "true"
        ]
        verified_cases = [
            item for item in safety_cases if item.status == "VERIFIED"
        ]
        verification_status = (
            "VERIFIED"
            if verified_cases
            else safety_cases[-1].status
            if safety_cases
            else "NOT_REQUIRED"
        )
        first_change_at = (
            actual_executions[0].created_at if actual_executions else None
        )
        verified_at = (
            verified_cases[-1].updated_at if verified_cases else None
        )
        return {
            "incident": {
                "id": incident.id,
                "host_key": incident.host_key,
                "signal_key": incident.signal_key,
                "severity": incident.severity,
                "status": incident.status,
                "title": incident.title,
                "summary": incident.summary,
                "opened_at": _iso(incident.opened_at),
                "updated_at": _iso(incident.updated_at),
            },
            "correlation": {
                "task_id": task.id if task is not None else None,
                "trace_id": task.trace_id if task is not None else None,
                "root_cause": (
                    {
                        "title": hypothesis.title,
                        "rationale": hypothesis.rationale,
                        "confidence": hypothesis.confidence_level,
                        "score": hypothesis.confidence_score,
                    }
                    if hypothesis is not None
                    else None
                ),
                "proposal_count": len(proposals),
                "change_count": len(actual_executions),
                "verification_status": verification_status,
                "time_to_investigation_seconds": _elapsed_seconds(
                    incident.opened_at,
                    task.created_at if task is not None else None,
                ),
                "time_to_change_seconds": _elapsed_seconds(
                    incident.opened_at,
                    first_change_at,
                ),
                "time_to_verified_seconds": _elapsed_seconds(
                    incident.opened_at,
                    verified_at,
                ),
                "recovery": {
                    "healthy_streak": incident.healthy_streak,
                    "target": incident.recovery_target,
                    "last_healthy_at": _iso(incident.last_healthy_at),
                },
            },
            "events": [
                {key: value for key, value in item.items() if not key.startswith("_")}
                for item in sorted(
                    events,
                    key=lambda item: (_timestamp(item["_at"]), item["_sequence"]),
                )
            ],
        }

    def _primary_hypothesis(self, task: Task | None) -> Hypothesis | None:
        if task is None:
            return None
        investigation = self.session.scalar(
            select(Investigation).where(Investigation.task_id == task.id)
        )
        if investigation is None:
            return None
        return self.session.scalar(
            select(Hypothesis)
            .where(
                Hypothesis.investigation_id == investigation.id,
                Hypothesis.status == "SUPPORTED",
            )
            .order_by(
                Hypothesis.confidence_score.desc(),
                Hypothesis.updated_at.desc(),
                Hypothesis.id.asc(),
            )
            .limit(1)
        )

    def _events(
        self,
        incident: Incident,
        findings: list[Finding],
        task: Task | None,
        task_events: list[TaskEvent],
        hypothesis: Hypothesis | None,
    ) -> list[dict[str, Any]]:
        events = [
            _event(
                key=f"incident:{incident.id}:opened",
                occurred_at=incident.opened_at,
                sequence=0,
                phase="DETECTION",
                title="事件已聚合",
                summary=incident.summary,
                status="OPEN",
                references=[f"incident:{incident.id}"],
                details={"signal_key": incident.signal_key},
            )
        ]
        for finding in findings:
            events.append(
                _event(
                    key=f"finding:{finding.id}:first",
                    occurred_at=finding.first_observed_at,
                    sequence=finding.id,
                    phase="DETECTION",
                    title=finding.title,
                    summary=finding.summary,
                    status=finding.severity,
                    references=[
                        f"finding:{finding.id}",
                        *finding.evidence_refs_json,
                    ],
                    details={
                        "metric": finding.metric_json,
                        "occurrence_count": finding.occurrence_count,
                    },
                )
            )
            if (
                finding.occurrence_count > 1
                and finding.last_observed_at != finding.first_observed_at
            ):
                events.append(
                    _event(
                        key=f"finding:{finding.id}:latest",
                        occurred_at=finding.last_observed_at,
                        sequence=100000 + finding.id,
                        phase="DETECTION",
                        title="异常持续出现",
                        summary=f"同一信号累计出现 {finding.occurrence_count} 次。",
                        status=finding.severity,
                        references=[f"finding:{finding.id}"],
                        details={"occurrence_count": finding.occurrence_count},
                    )
                )
        if task is not None:
            events.append(
                _event(
                    key=f"task:{task.id}:accepted",
                    occurred_at=task.created_at,
                    sequence=200000 + task.id,
                    phase="INVESTIGATION",
                    title="调查任务已受理",
                    summary=task.user_input,
                    status=task.status,
                    references=[f"task:{task.id}", f"trace:{task.trace_id}"],
                    details={"intent": task.intent},
                )
            )
        if hypothesis is not None:
            events.append(
                _event(
                    key=f"hypothesis:{hypothesis.id}:supported",
                    occurred_at=hypothesis.updated_at,
                    sequence=300000 + hypothesis.id,
                    phase="INVESTIGATION",
                    title=hypothesis.title,
                    summary=hypothesis.rationale,
                    status="SUPPORTED",
                    references=[f"hypothesis:{hypothesis.id}"],
                    details={
                        "confidence": hypothesis.confidence_level,
                        "score": hypothesis.confidence_score,
                    },
                )
            )
        for task_event in task_events:
            mapped = _task_event(task_event)
            if mapped is not None:
                events.append(mapped)
        if incident.last_healthy_at is not None:
            events.append(
                _event(
                    key=f"incident:{incident.id}:healthy:{incident.healthy_streak}",
                    occurred_at=incident.last_healthy_at,
                    sequence=900000 + incident.id,
                    phase="RECOVERY",
                    title="健康采样已确认",
                    summary=(
                        f"连续健康采样 {incident.healthy_streak}/"
                        f"{incident.recovery_target}。"
                    ),
                    status=(
                        "COMPLETED"
                        if incident.healthy_streak >= incident.recovery_target
                        else "RUNNING"
                    ),
                    references=[f"incident:{incident.id}"],
                    details={
                        "healthy_streak": incident.healthy_streak,
                        "recovery_target": incident.recovery_target,
                    },
                )
            )
        if incident.closed_at is not None:
            events.append(
                _event(
                    key=f"incident:{incident.id}:closed",
                    occurred_at=incident.closed_at,
                    sequence=1000000 + incident.id,
                    phase="RECOVERY",
                    title="事件已结束",
                    summary=(
                        "连续健康采样达到恢复阈值。"
                        if incident.status == "RESOLVED"
                        else "运维人员已关闭事件。"
                    ),
                    status=incident.status,
                    references=[f"incident:{incident.id}"],
                    details={},
                )
            )
        return events


def _task_event(event: TaskEvent) -> dict[str, Any] | None:
    payload = event.payload_json if isinstance(event.payload_json, dict) else {}
    if event.event_type == "tool_call":
        tool_name = payload.get("tool_name")
        if tool_name not in ACTION_TOOLS:
            return None
        phase, title, status = ("CHANGE", "受限变更已执行", "COMPLETED")
    else:
        presentation = EVENT_PRESENTATION.get(event.event_type)
        if presentation is None:
            return None
        phase, title, status = presentation
        if event.event_type in {"verification_precondition", "verify_result"}:
            valid = payload.get("valid")
            if valid is False:
                status = "FAILED"
            elif valid is True:
                status = "COMPLETED"

    references = [f"event:{event.id}"]
    for key, prefix in (
        ("proposal_id", "proposal"),
        ("tool_call_id", "tool_call"),
        ("action_tool_call_id", "tool_call"),
        ("execution_record_id", "execution"),
        ("safety_case_id", "safety_case"),
    ):
        value = payload.get(key)
        if isinstance(value, int):
            references.append(f"{prefix}:{value}")
    verifier_ids = payload.get("verifier_tool_call_ids")
    if isinstance(verifier_ids, list):
        references.extend(
            f"tool_call:{value}" for value in verifier_ids if isinstance(value, int)
        )
    return _event(
        key=f"task_event:{event.id}",
        occurred_at=event.created_at,
        sequence=400000 + event.id,
        phase=phase,
        title=title,
        summary=event.message,
        status=status,
        references=list(dict.fromkeys(references)),
        details={
            key: payload[key]
            for key in (
                "tool_name",
                "risk_level",
                "valid",
                "decision",
                "case_hash",
            )
            if key in payload
        },
    )


def _event(
    *,
    key: str,
    occurred_at: datetime,
    sequence: int,
    phase: str,
    title: str,
    summary: str,
    status: str,
    references: list[str],
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "key": key,
        "occurred_at": _iso(occurred_at),
        "phase": phase,
        "title": title,
        "summary": summary,
        "status": status,
        "references": references,
        "details": details,
        "_at": occurred_at,
        "_sequence": sequence,
    }


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc(value).isoformat()


def _timestamp(value: datetime) -> float:
    return _as_utc(value).timestamp()


def _as_utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _elapsed_seconds(start: datetime, end: datetime | None) -> int | None:
    if end is None:
        return None
    return max(0, int(_timestamp(end) - _timestamp(start)))
