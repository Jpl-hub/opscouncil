from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import (
    Investigation,
    ModelInvocation,
    SafetyReview,
    Task,
    ToolCall,
)


def build_task_observability(session: Session, task_id: int) -> dict[str, Any]:
    task = session.get(Task, task_id)
    if task is None:
        raise LookupError("task not found")
    invocations = list(
        session.scalars(
            select(ModelInvocation)
            .where(ModelInvocation.task_id == task.id)
            .order_by(ModelInvocation.id.asc())
        )
    )
    tool_calls = list(
        session.scalars(
            select(ToolCall)
            .where(ToolCall.task_id == task.id)
            .order_by(ToolCall.id.asc())
        )
    )
    investigation = session.scalar(
        select(Investigation).where(Investigation.task_id == task.id)
    )
    reviews = list(
        session.scalars(
            select(SafetyReview)
            .where(SafetyReview.task_id == task.id)
            .order_by(SafetyReview.id.asc())
        )
    )
    model_duration = sum(item.duration_ms for item in invocations)
    tool_duration = sum(item.duration_ms for item in tool_calls)
    task_elapsed = _duration_ms(task.created_at, task.sealed_at or task.updated_at)
    return {
        "task_id": task.id,
        "trace_id": task.trace_id,
        "task_status": task.status,
        "summary": {
            "task_elapsed_ms": task_elapsed,
            "model_duration_ms": model_duration,
            "tool_duration_ms": tool_duration,
            "other_duration_ms": max(task_elapsed - model_duration - tool_duration, 0),
            "model_call_count": len(invocations),
            "model_failure_count": sum(item.status == "FAILED" for item in invocations),
            "tool_call_count": len(tool_calls),
            "tool_failure_count": sum(
                str(item.status).casefold()
                not in {"ok", "success", "succeeded", "partial"}
                for item in tool_calls
            ),
            "tool_partial_count": sum(
                str(item.status).casefold() == "partial" for item in tool_calls
            ),
            "input_tokens": _sum_known(item.input_tokens for item in invocations),
            "output_tokens": _sum_known(item.output_tokens for item in invocations),
            "total_tokens": _sum_known(item.total_tokens for item in invocations),
            "token_accounting_complete": bool(invocations)
            and all(item.total_tokens is not None for item in invocations),
            "investigation_iterations": investigation.current_iteration if investigation else 0,
            "investigation_stop_reason": investigation.stop_reason if investigation else None,
            "duplicate_call_blocked": bool(
                investigation and investigation.stop_reason == "DUPLICATE_TOOL_CALL"
            ),
            "safety_decisions": list(dict.fromkeys(item.decision for item in reviews)),
        },
        "model_invocations": [_invocation_row(item) for item in invocations],
        "tool_calls": [
            {
                "id": item.id,
                "tool_name": item.tool_name,
                "status": item.status,
                "duration_ms": item.duration_ms,
            }
            for item in tool_calls
        ],
    }


def _invocation_row(item: ModelInvocation) -> dict[str, Any]:
    return {
        "id": item.id,
        "stage": item.stage,
        "operation": item.operation,
        "provider": item.provider,
        "model": item.model,
        "status": item.status,
        "duration_ms": item.duration_ms,
        "input_tokens": item.input_tokens,
        "output_tokens": item.output_tokens,
        "total_tokens": item.total_tokens,
        "finish_reason": item.finish_reason,
        "error_category": item.error_category,
        "prompt_hash": item.prompt_hash,
        "created_at": item.created_at.isoformat(),
    }


def _sum_known(values: Iterable[int | None]) -> int | None:
    items = list(values)
    return (
        sum(int(value) for value in items if value is not None)
        if any(value is not None for value in items)
        else None
    )


def _duration_ms(started_at: datetime, ended_at: datetime) -> int:
    return max(int((_as_utc(ended_at) - _as_utc(started_at)).total_seconds() * 1000), 0)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
