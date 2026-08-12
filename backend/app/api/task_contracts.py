from __future__ import annotations

from datetime import datetime

from backend.app.core.pydantic_compat import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import ConversationTurn, Task, TaskJob


class TaskCreateRequest(BaseModel):
    input: str = Field(min_length=1, max_length=4000)
    conversation_id: str | None = Field(default=None, min_length=1, max_length=64)


class TaskResponse(BaseModel):
    id: int
    trace_id: str
    user_input: str
    intent: str
    status: str
    risk_level: str
    summary: str | None
    conversation_id: str | None = None
    parent_task_id: int | None = None
    queue_status: str | None = None


class TaskRuntimeResponse(TaskResponse):
    queue_status: str


class ApprovalQueueItemResponse(BaseModel):
    id: int
    task_id: int
    trace_id: str
    user_input: str
    task_status: str
    tool_name: str
    risk_level: str
    reason: str
    status: str
    created_at: datetime


def task_to_response(task: Task, session: Session | None = None) -> TaskResponse:
    turn = None
    job = None
    if session is not None:
        turn = session.execute(
            select(ConversationTurn).where(ConversationTurn.task_id == task.id)
        ).scalar_one_or_none()
        job = session.execute(
            select(TaskJob).where(TaskJob.task_id == task.id)
        ).scalar_one_or_none()
    queue_status = None
    if job is not None:
        queue_status = (
            "CANCEL_REQUESTED"
            if job.status == "RUNNING" and job.cancel_requested_at is not None
            else job.status
        )
    return TaskResponse(
        id=task.id,
        trace_id=task.trace_id,
        user_input=task.user_input,
        intent=task.intent,
        status=task.status,
        risk_level=task.risk_level,
        summary=task.summary,
        conversation_id=turn.conversation_id if turn is not None else None,
        parent_task_id=turn.parent_task_id if turn is not None else None,
        queue_status=queue_status,
    )


def task_runtime_to_response(
    task: Task,
    job: TaskJob,
    session: Session,
    *,
    queue_status: str | None = None,
) -> TaskRuntimeResponse:
    response = task_to_response(task, session)
    payload = response.model_dump()
    payload["queue_status"] = queue_status or job.status
    return TaskRuntimeResponse(**payload)
