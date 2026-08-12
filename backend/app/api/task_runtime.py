from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.api.task_contracts import (
    TaskCreateRequest,
    TaskRuntimeResponse,
    task_runtime_to_response,
)
from backend.app.core.database import get_session
from backend.app.models.entities import Task, TaskJob
from backend.app.runtime.intake import TaskIntakeService
from backend.app.runtime.queue import TaskQueue
from backend.app.runtime.events import stream_task_events


def build_task_runtime_router() -> APIRouter:
    router = APIRouter()

    @router.post(
        "/tasks",
        response_model=TaskRuntimeResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def create_task(
        payload: TaskCreateRequest,
        session: Session = Depends(get_session),
    ) -> TaskRuntimeResponse:
        try:
            accepted = TaskIntakeService(session).accept(payload.input, payload.conversation_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        response = task_runtime_to_response(accepted.task, accepted.job, session)
        session.commit()
        return response

    @router.post("/tasks/{task_id}/cancel", response_model=TaskRuntimeResponse)
    def cancel_task(
        task_id: int,
        session: Session = Depends(get_session),
    ) -> TaskRuntimeResponse:
        task = session.get(Task, task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")
        try:
            queue_status = TaskQueue(session).request_cancel(task_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        job = session.scalar(select(TaskJob).where(TaskJob.task_id == task_id))
        if job is None:
            raise HTTPException(status_code=404, detail="task job not found")
        response = task_runtime_to_response(task, job, session, queue_status=queue_status)
        session.commit()
        return response

    @router.get("/tasks/{task_id}/stream")
    def stream_task(
        task_id: int,
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
        session: Session = Depends(get_session),
    ) -> StreamingResponse:
        if session.get(Task, task_id) is None:
            raise HTTPException(status_code=404, detail="task not found")
        try:
            cursor = max(int(last_event_id or "0"), 0)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Last-Event-ID must be an integer") from exc
        stream_session_factory = sessionmaker(
            bind=session.get_bind(),
            autoflush=False,
            expire_on_commit=False,
            future=True,
        )
        session.rollback()
        return StreamingResponse(
            stream_task_events(stream_session_factory, task_id, after_id=cursor),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    return router
