from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import time
from typing import AsyncIterator

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.models.entities import Task, TaskEvent
from backend.app.schemas.enums import TaskStatus


TERMINAL_TASK_STATES = {
    TaskStatus.SEALED.value,
    TaskStatus.REJECTED.value,
    TaskStatus.BLOCKED.value,
    TaskStatus.NEEDS_OPERATOR.value,
    TaskStatus.FAILED.value,
    TaskStatus.CANCELLED.value,
    TaskStatus.ROLLED_BACK.value,
}


@dataclass(frozen=True)
class EventBatch:
    events: list[dict[str, object]]
    terminal: bool
    last_event_id: int


def read_event_batch(
    session: Session,
    task_id: int,
    *,
    after_id: int = 0,
    limit: int = 100,
) -> EventBatch:
    task = session.get(Task, task_id)
    if task is None:
        raise LookupError("task not found")
    rows = list(
        session.execute(
            select(TaskEvent)
            .where(TaskEvent.task_id == task_id, TaskEvent.id > max(after_id, 0))
            .order_by(TaskEvent.id.asc())
            .limit(min(max(limit, 1), 500))
        ).scalars()
    )
    events = [_event_payload(event) for event in rows]
    return EventBatch(
        events=events,
        terminal=task.status in TERMINAL_TASK_STATES,
        last_event_id=rows[-1].id if rows else max(after_id, 0),
    )


async def stream_task_events(
    session_factory: sessionmaker[Session],
    task_id: int,
    *,
    after_id: int = 0,
    poll_seconds: float = 0.25,
    heartbeat_seconds: float = 15.0,
) -> AsyncIterator[str]:
    cursor = max(after_id, 0)
    last_output_at = time.monotonic()
    while True:
        with session_factory() as session:
            batch = read_event_batch(session, task_id, after_id=cursor)
        for event in batch.events:
            cursor = int(event["id"])
            yield _format_event(event)
            last_output_at = time.monotonic()
        if batch.terminal:
            return
        now = time.monotonic()
        if not batch.events and now - last_output_at >= heartbeat_seconds:
            yield ": heartbeat\n\n"
            last_output_at = now
        await asyncio.sleep(max(poll_seconds, 0.01))


def _event_payload(event: TaskEvent) -> dict[str, object]:
    return {
        "id": event.id,
        "task_id": event.task_id,
        "stage": event.stage,
        "event_type": event.event_type,
        "message": event.message,
        "payload": event.payload_json,
        "created_at": event.created_at.isoformat(),
    }


def _format_event(event: dict[str, object]) -> str:
    data = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    return f"id: {event['id']}\nevent: task_event\ndata: {data}\n\n"
