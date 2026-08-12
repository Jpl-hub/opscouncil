from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import AuditChain, Task, TaskEvent


ZERO_HASH = "0" * 64


def stable_hash(payload: Any) -> str:
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class AuditService:
    def __init__(
        self,
        session: Session,
        after_append: Callable[[], None] | None = None,
        event_sink: Callable[[Task, TaskEvent], None] | None = None,
    ):
        self.session = session
        self.after_append = after_append
        self.event_sink = event_sink

    def append_event(
        self,
        task: Task,
        stage: str,
        event_type: str,
        message: str,
        payload: dict | None = None,
    ) -> TaskEvent:
        event = TaskEvent(
            task_id=task.id,
            stage=stage,
            event_type=event_type,
            message=message,
            payload_json=payload or {},
        )
        self.session.add(event)
        self.session.flush()

        previous = self.session.execute(
            select(AuditChain)
            .where(AuditChain.trace_id == task.trace_id)
            .order_by(AuditChain.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        prev_hash = previous.event_hash if previous else ZERO_HASH
        payload_hash = stable_hash(
            {
                "event_id": event.id,
                "task_id": task.id,
                "stage": stage,
                "event_type": event_type,
                "message": message,
                "payload": payload or {},
            }
        )
        event_hash = stable_hash({"prev_hash": prev_hash, "payload_hash": payload_hash})
        self.session.add(
            AuditChain(
                trace_id=task.trace_id,
                event_id=event.id,
                prev_hash=prev_hash,
                payload_hash=payload_hash,
                event_hash=event_hash,
            )
        )
        self.session.flush()
        if self.event_sink is not None:
            self.event_sink(task, event)
        if self.after_append is not None:
            self.after_append()
        return event

    def verify_trace(self, trace_id: str) -> dict[str, Any]:
        rows = self.session.execute(
            select(AuditChain, TaskEvent)
            .join(TaskEvent, TaskEvent.id == AuditChain.event_id)
            .where(AuditChain.trace_id == trace_id)
            .order_by(AuditChain.id.asc())
        ).all()
        previous_hash = ZERO_HASH
        entries: list[dict[str, Any]] = []
        valid = True
        for chain, event in rows:
            expected_payload_hash = stable_hash(
                {
                    "event_id": event.id,
                    "task_id": event.task_id,
                    "stage": event.stage,
                    "event_type": event.event_type,
                    "message": event.message,
                    "payload": event.payload_json,
                }
            )
            expected_event_hash = stable_hash(
                {"prev_hash": previous_hash, "payload_hash": expected_payload_hash}
            )
            prev_ok = chain.prev_hash == previous_hash
            payload_ok = chain.payload_hash == expected_payload_hash
            event_ok = chain.event_hash == expected_event_hash
            entry_valid = prev_ok and payload_ok and event_ok
            valid = valid and entry_valid
            entries.append(
                {
                    "chain_id": chain.id,
                    "event_id": event.id,
                    "stage": event.stage,
                    "event_type": event.event_type,
                    "prev_ok": prev_ok,
                    "payload_ok": payload_ok,
                    "event_ok": event_ok,
                    "valid": entry_valid,
                    "stored_event_hash": chain.event_hash,
                    "expected_event_hash": expected_event_hash,
                }
            )
            previous_hash = chain.event_hash
        return {
            "trace_id": trace_id,
            "valid": valid,
            "entry_count": len(entries),
            "head_hash": previous_hash if rows else ZERO_HASH,
            "entries": entries,
        }
