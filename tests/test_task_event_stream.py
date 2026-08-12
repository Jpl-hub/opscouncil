from __future__ import annotations

import asyncio
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.audit.service import AuditService
from backend.app.core.database import get_session
from backend.app.models.entities import (
    AuditChain,
    Conversation,
    ConversationTurn,
    Task,
    TaskEvent,
    TaskJob,
)
from backend.app.runtime.events import read_event_batch, stream_task_events
from backend.app.runtime.intake import TaskIntakeService


TABLES = [
    Task.__table__,
    Conversation.__table__,
    ConversationTurn.__table__,
    TaskEvent.__table__,
    AuditChain.__table__,
    TaskJob.__table__,
]


class TaskEventStreamTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in TABLES:
            table.create(engine)
        self.session_factory = sessionmaker(
            bind=engine,
            autoflush=False,
            expire_on_commit=False,
            future=True,
        )

    def _terminal_task(self) -> tuple[int, list[int]]:
        with self.session_factory() as session:
            accepted = TaskIntakeService(session).accept("检查磁盘")
            second = AuditService(session).append_event(
                accepted.task,
                "PERCEIVE",
                "tool_call",
                "磁盘工具调用完成。",
                {"tool_name": "disk_usage"},
            )
            accepted.task.status = "SEALED"
            third = AuditService(session).append_event(
                accepted.task,
                "SEALED",
                "state_transition",
                "任务审计链封存。",
                {"status": "SEALED"},
            )
            task_id = accepted.task.id
            first = accepted.task.events[0]
            event_ids = [first.id, second.id, third.id]
            session.commit()
        return task_id, event_ids

    def test_batch_is_ordered_and_resumes_after_cursor(self) -> None:
        task_id, event_ids = self._terminal_task()

        with self.session_factory() as session:
            batch = read_event_batch(session, task_id, after_id=event_ids[0])

        self.assertEqual([event["id"] for event in batch.events], event_ids[1:])
        self.assertTrue(batch.terminal)
        self.assertEqual(batch.last_event_id, event_ids[-1])

    def test_async_stream_emits_persisted_events_and_closes_at_terminal_state(self) -> None:
        task_id, event_ids = self._terminal_task()

        async def collect() -> list[str]:
            return [
                chunk
                async for chunk in stream_task_events(
                    self.session_factory,
                    task_id,
                    after_id=event_ids[0],
                    poll_seconds=0.01,
                    heartbeat_seconds=0.02,
                )
            ]

        chunks = asyncio.run(collect())

        body = "".join(chunks)
        self.assertNotIn(f"id: {event_ids[0]}", body)
        self.assertIn(f"id: {event_ids[1]}", body)
        self.assertIn(f"id: {event_ids[2]}", body)
        self.assertIn("event: task_event", body)
        self.assertIn('"event_type":"state_transition"', body)

    def test_http_stream_honors_last_event_id_and_sets_no_buffer_headers(self) -> None:
        task_id, event_ids = self._terminal_task()
        app = FastAPI()
        app.include_router(build_router(object()))  # type: ignore[arg-type]

        def override_session():
            with self.session_factory() as session:
                yield session

        app.dependency_overrides[get_session] = override_session
        with TestClient(app) as client:
            response = client.get(
                f"/api/tasks/{task_id}/stream",
                headers={"Last-Event-ID": str(event_ids[0])},
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/event-stream"))
        self.assertEqual(response.headers["cache-control"], "no-cache")
        self.assertEqual(response.headers["x-accel-buffering"], "no")
        self.assertNotIn(f"id: {event_ids[0]}", response.text)
        self.assertIn(f"id: {event_ids[1]}", response.text)
        self.assertIn(f"id: {event_ids[2]}", response.text)

    def test_unknown_stream_task_returns_404(self) -> None:
        app = FastAPI()
        app.include_router(build_router(object()))  # type: ignore[arg-type]

        def override_session():
            with self.session_factory() as session:
                yield session

        app.dependency_overrides[get_session] = override_session
        with TestClient(app) as client:
            response = client.get("/api/tasks/999/stream")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
