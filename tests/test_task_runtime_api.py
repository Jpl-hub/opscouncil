from __future__ import annotations

from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.core.database import get_session
from backend.app.models.entities import (
    AuditChain,
    Conversation,
    ConversationTurn,
    Task,
    TaskEvent,
    TaskJob,
)
from backend.app.runtime.queue import TaskQueue


TABLES = [
    Task.__table__,
    Conversation.__table__,
    ConversationTurn.__table__,
    TaskEvent.__table__,
    AuditChain.__table__,
    TaskJob.__table__,
]


class TaskRuntimeApiTest(unittest.TestCase):
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
        app = FastAPI()
        app.include_router(build_router(object()))  # type: ignore[arg-type]

        def override_session():
            with self.session_factory() as session:
                try:
                    yield session
                    session.commit()
                except Exception:
                    session.rollback()
                    raise

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()

    def test_create_returns_202_and_never_invokes_agent_runner(self) -> None:
        with patch(
            "backend.app.agent.runner.AgentRunner.run",
            side_effect=AssertionError("Agent must not run in the API process"),
        ):
            response = self.client.post("/api/tasks", json={"input": "检查当前主机监听端口"})

        self.assertEqual(response.status_code, 202)
        body = response.json()
        self.assertEqual(body["status"], "RECEIVED")
        self.assertEqual(body["queue_status"], "QUEUED")
        self.assertIsNotNone(body["conversation_id"])
        immediate_read = self.client.get(f"/api/tasks/{body['id']}")
        self.assertEqual(immediate_read.status_code, 200)
        self.assertEqual(immediate_read.json()["queue_status"], "QUEUED")
        with self.session_factory() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(Task)), 1)
            job = session.scalar(select(TaskJob))
            assert job is not None
            self.assertEqual(job.status, "QUEUED")
            event_types = list(session.scalars(select(TaskEvent.event_type)))
        self.assertEqual(event_types, ["task_created"])

    def test_follow_up_reuses_conversation_and_unknown_conversation_rolls_back(self) -> None:
        first = self.client.post("/api/tasks", json={"input": "检查 8080 端口"}).json()

        follow_up = self.client.post(
            "/api/tasks",
            json={"input": "它由哪个进程监听？", "conversation_id": first["conversation_id"]},
        )
        missing = self.client.post(
            "/api/tasks",
            json={"input": "继续检查", "conversation_id": "missing-conversation"},
        )

        self.assertEqual(follow_up.status_code, 202)
        self.assertEqual(follow_up.json()["conversation_id"], first["conversation_id"])
        self.assertEqual(follow_up.json()["parent_task_id"], first["id"])
        self.assertEqual(missing.status_code, 404)
        with self.session_factory() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(Task)), 2)
            self.assertEqual(session.scalar(select(func.count()).select_from(TaskJob)), 2)

    def test_cancel_queued_task_is_immediate_and_idempotent(self) -> None:
        accepted = self.client.post("/api/tasks", json={"input": "检查磁盘空间"}).json()

        first = self.client.post(f"/api/tasks/{accepted['id']}/cancel")
        second = self.client.post(f"/api/tasks/{accepted['id']}/cancel")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["status"], "CANCELLED")
        self.assertEqual(first.json()["queue_status"], "CANCELLED")
        self.assertEqual(second.json()["queue_status"], "CANCELLED")

    def test_cancel_running_task_sets_cooperative_signal(self) -> None:
        accepted = self.client.post("/api/tasks", json={"input": "检查进程"}).json()
        with self.session_factory() as session:
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == accepted["id"]))
            assert job is not None
            job.available_at = datetime(2026, 7, 11, tzinfo=timezone.utc)
            session.flush()
            TaskQueue(session).claim_next(
                "worker-api-test",
                now=datetime(2026, 7, 11, tzinfo=timezone.utc),
            )
            session.commit()

        response = self.client.post(f"/api/tasks/{accepted['id']}/cancel")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["queue_status"], "CANCEL_REQUESTED")
        with self.session_factory() as session:
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == accepted["id"]))
            assert job is not None
            self.assertIsNotNone(job.cancel_requested_at)

    def test_cancel_unknown_task_returns_404(self) -> None:
        response = self.client.post("/api/tasks/999/cancel")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
