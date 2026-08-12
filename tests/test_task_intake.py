from __future__ import annotations

import unittest

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.agent.conversation import ConversationService
from backend.app.models.entities import (
    AuditChain,
    Conversation,
    ConversationTurn,
    Task,
    TaskEvent,
    TaskJob,
)
from backend.app.runtime.intake import TaskIntakeService


TABLES = [
    Task.__table__,
    Conversation.__table__,
    ConversationTurn.__table__,
    TaskEvent.__table__,
    AuditChain.__table__,
    TaskJob.__table__,
]


class TaskIntakeTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in TABLES:
            table.create(engine)
        self.session = Session(engine, expire_on_commit=False)

    def tearDown(self) -> None:
        self.session.close()

    def test_accept_creates_task_turn_event_and_job_without_running_agent(self) -> None:
        accepted = TaskIntakeService(self.session).accept("检查当前主机监听端口")

        turn = self.session.execute(
            select(ConversationTurn).where(ConversationTurn.task_id == accepted.task.id)
        ).scalar_one()
        event = self.session.execute(
            select(TaskEvent).where(TaskEvent.task_id == accepted.task.id)
        ).scalar_one()
        job = self.session.execute(
            select(TaskJob).where(TaskJob.task_id == accepted.task.id)
        ).scalar_one()

        self.assertEqual(accepted.task.status, "RECEIVED")
        self.assertEqual(accepted.task.intent, "unknown")
        self.assertIsNone(accepted.task.summary)
        self.assertEqual(turn.conversation_id, accepted.conversation_id)
        self.assertIsNone(turn.parent_task_id)
        self.assertEqual(event.event_type, "task_created")
        self.assertEqual(event.payload_json["conversation_id"], accepted.conversation_id)
        self.assertEqual(job.status, "QUEUED")
        self.assertEqual(job.attempt_count, 0)
        self.assertIsNone(job.lease_owner)

    def test_follow_up_attaches_to_known_conversation_and_worker_context_excludes_current_turn(self) -> None:
        intake = TaskIntakeService(self.session)
        first = intake.accept("检查 8080 端口")
        first.task.intent = "network_exposure_analysis"
        first.task.status = "SEALED"
        first.task.risk_level = "R1"
        first.task.summary = "发现 8080 端口由 python 监听。"
        self.session.flush()

        second = intake.accept("它对应哪个进程？", first.conversation_id)
        context = ConversationService(self.session).context_for_task(second.task.id)
        second_turn = ConversationService(self.session).get_turn(second.task.id)

        self.assertEqual(second.conversation_id, first.conversation_id)
        self.assertEqual(second_turn.parent_task_id, first.task.id)
        self.assertEqual([item["task_id"] for item in context], [first.task.id])
        self.assertNotIn(second.task.id, [item["task_id"] for item in context])

    def test_unknown_conversation_rejects_without_partial_rows(self) -> None:
        with self.assertRaises(LookupError):
            TaskIntakeService(self.session).accept("继续检查", "missing-conversation")

        self.assertEqual(self.session.scalar(select(func.count()).select_from(Task)), 0)
        self.assertEqual(self.session.scalar(select(func.count()).select_from(TaskJob)), 0)

    def test_caller_rollback_removes_the_entire_intake_unit(self) -> None:
        TaskIntakeService(self.session).accept("检查磁盘空间")
        self.session.rollback()

        self.assertEqual(self.session.scalar(select(func.count()).select_from(Task)), 0)
        self.assertEqual(self.session.scalar(select(func.count()).select_from(Conversation)), 0)
        self.assertEqual(self.session.scalar(select(func.count()).select_from(ConversationTurn)), 0)
        self.assertEqual(self.session.scalar(select(func.count()).select_from(TaskEvent)), 0)
        self.assertEqual(self.session.scalar(select(func.count()).select_from(TaskJob)), 0)


if __name__ == "__main__":
    unittest.main()
