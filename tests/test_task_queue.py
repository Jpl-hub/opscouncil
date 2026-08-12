from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.models.entities import (
    AuditChain,
    Conversation,
    ConversationTurn,
    Task,
    TaskEvent,
    TaskJob,
)
from backend.app.runtime.intake import TaskIntakeService
from backend.app.runtime.queue import JobStateError, TaskQueue


TABLES = [
    Task.__table__,
    Conversation.__table__,
    ConversationTurn.__table__,
    TaskEvent.__table__,
    AuditChain.__table__,
    TaskJob.__table__,
]


class TaskQueueTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in TABLES:
            table.create(self.engine)
        self.session = Session(self.engine, expire_on_commit=False)
        self.queue = TaskQueue(self.session)
        self.now = datetime(2026, 7, 11, 8, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.session.close()

    def _accept(self, text: str):  # type: ignore[no-untyped-def]
        return TaskIntakeService(self.session).accept(text)

    def test_claims_oldest_available_job_and_records_lease(self) -> None:
        first = self._accept("检查磁盘")
        second = self._accept("检查端口")
        first.job.available_at = self.now - timedelta(seconds=2)
        second.job.available_at = self.now - timedelta(seconds=1)
        self.session.flush()

        claimed = self.queue.claim_next("worker-a", now=self.now, lease_seconds=90)

        self.assertIsNotNone(claimed)
        assert claimed is not None
        self.assertEqual(claimed.id, first.job.id)
        self.assertEqual(claimed.status, "RUNNING")
        self.assertEqual(claimed.lease_owner, "worker-a")
        self.assertEqual(claimed.attempt_count, 1)
        self.assertIsNotNone(claimed.started_at)
        self.assertEqual(second.job.status, "QUEUED")

    def test_future_job_is_not_claimed(self) -> None:
        accepted = self._accept("稍后巡检")
        accepted.job.available_at = self.now + timedelta(minutes=5)
        self.session.flush()

        self.assertIsNone(self.queue.claim_next("worker-a", now=self.now))

    def test_success_requires_owner_and_terminal_task(self) -> None:
        accepted = self._accept("检查服务")
        accepted.job.available_at = self.now
        claimed = self.queue.claim_next("worker-a", now=self.now)
        assert claimed is not None

        with self.assertRaises(JobStateError):
            self.queue.mark_succeeded(claimed.id, "worker-b", now=self.now)
        with self.assertRaises(JobStateError):
            self.queue.mark_succeeded(claimed.id, "worker-a", now=self.now)

        accepted.task.status = "SEALED"
        self.queue.mark_succeeded(claimed.id, "worker-a", now=self.now)
        self.assertEqual(claimed.status, "SUCCEEDED")
        self.assertIsNotNone(claimed.finished_at)
        self.assertIsNone(claimed.lease_owner)

    def test_queued_cancel_is_terminal_and_audited_without_claim(self) -> None:
        accepted = self._accept("检查日志")

        result = self.queue.request_cancel(accepted.task.id, now=self.now)

        self.assertEqual(result, "CANCELLED")
        self.assertEqual(accepted.job.status, "CANCELLED")
        self.assertEqual(accepted.task.status, "CANCELLED")
        self.assertIn("取消", accepted.task.summary or "")
        event_types = list(
            self.session.scalars(
                select(TaskEvent.event_type)
                .where(TaskEvent.task_id == accepted.task.id)
                .order_by(TaskEvent.id.asc())
            )
        )
        self.assertEqual(event_types, ["task_created", "task_cancelled"])
        self.assertIsNone(self.queue.claim_next("worker-a", now=self.now))

    def test_running_cancel_sets_signal_then_worker_marks_terminal(self) -> None:
        accepted = self._accept("检查进程")
        accepted.job.available_at = self.now
        claimed = self.queue.claim_next("worker-a", now=self.now)
        assert claimed is not None

        result = self.queue.request_cancel(accepted.task.id, now=self.now + timedelta(seconds=1))

        self.assertEqual(result, "CANCEL_REQUESTED")
        self.assertTrue(self.queue.is_cancel_requested(claimed.id))
        self.assertEqual(accepted.task.status, "RECEIVED")

        self.queue.mark_cancelled(
            claimed.id,
            "worker-a",
            now=self.now + timedelta(seconds=2),
        )
        self.assertEqual(claimed.status, "CANCELLED")
        self.assertEqual(accepted.task.status, "CANCELLED")

    def test_cancel_refreshes_a_stale_queued_identity_before_deciding(self) -> None:
        accepted = self._accept("检查网络监听")
        accepted.job.available_at = self.now
        self.session.commit()

        with Session(self.engine, expire_on_commit=False) as worker_session:
            claimed = TaskQueue(worker_session).claim_next(
                "worker-a",
                now=self.now,
                lease_seconds=120,
            )
            assert claimed is not None
            worker_session.commit()

        self.assertEqual(accepted.job.status, "QUEUED")
        result = self.queue.request_cancel(
            accepted.task.id,
            now=self.now + timedelta(seconds=1),
        )

        self.assertEqual(result, "CANCEL_REQUESTED")
        self.assertEqual(accepted.job.status, "RUNNING")
        self.assertEqual(accepted.job.lease_owner, "worker-a")
        self.assertIsNotNone(accepted.job.cancel_requested_at)

    def test_expired_running_lease_fails_closed_and_is_never_requeued(self) -> None:
        accepted = self._accept("分析配置漂移")
        accepted.job.available_at = self.now
        claimed = self.queue.claim_next("worker-a", now=self.now, lease_seconds=30)
        assert claimed is not None

        failed_task_ids = self.queue.fail_abandoned_leases(self.now + timedelta(seconds=31))

        self.assertEqual(failed_task_ids, [accepted.task.id])
        self.assertEqual(claimed.status, "FAILED")
        self.assertEqual(accepted.task.status, "FAILED")
        self.assertEqual(claimed.attempt_count, 1)
        self.assertIsNone(self.queue.claim_next("worker-b", now=self.now + timedelta(seconds=32)))
        events = list(
            self.session.scalars(
                select(TaskEvent.event_type)
                .where(TaskEvent.task_id == accepted.task.id)
                .order_by(TaskEvent.id.asc())
            )
        )
        self.assertEqual(events[-1], "worker_lease_expired")


if __name__ == "__main__":
    unittest.main()
