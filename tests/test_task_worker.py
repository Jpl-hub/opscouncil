from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.agent.runner import TaskCancelledError
from backend.app.models.entities import (
    AuditChain,
    Conversation,
    ConversationTurn,
    Task,
    TaskEvent,
    TaskJob,
    utcnow,
)
from backend.app.runtime.intake import TaskIntakeService
from backend.app.runtime.queue import TaskQueue
from backend.app.runtime.worker import TaskWorker


TABLES = [
    Task.__table__,
    Conversation.__table__,
    ConversationTurn.__table__,
    TaskEvent.__table__,
    AuditChain.__table__,
    TaskJob.__table__,
]


class RecordingRunner:
    calls: list[dict[str, object]] = []
    mode = "success"
    session_factory = None

    def __init__(
        self,
        session: Session,
        registry: object,
        *,
        cancellation_probe,
        event_checkpoint,
    ) -> None:  # type: ignore[no-untyped-def]
        self.session = session
        self.cancellation_probe = cancellation_probe
        self.event_checkpoint = event_checkpoint

    def run(self, task: Task, conversation_context: list[dict[str, object]] | None = None) -> None:
        type(self).calls.append(
            {
                "task_id": task.id,
                "context": conversation_context or [],
            }
        )
        if type(self).mode == "raise":
            raise RuntimeError("model transport included a\nprivate traceback")
        if type(self).mode == "cancel":
            assert type(self).session_factory is not None
            with type(self).session_factory() as cancel_session:
                TaskQueue(cancel_session).request_cancel(task.id)
                cancel_session.commit()
            if self.cancellation_probe():
                raise TaskCancelledError
        if type(self).mode == "externally_settled":
            job = self.session.scalar(select(TaskJob).where(TaskJob.task_id == task.id))
            assert job is not None
            task.status = "CANCELLED"
            task.summary = "任务已由外部控制面关闭。"
            task.sealed_at = utcnow()
            job.status = "CANCELLED"
            job.lease_owner = None
            job.lease_expires_at = None
            job.finished_at = utcnow()
            self.session.commit()
            raise RuntimeError("job was settled by the control plane")
        if type(self).mode == "failed_status":
            task.status = "FAILED"
            task.summary = "模型意图解析失败。"
        elif type(self).mode == "needs_operator":
            task.status = "NEEDS_OPERATOR"
            task.summary = "已保留系统证据，等待运维人员继续处理。"
        else:
            task.status = "SEALED"
            task.summary = "完成只读分析。"
            task.sealed_at = utcnow()
        task.updated_at = utcnow()
        self.session.flush()
        self.event_checkpoint()


class RecordingPatrolService:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def run_due_once(self, worker_id: str, *, now: datetime | None = None) -> bool:
        self.calls.append({"worker_id": worker_id, "now": now})
        return self.result


class RecordingApprovalProcessor:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.calls: list[datetime | None] = []

    def run_once(self, *, now: datetime | None = None) -> bool:
        self.calls.append(now)
        return self.result


class TaskWorkerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in TABLES:
            table.create(self.engine)
        self.session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
            future=True,
        )
        RecordingRunner.calls = []
        RecordingRunner.mode = "success"
        RecordingRunner.session_factory = self.session_factory
        self.now = datetime(2026, 7, 11, 9, 0, tzinfo=timezone.utc)

    def _accept(self, text: str, conversation_id: str | None = None) -> tuple[int, str]:
        with self.session_factory() as session:
            accepted = TaskIntakeService(session).accept(text, conversation_id)
            accepted.job.available_at = self.now
            task_id = accepted.task.id
            accepted_conversation_id = accepted.conversation_id
            session.commit()
        return task_id, accepted_conversation_id

    def _worker(
        self,
        patrol_service: RecordingPatrolService | None = None,
        approval_processor: RecordingApprovalProcessor | None = None,
    ) -> TaskWorker:
        return TaskWorker(
            self.session_factory,
            registry=object(),
            worker_id="worker-test",
            runner_factory=RecordingRunner,
            lease_seconds=120,
            patrol_service=patrol_service,
            approval_processor=approval_processor,
        )

    def test_approval_decision_has_priority_over_new_agent_tasks(self) -> None:
        task_id, _ = self._accept("检查磁盘")
        approval = RecordingApprovalProcessor(result=True)
        patrol = RecordingPatrolService(result=True)

        worked = self._worker(patrol, approval).run_once(now=self.now)

        self.assertTrue(worked)
        self.assertEqual(approval.calls, [self.now])
        self.assertEqual(RecordingRunner.calls, [])
        self.assertEqual(patrol.calls, [])
        with self.session_factory() as session:
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == task_id))
            assert job is not None
            self.assertEqual(job.status, "QUEUED")

    def test_worker_claims_and_completes_one_task(self) -> None:
        task_id, _ = self._accept("检查磁盘")
        patrol = RecordingPatrolService()

        worked = self._worker(patrol).run_once(now=self.now)

        self.assertTrue(worked)
        self.assertEqual([call["task_id"] for call in RecordingRunner.calls], [task_id])
        self.assertEqual(patrol.calls, [])
        with self.session_factory() as session:
            task = session.get(Task, task_id)
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == task_id))
            assert task is not None and job is not None
            self.assertEqual(task.status, "SEALED")
            self.assertEqual(job.status, "SUCCEEDED")
            events = list(
                session.scalars(
                    select(TaskEvent.event_type)
                    .where(TaskEvent.task_id == task_id)
                    .order_by(TaskEvent.id.asc())
                )
            )
        self.assertEqual(events, ["task_created", "worker_started"])

    def test_idle_worker_runs_one_due_patrol(self) -> None:
        patrol = RecordingPatrolService(result=True)

        worked = self._worker(patrol).run_once(now=self.now)

        self.assertTrue(worked)
        self.assertEqual(
            patrol.calls,
            [{"worker_id": "worker-test", "now": self.now}],
        )
        self.assertEqual(RecordingRunner.calls, [])

    def test_idle_worker_remains_idle_when_no_patrol_is_due(self) -> None:
        patrol = RecordingPatrolService(result=False)

        worked = self._worker(patrol).run_once(now=self.now)

        self.assertFalse(worked)
        self.assertEqual(len(patrol.calls), 1)

    def test_worker_reconstructs_only_prior_sealed_conversation_context(self) -> None:
        first_id, conversation_id = self._accept("检查 8080 端口")
        with self.session_factory() as session:
            first = session.get(Task, first_id)
            assert first is not None
            first.status = "SEALED"
            first.intent = "network_exposure_analysis"
            first.summary = "发现 8080 端口。"
            first_job = session.scalar(select(TaskJob).where(TaskJob.task_id == first_id))
            assert first_job is not None
            first_job.status = "SUCCEEDED"
            session.commit()
        second_id, _ = self._accept("它由哪个进程监听？", conversation_id)

        self._worker().run_once(now=self.now)

        self.assertEqual(RecordingRunner.calls[0]["task_id"], second_id)
        context = RecordingRunner.calls[0]["context"]
        self.assertEqual([item["task_id"] for item in context], [first_id])

    def test_runner_exception_is_sanitized_and_persisted_as_failed_job(self) -> None:
        task_id, _ = self._accept("检查服务")
        RecordingRunner.mode = "raise"

        worked = self._worker().run_once(now=self.now)

        self.assertTrue(worked)
        with self.session_factory() as session:
            task = session.get(Task, task_id)
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == task_id))
            assert task is not None and job is not None
            self.assertEqual(task.status, "FAILED")
            self.assertEqual(job.status, "FAILED")
            self.assertNotIn("\n", job.last_error or "")
            self.assertIn("model transport", job.last_error or "")

    def test_runner_failed_status_maps_to_failed_job(self) -> None:
        task_id, _ = self._accept("检查网络")
        RecordingRunner.mode = "failed_status"

        self._worker().run_once(now=self.now)

        with self.session_factory() as session:
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == task_id))
            assert job is not None
            self.assertEqual(job.status, "FAILED")
            self.assertIn("模型意图解析失败", job.last_error or "")

    def test_needs_operator_is_a_successful_terminal_worker_outcome(self) -> None:
        task_id, _ = self._accept("检查网络")
        RecordingRunner.mode = "needs_operator"

        self._worker().run_once(now=self.now)

        with self.session_factory() as session:
            task = session.get(Task, task_id)
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == task_id))
            assert task is not None and job is not None
            self.assertEqual(task.status, "NEEDS_OPERATOR")
            self.assertEqual(job.status, "SUCCEEDED")

    def test_running_cancellation_stops_at_probe_and_marks_both_records_cancelled(self) -> None:
        task_id, _ = self._accept("检查进程")
        RecordingRunner.mode = "cancel"

        self._worker().run_once(now=self.now)

        with self.session_factory() as session:
            task = session.get(Task, task_id)
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == task_id))
            assert task is not None and job is not None
            self.assertEqual(task.status, "CANCELLED")
            self.assertEqual(job.status, "CANCELLED")

    def test_external_terminal_transition_does_not_stop_worker_loop(self) -> None:
        task_id, _ = self._accept("检查监听端口")
        RecordingRunner.mode = "externally_settled"

        worked = self._worker().run_once(now=self.now)

        self.assertTrue(worked)
        with self.session_factory() as session:
            task = session.get(Task, task_id)
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == task_id))
            assert task is not None and job is not None
            self.assertEqual(task.status, "CANCELLED")
            self.assertEqual(job.status, "CANCELLED")

    def test_abandoned_job_is_failed_before_new_work_is_claimed(self) -> None:
        abandoned_id, _ = self._accept("分析配置漂移")
        with self.session_factory() as session:
            accepted_job = session.scalar(select(TaskJob).where(TaskJob.task_id == abandoned_id))
            assert accepted_job is not None
            accepted_job.available_at = self.now - timedelta(minutes=2)
            session.flush()
            TaskQueue(session).claim_next(
                "dead-worker",
                now=self.now - timedelta(minutes=2),
                lease_seconds=30,
            )
            session.commit()

        worked = self._worker().run_once(now=self.now)

        self.assertFalse(worked)
        self.assertEqual(RecordingRunner.calls, [])
        with self.session_factory() as session:
            task = session.get(Task, abandoned_id)
            job = session.scalar(select(TaskJob).where(TaskJob.task_id == abandoned_id))
            assert task is not None and job is not None
            self.assertEqual(task.status, "FAILED")
            self.assertEqual(job.status, "FAILED")


if __name__ == "__main__":
    unittest.main()
