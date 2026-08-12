from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.models.entities import Task, TaskJob, WorkerInstance
from backend.app.runtime.health import WorkerHeartbeatReporter, worker_runtime_status


class WorkerRuntimeHealthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in (Task.__table__, TaskJob.__table__, WorkerInstance.__table__):
            table.create(self.engine)
        self.session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            expire_on_commit=False,
            future=True,
        )
        self.now = datetime(2026, 7, 12, 10, 0, tzinfo=timezone.utc)

    def test_status_reports_online_worker_and_real_queue_age(self) -> None:
        with self.session_factory() as session:
            task = Task(
                trace_id="trace-worker-queue",
                user_input="检查服务",
                status="RECEIVED",
                created_at=self.now - timedelta(minutes=2),
                updated_at=self.now - timedelta(minutes=2),
            )
            session.add(task)
            session.flush()
            session.add_all(
                [
                    TaskJob(
                        task_id=task.id,
                        status="QUEUED",
                        available_at=self.now - timedelta(minutes=2),
                        created_at=self.now - timedelta(minutes=2),
                        updated_at=self.now - timedelta(minutes=2),
                    ),
                    WorkerInstance(
                        worker_id="worker-a",
                        hostname="linux-node",
                        pid=2001,
                        status="RUNNING",
                        started_at=self.now - timedelta(hours=1),
                        last_seen_at=self.now - timedelta(seconds=3),
                        updated_at=self.now - timedelta(seconds=3),
                    ),
                ]
            )
            session.commit()

            report = worker_runtime_status(
                session,
                now=self.now,
                stale_after_seconds=20,
                queue_warn_seconds=60,
            )

        self.assertEqual(report["overall_status"], "warn")
        self.assertEqual(report["online_worker_count"], 1)
        self.assertEqual(report["queue"]["queued"], 1)
        self.assertEqual(report["queue"]["oldest_wait_seconds"], 120)
        self.assertEqual(report["instances"][0]["status"], "ONLINE")

    def test_stale_worker_is_not_reported_online(self) -> None:
        with self.session_factory() as session:
            session.add(
                WorkerInstance(
                    worker_id="worker-stale",
                    hostname="linux-node",
                    pid=2002,
                    status="RUNNING",
                    started_at=self.now - timedelta(hours=1),
                    last_seen_at=self.now - timedelta(seconds=21),
                    updated_at=self.now - timedelta(seconds=21),
                )
            )
            session.commit()

            report = worker_runtime_status(
                session,
                now=self.now,
                stale_after_seconds=20,
            )

        self.assertEqual(report["overall_status"], "blocked")
        self.assertEqual(report["online_worker_count"], 0)
        self.assertEqual(report["instances"][0]["status"], "STALE")

    def test_reporter_persists_heartbeat_and_stop_state(self) -> None:
        reporter = WorkerHeartbeatReporter(
            self.session_factory,
            "worker-reporter",
            interval_seconds=5,
            hostname="linux-node",
            pid=2003,
        )

        reporter.heartbeat()
        with self.session_factory() as session:
            instance = session.scalar(
                select(WorkerInstance).where(WorkerInstance.worker_id == "worker-reporter")
            )
            assert instance is not None
            self.assertEqual(instance.status, "RUNNING")

        reporter.stop()
        with self.session_factory() as session:
            instance = session.scalar(
                select(WorkerInstance).where(WorkerInstance.worker_id == "worker-reporter")
            )
            assert instance is not None
            self.assertEqual(instance.status, "STOPPED")


if __name__ == "__main__":
    unittest.main()
