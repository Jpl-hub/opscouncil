from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import os
import socket
import threading
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import settings
from backend.app.models.entities import TaskJob, WorkerInstance, utcnow
from backend.app.schemas.enums import JobStatus


logger = logging.getLogger(__name__)


class WorkerHeartbeatReporter:
    """Publishes worker liveness independently from potentially long Agent calls."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        worker_id: str,
        *,
        interval_seconds: float | None = None,
        hostname: str | None = None,
        pid: int | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.worker_id = worker_id
        self.interval_seconds = max(
            interval_seconds or settings.worker_heartbeat_seconds,
            1.0,
        )
        self.hostname = hostname or socket.gethostname()
        self.pid = pid or os.getpid()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self.heartbeat()
        self._thread = threading.Thread(
            target=self._run,
            name=f"worker-heartbeat-{self.worker_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_seconds + 1.0)
        try:
            self._write("STOPPED")
        except Exception:
            logger.exception("failed to persist worker stop state")

    def heartbeat(self) -> None:
        self._write("RUNNING")

    def _run(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            try:
                self.heartbeat()
            except Exception:
                logger.exception("failed to persist worker heartbeat")

    def _write(self, status: str) -> None:
        now = utcnow()
        with self.session_factory() as session:
            instance = session.scalar(
                select(WorkerInstance)
                .where(WorkerInstance.worker_id == self.worker_id)
                .with_for_update()
            )
            if instance is None:
                instance = WorkerInstance(
                    worker_id=self.worker_id,
                    hostname=self.hostname,
                    pid=self.pid,
                    status=status,
                    started_at=now,
                    last_seen_at=now,
                    updated_at=now,
                )
                session.add(instance)
            else:
                instance.hostname = self.hostname
                instance.pid = self.pid
                instance.status = status
                instance.last_seen_at = now
                instance.updated_at = now
            session.commit()


def worker_runtime_status(
    session: Session,
    *,
    now: datetime | None = None,
    stale_after_seconds: int | None = None,
    queue_warn_seconds: int | None = None,
) -> dict[str, Any]:
    checked_at = _as_utc(now or utcnow())
    stale_seconds = max(stale_after_seconds or settings.worker_stale_seconds, 5)
    queue_warn = max(queue_warn_seconds or settings.worker_queue_warn_seconds, 1)
    fresh_after = checked_at - timedelta(seconds=stale_seconds)

    instances = list(
        session.scalars(
            select(WorkerInstance)
            .order_by(WorkerInstance.last_seen_at.desc(), WorkerInstance.id.desc())
            .limit(10)
        )
    )
    fresh = [
        item
        for item in instances
        if item.status == "RUNNING" and _as_utc(item.last_seen_at) >= fresh_after
    ]
    counts = {
        state: int(count)
        for state, count in session.execute(
            select(TaskJob.status, func.count(TaskJob.id)).group_by(TaskJob.status)
        )
    }
    oldest_queued_at = session.scalar(
        select(func.min(TaskJob.created_at)).where(TaskJob.status == JobStatus.QUEUED.value)
    )
    oldest_wait_seconds = (
        max(int((checked_at - _as_utc(oldest_queued_at)).total_seconds()), 0)
        if oldest_queued_at is not None
        else 0
    )
    queued = counts.get(JobStatus.QUEUED.value, 0)
    running = counts.get(JobStatus.RUNNING.value, 0)

    if not fresh:
        overall_status = "blocked"
        summary = "未检测到在线任务执行器；新任务将保留在持久化队列中。"
    elif queued and oldest_wait_seconds >= queue_warn:
        overall_status = "warn"
        summary = f"{len(fresh)} 个任务执行器在线，最久排队 {oldest_wait_seconds} 秒。"
    else:
        overall_status = "ok"
        summary = f"{len(fresh)} 个任务执行器在线，当前排队 {queued} 项。"

    return {
        "overall_status": overall_status,
        "summary": summary,
        "online_worker_count": len(fresh),
        "queue": {
            "queued": queued,
            "running": running,
            "oldest_wait_seconds": oldest_wait_seconds,
        },
        "instances": [
            {
                "worker_id": item.worker_id,
                "hostname": item.hostname,
                "pid": item.pid,
                "status": (
                    "ONLINE"
                    if item in fresh
                    else "STOPPED"
                    if item.status == "STOPPED"
                    else "STALE"
                ),
                "started_at": item.started_at.isoformat(),
                "last_seen_at": item.last_seen_at.isoformat(),
                "age_seconds": max(
                    int((checked_at - _as_utc(item.last_seen_at)).total_seconds()),
                    0,
                ),
            }
            for item in instances
        ],
        "checked_at": checked_at.isoformat(),
    }


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
