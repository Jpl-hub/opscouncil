from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.agent.conversation import ConversationService
from backend.app.agent.runner import AgentRunner, TaskCancelledError
from backend.app.audit.service import AuditService
from backend.app.mcp.registry import ToolRegistry
from backend.app.models.entities import Task, TaskJob, utcnow
from backend.app.runtime.queue import JobStateError, TaskQueue
from backend.app.schemas.enums import JobStatus, TaskStatus


RunnerFactory = Callable[..., AgentRunner]


class PatrolServiceProtocol(Protocol):
    def run_due_once(
        self,
        worker_id: str,
        *,
        now: datetime | None = None,
    ) -> bool: ...


class ApprovalProcessorProtocol(Protocol):
    def run_once(self, *, now: datetime | None = None) -> bool: ...


class TaskWorker:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        registry: ToolRegistry,
        worker_id: str,
        *,
        runner_factory: RunnerFactory = AgentRunner,
        lease_seconds: int = 300,
        patrol_service: PatrolServiceProtocol | None = None,
        approval_processor: ApprovalProcessorProtocol | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.registry = registry
        self.worker_id = worker_id
        self.runner_factory = runner_factory
        self.lease_seconds = max(lease_seconds, 30)
        self.patrol_service = patrol_service
        self.approval_processor = approval_processor

    def run_once(self, *, now: datetime | None = None) -> bool:
        claimed_at = now or utcnow()
        if self.approval_processor is not None and self.approval_processor.run_once(now=claimed_at):
            return True
        job_id: int | None = None
        task_id: int | None = None
        with self.session_factory() as session:
            queue = TaskQueue(session)
            queue.fail_abandoned_leases(claimed_at)
            job = queue.claim_next(
                self.worker_id,
                now=claimed_at,
                lease_seconds=self.lease_seconds,
            )
            if job is None:
                session.commit()
            else:
                job_id = job.id
                task_id = job.task_id
                session.commit()

        if job_id is None or task_id is None:
            if self.patrol_service is None:
                return False
            return self.patrol_service.run_due_once(self.worker_id, now=claimed_at)

        try:
            self._execute(job_id, task_id)
        except TaskCancelledError:
            self._mark_cancelled(job_id)
        except Exception as exc:
            self._mark_failed(job_id, str(exc))
        else:
            with self.session_factory() as session:
                task = session.get(Task, task_id)
                queue = TaskQueue(session)
                if task is None:
                    queue.mark_failed(
                        job_id,
                        self.worker_id,
                        "task record disappeared during worker execution",
                    )
                elif task.status == TaskStatus.FAILED.value:
                    queue.mark_failed(
                        job_id,
                        self.worker_id,
                        task.summary or "Agent workflow failed",
                    )
                else:
                    queue.mark_succeeded(job_id, self.worker_id)
                session.commit()
        return True

    def _execute(self, job_id: int, task_id: int) -> None:
        with self.session_factory() as session:
            job = session.scalar(select(TaskJob).where(TaskJob.id == job_id))
            task = session.get(Task, task_id)
            if job is None or task is None:
                raise LookupError("claimed task or job not found")
            if job.status != JobStatus.RUNNING.value or job.lease_owner != self.worker_id:
                raise JobStateError("worker lost ownership before execution")

            def event_checkpoint() -> None:
                self._renew_lease(session, job)
                session.commit()

            def cancellation_probe() -> bool:
                session.refresh(job, attribute_names=["status", "lease_owner", "cancel_requested_at"])
                if job.status != JobStatus.RUNNING.value or job.lease_owner != self.worker_id:
                    raise JobStateError("worker lost job ownership during execution")
                return job.cancel_requested_at is not None

            AuditService(session, after_append=event_checkpoint).append_event(
                task,
                task.status,
                "worker_started",
                "任务执行器已领取任务并开始受控执行。",
                {"worker_id": self.worker_id, "attempt_count": job.attempt_count},
            )
            runner = self.runner_factory(
                session,
                self.registry,
                cancellation_probe=cancellation_probe,
                event_checkpoint=event_checkpoint,
            )
            context = ConversationService(session).context_for_task(task.id)
            runner.run(task, context)
            session.commit()

    def _renew_lease(self, session: Session, job: TaskJob) -> None:
        session.refresh(job, attribute_names=["status", "lease_owner", "cancel_requested_at"])
        if job.status != JobStatus.RUNNING.value or job.lease_owner != self.worker_id:
            raise JobStateError("worker cannot renew an unowned job")
        refreshed_at = utcnow()
        job.lease_expires_at = refreshed_at + timedelta(seconds=self.lease_seconds)
        job.updated_at = refreshed_at

    def _mark_cancelled(self, job_id: int) -> None:
        with self.session_factory() as session:
            try:
                TaskQueue(session).mark_cancelled(job_id, self.worker_id)
            except JobStateError:
                session.rollback()
                if not self._ownership_changed(session, job_id):
                    raise
            else:
                session.commit()

    def _mark_failed(self, job_id: int, error: str) -> None:
        with self.session_factory() as session:
            try:
                TaskQueue(session).mark_failed(job_id, self.worker_id, error)
            except JobStateError:
                session.rollback()
                if not self._ownership_changed(session, job_id):
                    raise
            else:
                session.commit()

    def _ownership_changed(self, session: Session, job_id: int) -> bool:
        job = session.get(TaskJob, job_id)
        if job is None:
            return False
        session.refresh(job, attribute_names=["status", "lease_owner"])
        return job.status != JobStatus.RUNNING.value or job.lease_owner != self.worker_id
