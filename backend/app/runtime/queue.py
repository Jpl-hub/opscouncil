from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.service import AuditService
from backend.app.models.entities import Task, TaskJob, utcnow
from backend.app.schemas.enums import JobStatus, TaskStatus


SUCCESSFUL_TASK_STATES = {
    TaskStatus.SEALED.value,
    TaskStatus.REJECTED.value,
    TaskStatus.BLOCKED.value,
    TaskStatus.NEEDS_OPERATOR.value,
    TaskStatus.ROLLED_BACK.value,
}
TERMINAL_JOB_STATES = {
    JobStatus.SUCCEEDED.value,
    JobStatus.FAILED.value,
    JobStatus.CANCELLED.value,
}


class JobStateError(RuntimeError):
    pass


class TaskQueue:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.audit = AuditService(session)

    def claim_next(
        self,
        worker_id: str,
        *,
        now: datetime | None = None,
        lease_seconds: int = 300,
    ) -> TaskJob | None:
        claimed_at = now or utcnow()
        job = self.session.execute(
            select(TaskJob)
            .where(
                TaskJob.status == JobStatus.QUEUED.value,
                TaskJob.available_at <= claimed_at,
            )
            .order_by(TaskJob.available_at.asc(), TaskJob.id.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        ).scalar_one_or_none()
        if job is None:
            return None
        job.status = JobStatus.RUNNING.value
        job.lease_owner = worker_id
        job.lease_expires_at = claimed_at + timedelta(seconds=max(lease_seconds, 1))
        job.attempt_count += 1
        job.started_at = job.started_at or claimed_at
        job.updated_at = claimed_at
        self.session.flush()
        return job

    def mark_succeeded(
        self,
        job_id: int,
        worker_id: str,
        *,
        now: datetime | None = None,
    ) -> TaskJob:
        job = self._owned_running_job(job_id, worker_id)
        task = self._task(job)
        if task.status not in SUCCESSFUL_TASK_STATES:
            raise JobStateError(f"task {task.id} is not in a successful terminal state")
        self._finish(job, JobStatus.SUCCEEDED, now or utcnow())
        return job

    def mark_failed(
        self,
        job_id: int,
        worker_id: str,
        error: str,
        *,
        now: datetime | None = None,
    ) -> TaskJob:
        failed_at = now or utcnow()
        job = self._owned_running_job(job_id, worker_id)
        task = self._task(job)
        message = _sanitize_error(error)
        if task.status != TaskStatus.FAILED.value:
            task.status = TaskStatus.FAILED.value
            task.summary = f"任务执行失败：{message}"
            task.updated_at = failed_at
            self.audit.append_event(
                task,
                TaskStatus.FAILED.value,
                "worker_execution_failed",
                "Worker 执行任务失败，任务已停止。",
                {"error": message},
            )
        job.last_error = message
        self._finish(job, JobStatus.FAILED, failed_at)
        return job

    def request_cancel(self, task_id: int, *, now: datetime | None = None) -> str:
        requested_at = now or utcnow()
        job = self.session.execute(
            select(TaskJob)
            .where(TaskJob.task_id == task_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if job is None:
            raise LookupError("task job not found")
        if job.status in TERMINAL_JOB_STATES:
            return job.status
        task = self._task(job)
        if job.status == JobStatus.QUEUED.value:
            job.cancel_requested_at = requested_at
            self._finish(job, JobStatus.CANCELLED, requested_at)
            task.status = TaskStatus.CANCELLED.value
            task.summary = "任务在进入 Agent 执行前由操作员取消，未调用模型或系统工具。"
            task.updated_at = requested_at
            task.sealed_at = requested_at
            self.audit.append_event(
                task,
                TaskStatus.CANCELLED.value,
                "task_cancelled",
                "排队任务已取消，未进入 Agent 执行。",
                {"previous_job_status": JobStatus.QUEUED.value},
            )
            return JobStatus.CANCELLED.value
        if job.status != JobStatus.RUNNING.value:
            raise JobStateError(f"cannot cancel job in state {job.status}")
        if job.cancel_requested_at is None:
            job.cancel_requested_at = requested_at
            job.updated_at = requested_at
            self.audit.append_event(
                task,
                task.status,
                "task_cancel_requested",
                "已请求取消运行中的任务，任务执行器将在下一个安全边界停止。",
                {},
            )
        return "CANCEL_REQUESTED"

    def is_cancel_requested(self, job_id: int) -> bool:
        job = self.session.get(TaskJob, job_id)
        if job is None:
            raise LookupError("task job not found")
        self.session.refresh(job, attribute_names=["cancel_requested_at", "status"])
        return job.status == JobStatus.RUNNING.value and job.cancel_requested_at is not None

    def mark_cancelled(
        self,
        job_id: int,
        worker_id: str,
        *,
        now: datetime | None = None,
    ) -> TaskJob:
        cancelled_at = now or utcnow()
        job = self._owned_running_job(job_id, worker_id)
        task = self._task(job)
        if job.cancel_requested_at is None:
            raise JobStateError("running job has no cancellation request")
        task.status = TaskStatus.CANCELLED.value
        task.summary = "任务已在安全边界停止，后续模型与工具步骤未再执行。"
        task.updated_at = cancelled_at
        task.sealed_at = cancelled_at
        self.audit.append_event(
            task,
            TaskStatus.CANCELLED.value,
            "task_cancelled",
            "运行任务已在安全边界取消。",
            {},
        )
        self._finish(job, JobStatus.CANCELLED, cancelled_at)
        return job

    def fail_abandoned_leases(self, now: datetime | None = None) -> list[int]:
        failed_at = now or utcnow()
        jobs = list(
            self.session.execute(
                select(TaskJob)
                .where(
                    TaskJob.status == JobStatus.RUNNING.value,
                    TaskJob.lease_expires_at.is_not(None),
                    TaskJob.lease_expires_at < failed_at,
                )
                .order_by(TaskJob.id.asc())
                .with_for_update(skip_locked=True)
            ).scalars()
        )
        failed_task_ids: list[int] = []
        for job in jobs:
            task = self._task(job)
            task.status = TaskStatus.FAILED.value
            task.summary = "任务执行器租约过期，系统为避免重复执行已停止任务。"
            task.updated_at = failed_at
            task.sealed_at = failed_at
            self.audit.append_event(
                task,
                TaskStatus.FAILED.value,
                "worker_lease_expired",
                "任务执行器租约过期，任务失败关闭且未自动重放。",
                {"worker_id": job.lease_owner, "attempt_count": job.attempt_count},
            )
            job.last_error = "worker lease expired; automatic replay disabled"
            self._finish(job, JobStatus.FAILED, failed_at)
            failed_task_ids.append(task.id)
        return failed_task_ids

    def _owned_running_job(self, job_id: int, worker_id: str) -> TaskJob:
        job = self.session.execute(
            select(TaskJob)
            .where(TaskJob.id == job_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if job is None:
            raise LookupError("task job not found")
        if job.status != JobStatus.RUNNING.value or job.lease_owner != worker_id:
            raise JobStateError("worker does not own a running job")
        return job

    def _task(self, job: TaskJob) -> Task:
        task = self.session.get(Task, job.task_id)
        if task is None:
            raise JobStateError(f"task {job.task_id} not found")
        return task

    @staticmethod
    def _finish(job: TaskJob, status: JobStatus, finished_at: datetime) -> None:
        job.status = status.value
        job.finished_at = finished_at
        job.updated_at = finished_at
        job.lease_owner = None
        job.lease_expires_at = None


def _sanitize_error(error: str) -> str:
    return " ".join(str(error).split())[:1000] or "unknown worker error"
