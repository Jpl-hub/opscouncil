from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.agent.runner import AgentRunner
from backend.app.audit.service import AuditService
from backend.app.channels.feishu.redaction import redact_text
from backend.app.models.entities import (
    ActionProposal,
    ApprovalDecisionJob,
    Operator,
    Task,
    utcnow,
)
from backend.app.schemas.enums import TaskStatus


class ApprovalJobStateError(RuntimeError):
    pass


class ApprovalDecisionQueue:
    def __init__(self, session: Session) -> None:
        self.session = session

    def claim_next(
        self,
        worker_id: str,
        *,
        now: datetime | None = None,
        lease_seconds: int = 300,
    ) -> ApprovalDecisionJob | None:
        claimed_at = now or utcnow()
        job = self.session.scalar(
            select(ApprovalDecisionJob)
            .where(
                ApprovalDecisionJob.status == "QUEUED",
                ApprovalDecisionJob.available_at <= claimed_at,
            )
            .order_by(ApprovalDecisionJob.available_at.asc(), ApprovalDecisionJob.id.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if job is None:
            return None
        job.status = "RUNNING"
        job.lease_owner = _worker_id(worker_id)
        job.lease_expires_at = claimed_at + timedelta(seconds=max(lease_seconds, 30))
        job.attempt_count += 1
        job.started_at = job.started_at or claimed_at
        job.updated_at = claimed_at
        self.session.flush()
        return job

    def renew(
        self,
        job_id: int,
        worker_id: str,
        *,
        now: datetime | None = None,
        lease_seconds: int = 300,
    ) -> ApprovalDecisionJob:
        renewed_at = now or utcnow()
        job = self._owned_running(job_id, worker_id)
        job.lease_expires_at = renewed_at + timedelta(seconds=max(lease_seconds, 30))
        job.updated_at = renewed_at
        self.session.flush()
        return job

    def mark_succeeded(
        self,
        job_id: int,
        worker_id: str,
        *,
        now: datetime | None = None,
    ) -> ApprovalDecisionJob:
        finished_at = now or utcnow()
        job = self._owned_running(job_id, worker_id)
        job.status = "SUCCEEDED"
        job.finished_at = finished_at
        job.updated_at = finished_at
        job.lease_owner = None
        job.lease_expires_at = None
        self.session.flush()
        return job

    def mark_needs_operator(
        self,
        job_id: int,
        worker_id: str,
        error: str,
        *,
        now: datetime | None = None,
    ) -> ApprovalDecisionJob:
        failed_at = now or utcnow()
        job = self._owned_running(job_id, worker_id)
        self._needs_operator(job, redact_text(error, max_chars=500), failed_at)
        self.session.flush()
        return job

    def fail_abandoned_leases(self, now: datetime | None = None) -> list[int]:
        failed_at = now or utcnow()
        jobs = list(
            self.session.scalars(
                select(ApprovalDecisionJob)
                .where(
                    ApprovalDecisionJob.status == "RUNNING",
                    ApprovalDecisionJob.lease_expires_at.is_not(None),
                    ApprovalDecisionJob.lease_expires_at < failed_at,
                )
                .order_by(ApprovalDecisionJob.id.asc())
                .with_for_update(skip_locked=True)
            )
        )
        for job in jobs:
            self._needs_operator(
                job,
                "审批执行租约过期；为避免重复副作用，系统未自动重放。",
                failed_at,
            )
        self.session.flush()
        return [job.id for job in jobs]

    def _needs_operator(
        self,
        job: ApprovalDecisionJob,
        reason: str,
        failed_at: datetime,
    ) -> None:
        job.status = "NEEDS_OPERATOR"
        job.last_error = reason or "审批执行状态不确定。"
        job.finished_at = failed_at
        job.updated_at = failed_at
        job.lease_owner = None
        job.lease_expires_at = None
        proposal = self.session.get(ActionProposal, job.proposal_id)
        task = self.session.get(Task, proposal.task_id) if proposal is not None else None
        if task is not None:
            task.status = TaskStatus.NEEDS_OPERATOR.value
            task.summary = "审批执行状态需要人工确认，系统不会自动重复执行。"
            task.updated_at = failed_at
            AuditService(self.session).append_event(
                task,
                TaskStatus.NEEDS_OPERATOR.value,
                "approval_job_needs_operator",
                "审批作业状态不确定，已停止自动重放。",
                {"approval_job_id": job.id, "proposal_id": job.proposal_id},
            )

    def _owned_running(self, job_id: int, worker_id: str) -> ApprovalDecisionJob:
        job = self.session.scalar(
            select(ApprovalDecisionJob)
            .where(ApprovalDecisionJob.id == job_id)
            .with_for_update()
        )
        if job is None:
            raise LookupError("approval decision job not found")
        if job.status != "RUNNING" or job.lease_owner != _worker_id(worker_id):
            raise ApprovalJobStateError("worker does not own a running approval job")
        return job


RunnerFactory = Callable[..., AgentRunner]


class ApprovalDecisionProcessor:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        registry: object,
        worker_id: str,
        *,
        runner_factory: RunnerFactory = AgentRunner,
        lease_seconds: int = 300,
    ) -> None:
        self.session_factory = session_factory
        self.registry = registry
        self.worker_id = _worker_id(worker_id)
        self.runner_factory = runner_factory
        self.lease_seconds = max(lease_seconds, 30)

    def run_once(self, *, now: datetime | None = None) -> bool:
        claimed_at = now or utcnow()
        with self.session_factory() as session:
            queue = ApprovalDecisionQueue(session)
            queue.fail_abandoned_leases(claimed_at)
            job = queue.claim_next(
                self.worker_id,
                now=claimed_at,
                lease_seconds=self.lease_seconds,
            )
            job_id = job.id if job is not None else None
            session.commit()
        if job_id is None:
            return False
        try:
            self._execute(job_id)
        except Exception as exc:
            with self.session_factory() as session:
                ApprovalDecisionQueue(session).mark_needs_operator(
                    job_id,
                    self.worker_id,
                    str(exc),
                )
                session.commit()
        else:
            with self.session_factory() as session:
                ApprovalDecisionQueue(session).mark_succeeded(job_id, self.worker_id)
                session.commit()
        return True

    def _execute(self, job_id: int) -> None:
        with self.session_factory() as session:
            job = session.get(ApprovalDecisionJob, job_id)
            if job is None or job.status != "RUNNING" or job.lease_owner != self.worker_id:
                raise ApprovalJobStateError("approval job ownership was lost before execution")
            operator = session.get(Operator, job.operator_id)
            if operator is None or operator.status != "ACTIVE":
                raise ApprovalJobStateError("approval operator is no longer active")

            def event_checkpoint() -> None:
                ApprovalDecisionQueue(session).renew(
                    job.id,
                    self.worker_id,
                    lease_seconds=self.lease_seconds,
                )
                session.commit()

            runner = self.runner_factory(
                session,
                self.registry,
                event_checkpoint=event_checkpoint,
            )
            if job.decision == "APPROVE":
                runner.approve_and_execute_proposal(
                    job.proposal_id,
                    operator=operator.username,
                    comment="飞书审批已通过身份映射与一次性令牌校验。",
                )
            else:
                runner.reject_proposal(
                    job.proposal_id,
                    operator=operator.username,
                    comment="飞书审批已通过身份映射与一次性令牌校验。",
                )
            session.commit()


def _worker_id(value: str) -> str:
    normalized = " ".join(str(value).split())[:128]
    if not normalized:
        raise ValueError("worker_id is required")
    return normalized
