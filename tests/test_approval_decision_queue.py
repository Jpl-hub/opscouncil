from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.channels.feishu.approval_queue import (
    ApprovalDecisionProcessor,
    ApprovalDecisionQueue,
)
from backend.app.models.entities import (
    ActionProposal,
    AuditChain,
    ApprovalDecisionJob,
    ApprovalDecisionToken,
    Operator,
    Task,
    TaskEvent,
)


TABLES = (
    Operator,
    Task,
    TaskEvent,
    AuditChain,
    ActionProposal,
    ApprovalDecisionToken,
    ApprovalDecisionJob,
)


def build_factory() -> sessionmaker[Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    for model in TABLES:
        model.__table__.create(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def add_job(factory: sessionmaker[Session], *, decision: str = "APPROVE") -> int:
    with factory() as session:
        operator = Operator(
            username="approver-a",
            display_name="审批负责人",
            role="APPROVER",
            status="ACTIVE",
        )
        task = Task(
            trace_id="trace-approval-job",
            user_input="处置日志",
            intent="disk_pressure_analysis",
            status="SEALED",
            risk_level="R2",
        )
        session.add_all([operator, task])
        session.flush()
        proposal = ActionProposal(
            task_id=task.id,
            tool_name="safe_log_rotate",
            input_json={"path": "/tmp/app.log", "dry_run": False},
            risk_level="R2",
            reason="test",
            status="PENDING_APPROVAL",
        )
        session.add(proposal)
        session.flush()
        token = ApprovalDecisionToken(
            token_hash="a" * 64,
            proposal_id=proposal.id,
            operator_id=operator.id,
            decision=decision,
            action_fingerprint="b" * 64,
            status="CONSUMED",
            expires_at=datetime(2026, 7, 12, 15, 0, tzinfo=timezone.utc),
        )
        session.add(token)
        session.flush()
        job = ApprovalDecisionJob(
            proposal_id=proposal.id,
            token_id=token.id,
            operator_id=operator.id,
            decision=decision,
            status="QUEUED",
            available_at=datetime(2026, 7, 12, 13, 59, tzinfo=timezone.utc),
        )
        session.add(job)
        session.commit()
        return job.id


def test_approval_job_claim_and_abandoned_lease_never_replays() -> None:
    factory = build_factory()
    job_id = add_job(factory)
    now = datetime(2026, 7, 12, 14, 0, tzinfo=timezone.utc)
    with factory() as session:
        queue = ApprovalDecisionQueue(session)
        claimed = queue.claim_next("worker-a", now=now, lease_seconds=30)
        assert claimed is not None
        assert claimed.id == job_id
        assert claimed.status == "RUNNING"
        session.commit()

    with factory() as session:
        affected = ApprovalDecisionQueue(session).fail_abandoned_leases(
            now + timedelta(seconds=31)
        )
        session.commit()
        job = session.get(ApprovalDecisionJob, job_id)
        assert affected == [job_id]
        assert job is not None
        assert job.status == "NEEDS_OPERATOR"
        assert ApprovalDecisionQueue(session).claim_next(
            "worker-b",
            now=now + timedelta(seconds=40),
        ) is None


class FakeRunner:
    calls: list[tuple[str, int, str]] = []

    def __init__(
        self,
        session: Session,
        registry: object,
        *,
        event_checkpoint=None,  # type: ignore[no-untyped-def]
    ) -> None:
        self.session = session

    def approve_and_execute_proposal(self, proposal_id: int, operator: str, comment: str):
        self.calls.append(("APPROVE", proposal_id, operator))
        proposal = self.session.get(ActionProposal, proposal_id)
        assert proposal is not None
        proposal.status = "EXECUTED"

    def reject_proposal(self, proposal_id: int, operator: str, comment: str):
        self.calls.append(("REJECT", proposal_id, operator))
        proposal = self.session.get(ActionProposal, proposal_id)
        assert proposal is not None
        proposal.status = "REJECTED"


def test_processor_hands_decision_to_existing_agent_approval_workflow() -> None:
    factory = build_factory()
    job_id = add_job(factory, decision="REJECT")
    FakeRunner.calls = []
    processor = ApprovalDecisionProcessor(
        factory,
        registry=object(),
        worker_id="approval-worker",
        runner_factory=FakeRunner,
    )

    worked = processor.run_once(now=datetime(2026, 7, 12, 14, 0, tzinfo=timezone.utc))

    assert worked is True
    with factory() as session:
        job = session.get(ApprovalDecisionJob, job_id)
        proposal = session.get(ActionProposal, job.proposal_id if job else 0)
        assert job is not None and proposal is not None
        assert job.status == "SUCCEEDED"
        assert proposal.status == "REJECTED"
        assert FakeRunner.calls == [("REJECT", proposal.id, "approver-a")]
