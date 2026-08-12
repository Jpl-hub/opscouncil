from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON
from pgvector.sqlalchemy import Vector

from backend.app.core.config import settings
from backend.app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_input: Mapped[str] = mapped_column(Text)
    intent: Mapped[str] = mapped_column(String(128), default="unknown")
    status: Mapped[str] = mapped_column(String(32), index=True)
    risk_level: Mapped[str] = mapped_column(String(8), default="R0")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sealed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events: Mapped[list["TaskEvent"]] = relationship(back_populates="task")
    tool_calls: Mapped[list["ToolCall"]] = relationship(back_populates="task")
    job: Mapped["TaskJob | None"] = relationship(back_populates="task", uselist=False)
    investigation: Mapped["Investigation | None"] = relationship(
        back_populates="task",
        uselist=False,
    )


class TaskJob(Base):
    __tablename__ = "task_jobs"
    __table_args__ = (
        CheckConstraint("attempt_count >= 0", name="ck_task_jobs_attempt_count_nonnegative"),
        Index("ix_task_jobs_claim", "status", "available_at", "id"),
        Index("ix_task_jobs_expired_lease", "status", "lease_expires_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="QUEUED", index=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    task: Mapped[Task] = relationship(back_populates="job")


class WorkerInstance(Base):
    __tablename__ = "worker_instances"
    __table_args__ = (
        CheckConstraint("pid > 0", name="ck_worker_instances_pid_positive"),
        CheckConstraint(
            "status IN ('RUNNING', 'STOPPED')",
            name="ck_worker_instances_status",
        ),
        Index("ix_worker_instances_health", "status", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    worker_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    pid: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="RUNNING", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        CheckConstraint("current_iteration >= 0", name="ck_investigations_current_iteration_nonnegative"),
        CheckConstraint("max_iterations > 0", name="ck_investigations_max_iterations_positive"),
        CheckConstraint("max_tool_calls > 0", name="ck_investigations_max_tool_calls_positive"),
        CheckConstraint("max_elapsed_ms > 0", name="ck_investigations_max_elapsed_ms_positive"),
        CheckConstraint(
            "status IN ('RUNNING', 'CONCLUDED', 'INCONCLUSIVE', 'NEEDS_OPERATOR', 'CANCELLED', 'FAILED')",
            name="ck_investigations_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="RUNNING", index=True)
    current_iteration: Mapped[int] = mapped_column(Integer, default=0)
    max_iterations: Mapped[int] = mapped_column(Integer, default=4)
    max_tool_calls: Mapped[int] = mapped_column(Integer, default=12)
    max_elapsed_ms: Mapped[int] = mapped_column(Integer, default=120000)
    stop_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    task: Mapped[Task] = relationship(back_populates="investigation")
    steps: Mapped[list["InvestigationStep"]] = relationship(
        back_populates="investigation",
        order_by="InvestigationStep.iteration",
    )
    evidence_items: Mapped[list["EvidenceItem"]] = relationship(back_populates="investigation")
    hypotheses: Mapped[list["Hypothesis"]] = relationship(back_populates="investigation")


class InvestigationStep(Base):
    __tablename__ = "investigation_steps"
    __table_args__ = (
        UniqueConstraint("investigation_id", "iteration", name="uq_investigation_step_iteration"),
        CheckConstraint("iteration > 0", name="ck_investigation_steps_iteration_positive"),
        CheckConstraint("duration_ms >= 0", name="ck_investigation_steps_duration_nonnegative"),
        CheckConstraint(
            "decision IS NULL OR decision IN ('COLLECT', 'CONCLUDE')",
            name="ck_investigation_steps_decision",
        ),
        CheckConstraint(
            "status IN ('DECIDED', 'COMPLETED', 'REJECTED', 'ERROR', 'CANCELLED')",
            name="ck_investigation_steps_status",
        ),
        Index("ix_investigation_steps_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    iteration: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="DECIDED")
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    decision_json: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_tool_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    requested_arguments_json: Mapped[dict] = mapped_column(JSON, default=dict)
    tool_call_id: Mapped[int | None] = mapped_column(ForeignKey("tool_calls.id"), nullable=True, index=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    investigation: Mapped[Investigation] = relationship(back_populates="steps")


class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    __table_args__ = (
        UniqueConstraint("investigation_id", "source_ref", name="uq_evidence_item_source_ref"),
        CheckConstraint(
            "source_type IN ('MCP', 'KNOWLEDGE')",
            name="ck_evidence_items_source_type",
        ),
        Index("ix_evidence_items_source", "source_type", "source_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    source_ref: Mapped[str] = mapped_column(String(512))
    source_type: Mapped[str] = mapped_column(String(32))
    source_key: Mapped[str] = mapped_column(String(256), index=True)
    tool_call_id: Mapped[int | None] = mapped_column(ForeignKey("tool_calls.id"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(256))
    summary: Mapped[str] = mapped_column(Text)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    trust_level: Mapped[str] = mapped_column(String(32))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation: Mapped[Investigation] = relationship(back_populates="evidence_items")
    hypothesis_links: Mapped[list["HypothesisEvidence"]] = relationship(
        back_populates="evidence_item"
    )


class Hypothesis(Base):
    __tablename__ = "hypotheses"
    __table_args__ = (
        UniqueConstraint("investigation_id", "key", name="uq_hypothesis_key"),
        CheckConstraint(
            "status IN ('OPEN', 'SUPPORTED', 'REJECTED', 'INCONCLUSIVE')",
            name="ck_hypotheses_status",
        ),
        CheckConstraint(
            "confidence_level IN ('LOW', 'MEDIUM', 'HIGH')",
            name="ck_hypotheses_confidence_level",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_hypotheses_confidence_score",
        ),
        CheckConstraint("first_seen_iteration > 0", name="ck_hypotheses_first_iteration_positive"),
        CheckConstraint("last_updated_iteration > 0", name="ck_hypotheses_last_iteration_positive"),
        Index("ix_hypotheses_status_confidence", "status", "confidence_level"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    key: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(256))
    rationale: Mapped[str] = mapped_column(Text)
    evidence_gap: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)
    confidence_level: Mapped[str] = mapped_column(String(16), default="LOW")
    confidence_score: Mapped[int] = mapped_column(Integer, default=0)
    first_seen_iteration: Mapped[int] = mapped_column(Integer)
    last_updated_iteration: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation: Mapped[Investigation] = relationship(back_populates="hypotheses")
    evidence_links: Mapped[list["HypothesisEvidence"]] = relationship(back_populates="hypothesis")


class HypothesisEvidence(Base):
    __tablename__ = "hypothesis_evidence"
    __table_args__ = (
        CheckConstraint(
            "relation IN ('SUPPORTS', 'REFUTES', 'CONTEXT')",
            name="ck_hypothesis_evidence_relation",
        ),
    )

    hypothesis_id: Mapped[int] = mapped_column(
        ForeignKey("hypotheses.id"),
        primary_key=True,
    )
    evidence_item_id: Mapped[int] = mapped_column(
        ForeignKey("evidence_items.id"),
        primary_key=True,
    )
    relation: Mapped[str] = mapped_column(String(16))
    rationale: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    hypothesis: Mapped[Hypothesis] = relationship(back_populates="evidence_links")
    evidence_item: Mapped[EvidenceItem] = relationship(back_populates="hypothesis_links")


class Conversation(Base):
    __tablename__ = "conversations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ConversationTurn(Base):
    __tablename__ = "conversation_turns"
    __table_args__ = (UniqueConstraint("conversation_id", "turn_index", name="uq_conversation_turn_index"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    conversation_id: Mapped[str] = mapped_column(ForeignKey("conversations.id"), index=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), unique=True, index=True)
    parent_task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id"), nullable=True, index=True)
    turn_index: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RiskChainAssessment(Base):
    __tablename__ = "risk_chain_assessments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('CLEAR', 'WATCH', 'BLOCKED')",
            name="ck_risk_chain_assessments_status",
        ),
        CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100",
            name="ck_risk_chain_assessments_score",
        ),
        Index(
            "ix_risk_chain_assessments_conversation_latest",
            "conversation_id",
            "created_at",
            "id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    conversation_id: Mapped[str | None] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    policy_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    chain_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    semantic_events_json: Mapped[list] = mapped_column(JSON, default=list)
    matched_task_ids_json: Mapped[list] = mapped_column(JSON, default=list)
    resource_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        index=True,
    )


class TaskEvent(Base):
    __tablename__ = "task_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    stage: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    message: Mapped[str] = mapped_column(Text)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    task: Mapped[Task] = relationship(back_populates="events")


class ToolCall(Base):
    __tablename__ = "tool_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    tool_version: Mapped[str] = mapped_column(String(32))
    input_json: Mapped[dict] = mapped_column(JSON, default=dict)
    output_json: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_level: Mapped[str] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(32), index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    task: Mapped[Task] = relationship(back_populates="tool_calls")


class SafetyReview(Base):
    __tablename__ = "safety_reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    review_type: Mapped[str] = mapped_column(String(64), index=True)
    risk_level: Mapped[str] = mapped_column(String(8))
    decision: Mapped[str] = mapped_column(String(32))
    matched_rules_json: Mapped[list] = mapped_column(JSON, default=list)
    reason: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[str] = mapped_column(
        String(64),
        default="legacy-unversioned",
    )
    policy_digest: Mapped[str] = mapped_column(String(64), default="")
    subject_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    provider: Mapped[str] = mapped_column(String(64), default="bailian")
    model: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), index=True)
    prompt_hash: Mapped[str] = mapped_column(String(64), index=True)
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_json: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    operator: Mapped[str] = mapped_column(String(128), default="local-admin")
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionProposal(Base):
    __tablename__ = "action_proposals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    input_json: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_level: Mapped[str] = mapped_column(String(8), index=True)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True)
    dry_run_result_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionSafetyCase(Base):
    __tablename__ = "action_safety_cases"
    __table_args__ = (
        CheckConstraint(
            "status IN ("
            "'READY', 'APPROVED', 'EXECUTING', 'VERIFIED', 'BLOCKED', "
            "'FAILED', 'NEEDS_OPERATOR', 'REJECTED', 'REVOKED'"
            ")",
            name="ck_action_safety_cases_status",
        ),
        Index(
            "ix_action_safety_cases_task_status",
            "task_id",
            "status",
            "id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"),
        index=True,
    )
    proposal_id: Mapped[int] = mapped_column(
        ForeignKey("action_proposals.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    risk_level: Mapped[str] = mapped_column(String(8), index=True)
    policy_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(24), default="READY", index=True)
    action_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    bound_action_json: Mapped[dict] = mapped_column(JSON, default=dict)
    scope_json: Mapped[dict] = mapped_column(JSON, default=dict)
    preconditions_json: Mapped[list] = mapped_column(JSON, default=list)
    postconditions_json: Mapped[list] = mapped_column(JSON, default=list)
    verifier_tool: Mapped[str] = mapped_column(String(128))
    rollback_strategy_json: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    result_json: Mapped[dict] = mapped_column(JSON, default=dict)
    case_hash: Mapped[str] = mapped_column(String(64), index=True)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pre_verifier_call_id: Mapped[int | None] = mapped_column(
        ForeignKey("tool_calls.id"),
        nullable=True,
    )
    execution_call_id: Mapped[int | None] = mapped_column(
        ForeignKey("tool_calls.id"),
        nullable=True,
    )
    post_verifier_call_id: Mapped[int | None] = mapped_column(
        ForeignKey("tool_calls.id"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExecutionRecord(Base):
    __tablename__ = "execution_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    proposal_id: Mapped[int | None] = mapped_column(ForeignKey("action_proposals.id"), nullable=True, index=True)
    tool_call_id: Mapped[int | None] = mapped_column(ForeignKey("tool_calls.id"), nullable=True, index=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    risk_level: Mapped[str] = mapped_column(String(8))
    executor_mode: Mapped[str] = mapped_column(String(64))
    runtime_user: Mapped[str] = mapped_column(String(128))
    runtime_uid: Mapped[int] = mapped_column(Integer)
    target_user: Mapped[str] = mapped_column(String(128))
    allowed: Mapped[str] = mapped_column(String(16), index=True)
    reason: Mapped[str] = mapped_column(Text)
    scope_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditChain(Base):
    __tablename__ = "audit_chain"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("task_events.id"), index=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    payload_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SystemSnapshot(Base):
    __tablename__ = "system_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id"), nullable=True, index=True)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PlatformCapabilitySnapshot(Base):
    __tablename__ = "platform_capability_snapshots"
    __table_args__ = (
        CheckConstraint(
            "status IN ('SUPPORTED', 'DEGRADED', 'UNAVAILABLE')",
            name="ck_platform_capability_snapshots_status",
        ),
        Index(
            "ix_platform_capability_snapshots_node_latest",
            "hostname",
            "created_at",
            "id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("tasks.id"),
        unique=True,
        index=True,
    )
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    machine: Mapped[str] = mapped_column(String(128))
    kernel: Mapped[str] = mapped_column(String(255))
    os_name: Mapped[str] = mapped_column(String(255))
    profile_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), index=True)
    payload_hash: Mapped[str] = mapped_column(String(64), index=True)
    payload_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
        index=True,
    )

    task: Mapped[Task] = relationship()


class EvaluationReport(Base):
    __tablename__ = "evaluation_reports"
    __table_args__ = (
        CheckConstraint(
            "report_type IN ('TOOL_PERFORMANCE', 'AGENT_ORCHESTRATION', 'SAFETY_GUARD', 'LAB_SCENARIO', 'OPERATIONAL_MEMORY')",
            name="ck_evaluation_reports_type",
        ),
        Index("ix_evaluation_reports_latest", "report_type", "created_at", "id"),
        Index(
            "ix_evaluation_reports_scope_latest",
            "report_type",
            "scope_key",
            "created_at",
            "id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_type: Mapped[str] = mapped_column(String(32), index=True)
    report_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scope_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    payload_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class PatrolPolicy(Base):
    __tablename__ = "patrol_policies"
    __table_args__ = (
        CheckConstraint("interval_seconds >= 60", name="ck_patrol_policies_interval"),
        Index("ix_patrol_policies_due", "enabled", "next_run_at", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    signal_keys_json: Mapped[list] = mapped_column(JSON, default=list)
    thresholds_json: Mapped[dict] = mapped_column(JSON, default=dict)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PatrolRun(Base):
    __tablename__ = "patrol_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('RUNNING', 'SUCCEEDED', 'FAILED')",
            name="ck_patrol_runs_status",
        ),
        Index("ix_patrol_runs_host_started", "host_key", "started_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("patrol_policies.id"), index=True)
    host_key: Mapped[str] = mapped_column(String(256), index=True)
    status: Mapped[str] = mapped_column(String(32), default="RUNNING", index=True)
    snapshot_json: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED')",
            name="ck_incidents_status",
        ),
        CheckConstraint(
            "severity IN ('WARN', 'CRITICAL')",
            name="ck_incidents_severity",
        ),
        CheckConstraint("healthy_streak >= 0", name="ck_incidents_healthy_streak"),
        CheckConstraint(
            "recovery_target >= 1 AND recovery_target <= 12",
            name="ck_incidents_recovery_target",
        ),
        Index("ix_incidents_open", "status", "severity", "updated_at"),
        Index("ix_incidents_host_signal", "host_key", "signal_key", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_key: Mapped[str] = mapped_column(String(256), index=True)
    signal_key: Mapped[str] = mapped_column(String(128), index=True)
    dedupe_key: Mapped[str | None] = mapped_column(String(512), nullable=True, unique=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(256))
    summary: Mapped[str] = mapped_column(Text)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id"), nullable=True, unique=True, index=True)
    healthy_streak: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    recovery_target: Mapped[int] = mapped_column(Integer, default=2, server_default="2")
    last_healthy_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('WARN', 'CRITICAL')",
            name="ck_findings_severity",
        ),
        CheckConstraint(
            "status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')",
            name="ck_findings_status",
        ),
        CheckConstraint("occurrence_count >= 1", name="ck_findings_occurrence_count"),
        Index("ix_findings_open", "status", "severity", "last_observed_at"),
        Index("ix_findings_host_signal", "host_key", "signal_key", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("patrol_policies.id"), index=True)
    patrol_run_id: Mapped[int] = mapped_column(ForeignKey("patrol_runs.id"), index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    host_key: Mapped[str] = mapped_column(String(256), index=True)
    signal_key: Mapped[str] = mapped_column(String(128), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)
    title: Mapped[str] = mapped_column(String(256))
    summary: Mapped[str] = mapped_column(Text)
    metric_json: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ConfigBaseline(Base):
    __tablename__ = "config_baselines"
    __table_args__ = (
        CheckConstraint("scope IN ('LIVE', 'LAB')", name="ck_config_baselines_scope"),
        Index("ix_config_baselines_scope_latest", "scope", "created_at", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    scope: Mapped[str] = mapped_column(
        String(16),
        default="LIVE",
        server_default="LIVE",
        index=True,
    )
    paths_json: Mapped[list] = mapped_column(JSON, default=list)
    snapshot_json: Mapped[list] = mapped_column(JSON, default=list)
    warnings_json: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(128), default="local-admin")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ConfigBaselineCheck(Base):
    __tablename__ = "config_baseline_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    baseline_id: Mapped[int] = mapped_column(ForeignKey("config_baselines.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    summary_json: Mapped[dict] = mapped_column(JSON, default=dict)
    changes_json: Mapped[list] = mapped_column(JSON, default=list)
    current_snapshot_json: Mapped[list] = mapped_column(JSON, default=list)
    warnings_json: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceExpectation(Base):
    __tablename__ = "service_expectations"
    __table_args__ = (
        UniqueConstraint(
            "host_key",
            "unit_name",
            "version",
            name="uq_service_expectations_host_unit_version",
        ),
        CheckConstraint("version >= 1", name="ck_service_expectations_version"),
        CheckConstraint(
            "record_status IN ('ACTIVE', 'RETIRED')",
            name="ck_service_expectations_record_status",
        ),
        CheckConstraint(
            "expected_active_state IN ('active', 'inactive')",
            name="ck_service_expectations_active_state",
        ),
        CheckConstraint(
            "criticality IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name="ck_service_expectations_criticality",
        ),
        CheckConstraint(
            "environment IN ('PRODUCTION', 'STAGING', 'TEST', 'DEVELOPMENT')",
            name="ck_service_expectations_environment",
        ),
        Index(
            "ix_service_expectations_lookup",
            "host_key",
            "unit_name",
            "version",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_key: Mapped[str] = mapped_column(String(256), index=True)
    unit_name: Mapped[str] = mapped_column(String(256), index=True)
    version: Mapped[int] = mapped_column(Integer)
    record_status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)
    expected_active_state: Mapped[str] = mapped_column(String(16))
    service_owner: Mapped[str] = mapped_column(String(256))
    criticality: Mapped[str] = mapped_column(String(16), index=True)
    environment: Mapped[str] = mapped_column(String(16))
    listener_expectations_json: Mapped[list] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(Text)
    source_ref: Mapped[str] = mapped_column(Text)
    approved_by: Mapped[str] = mapped_column(String(128))
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"
    __table_args__ = (
        CheckConstraint("version >= 1", name="ck_knowledge_documents_version"),
        CheckConstraint("status IN ('ACTIVE', 'INACTIVE')", name="ck_knowledge_documents_status"),
        Index("ix_knowledge_documents_status_type", "status", "source_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(256))
    source_type: Mapped[str] = mapped_column(String(64))
    source_uri: Mapped[str] = mapped_column(Text)
    trust_level: Mapped[str] = mapped_column(String(32), default="internal")
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class KnowledgeChunk(Base):
    __tablename__ = "knowledge_chunks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("knowledge_documents.id"), index=True)
    chunk_index: Mapped[int] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text)
    search_text: Mapped[str] = mapped_column(Text, default="")
    chunk_kind: Mapped[str] = mapped_column(String(64), default="content")
    vector_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(settings.embedding_dim), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)


class OperationalMemory(Base):
    __tablename__ = "operational_memories"
    __table_args__ = (
        UniqueConstraint("memory_key", "version", name="uq_operational_memory_version"),
        CheckConstraint("version >= 1", name="ck_operational_memories_version"),
        CheckConstraint(
            "status IN ('DRAFT', 'CONFLICTED', 'CONFIRMED', 'CORRECTED', 'INACTIVE', 'FORGOTTEN')",
            name="ck_operational_memories_status",
        ),
        CheckConstraint(
            "memory_kind IN ('INCIDENT_CASE', 'OPERATOR_PREFERENCE', 'PROCEDURE_DRAFT')",
            name="ck_operational_memories_kind",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_operational_memories_confidence",
        ),
        CheckConstraint(
            "retrieval_count >= 0 AND helpful_count >= 0 AND incorrect_count >= 0",
            name="ck_operational_memories_feedback_counts",
        ),
        CheckConstraint(
            "qualification_status IN ('PENDING', 'QUALIFIED', 'FAILED')",
            name="ck_operational_memories_qualification",
        ),
        Index("ix_operational_memories_scope", "status", "host_scope", "service_scope"),
        Index(
            "ix_operational_memories_governance",
            "status",
            "memory_kind",
            "symptom_fingerprint",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    memory_key: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16), default="DRAFT", index=True)
    memory_kind: Mapped[str] = mapped_column(String(32), default="INCIDENT_CASE", index=True)
    source_task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    supersedes_id: Mapped[int | None] = mapped_column(
        ForeignKey("operational_memories.id"),
        nullable=True,
        index=True,
    )
    host_scope: Mapped[str] = mapped_column(String(256), default="*")
    service_scope: Mapped[str] = mapped_column(String(256), default="*")
    symptom_fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)
    applicability_json: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence_score: Mapped[int] = mapped_column(Integer, default=50)
    title: Mapped[str] = mapped_column(String(256))
    root_cause: Mapped[str] = mapped_column(Text)
    resolution: Mapped[str] = mapped_column(Text)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    parent_content_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    search_text: Mapped[str] = mapped_column(Text)
    embedding: Mapped[list[float]] = mapped_column(Vector(settings.embedding_dim))
    created_by: Mapped[str] = mapped_column(String(128))
    confirmed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    retrieval_count: Mapped[int] = mapped_column(Integer, default=0)
    helpful_count: Mapped[int] = mapped_column(Integer, default=0)
    incorrect_count: Mapped[int] = mapped_column(Integer, default=0)
    qualification_status: Mapped[str] = mapped_column(
        String(16),
        default="PENDING",
        index=True,
    )
    qualification_report_json: Mapped[dict] = mapped_column(JSON, default=dict)
    qualified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    forgotten_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    forgotten_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    forget_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class OperationalMemoryRelation(Base):
    __tablename__ = "operational_memory_relations"
    __table_args__ = (
        UniqueConstraint(
            "source_memory_id",
            "target_memory_id",
            "relation",
            name="uq_operational_memory_relation",
        ),
        CheckConstraint(
            "source_memory_id <> target_memory_id",
            name="ck_operational_memory_relation_distinct",
        ),
        CheckConstraint(
            "relation IN ('SUPPORTS', 'DUPLICATES', 'CONFLICTS', 'SUPERSEDES')",
            name="ck_operational_memory_relation_type",
        ),
        CheckConstraint(
            "status IN ('PENDING', 'RESOLVED', 'DISMISSED')",
            name="ck_operational_memory_relation_status",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 100",
            name="ck_operational_memory_relation_confidence",
        ),
        Index(
            "ix_operational_memory_relations_pending",
            "status",
            "relation",
            "created_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_memory_id: Mapped[int] = mapped_column(
        ForeignKey("operational_memories.id", ondelete="CASCADE"),
        index=True,
    )
    target_memory_id: Mapped[int] = mapped_column(
        ForeignKey("operational_memories.id", ondelete="CASCADE"),
        index=True,
    )
    relation: Mapped[str] = mapped_column(String(16), index=True)
    reason: Mapped[str] = mapped_column(Text)
    confidence_score: Mapped[int] = mapped_column(Integer, default=100)
    detected_by: Mapped[str] = mapped_column(String(32), default="governance_policy")
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OperatorFeedback(Base):
    __tablename__ = "operator_feedback"
    __table_args__ = (
        CheckConstraint(
            "verdict IN ('HELPFUL', 'INCOMPLETE', 'INCORRECT')",
            name="ck_operator_feedback_verdict",
        ),
        Index("ix_operator_feedback_task_memory", "task_id", "memory_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    memory_id: Mapped[int | None] = mapped_column(
        ForeignKey("operational_memories.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor: Mapped[str] = mapped_column(String(128))
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    correction: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OperatorPreferenceProfile(Base):
    __tablename__ = "operator_preference_profiles"
    __table_args__ = (
        UniqueConstraint("actor_key", name="uq_operator_preference_profiles_actor"),
        CheckConstraint("version >= 1", name="ck_operator_preference_profiles_version"),
        CheckConstraint(
            "summary_density IN ('COMPACT', 'BALANCED', 'DETAILED')",
            name="ck_operator_preference_profiles_summary_density",
        ),
        CheckConstraint(
            "evidence_view IN ('CORE', 'ALL')",
            name="ck_operator_preference_profiles_evidence_view",
        ),
        CheckConstraint(
            "notification_route IN ('WEB', 'FEISHU', 'BOTH')",
            name="ck_operator_preference_profiles_notification_route",
        ),
        Index("ix_operator_preference_profiles_updated", "updated_at", "actor_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_key: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    summary_density: Mapped[str] = mapped_column(String(16), default="BALANCED")
    evidence_view: Mapped[str] = mapped_column(String(16), default="CORE")
    notification_route: Mapped[str] = mapped_column(String(16), default="WEB")
    service_focus_json: Mapped[list] = mapped_column(JSON, default=list)
    learning_signals_json: Mapped[dict] = mapped_column(JSON, default=dict)
    learned_intents_json: Mapped[list] = mapped_column(JSON, default=list)
    change_log_json: Mapped[list] = mapped_column(JSON, default=list)
    last_learning_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ModelInvocation(Base):
    __tablename__ = "model_invocations"
    __table_args__ = (
        CheckConstraint(
            "operation IN ('CHAT', 'EMBEDDING', 'RERANK')",
            name="ck_model_invocations_operation",
        ),
        CheckConstraint(
            "status IN ('SUCCEEDED', 'FAILED')",
            name="ck_model_invocations_status",
        ),
        CheckConstraint("duration_ms >= 0", name="ck_model_invocations_duration"),
        CheckConstraint(
            "input_tokens IS NULL OR input_tokens >= 0",
            name="ck_model_invocations_input_tokens",
        ),
        CheckConstraint(
            "output_tokens IS NULL OR output_tokens >= 0",
            name="ck_model_invocations_output_tokens",
        ),
        CheckConstraint(
            "total_tokens IS NULL OR total_tokens >= 0",
            name="ck_model_invocations_total_tokens",
        ),
        Index("ix_model_invocations_trace_time", "trace_id", "created_at", "id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE"),
        index=True,
    )
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    stage: Mapped[str] = mapped_column(String(64), index=True)
    operation: Mapped[str] = mapped_column(String(16))
    provider: Mapped[str] = mapped_column(String(32), default="bailian")
    model: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finish_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Operator(Base):
    __tablename__ = "operators"
    __table_args__ = (
        CheckConstraint(
            "role IN ('VIEWER', 'OPERATOR', 'APPROVER', 'ADMIN')",
            name="ck_operators_role",
        ),
        CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED')",
            name="ck_operators_status",
        ),
        Index("ix_operators_role_status", "role", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default="OPERATOR", index=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OperatorExternalIdentity(Base):
    __tablename__ = "operator_external_identities"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "tenant_key",
            "external_user_id",
            name="uq_operator_external_identity",
        ),
        CheckConstraint("provider IN ('FEISHU')", name="ck_operator_external_identities_provider"),
        CheckConstraint(
            "status IN ('ACTIVE', 'DISABLED')",
            name="ck_operator_external_identities_status",
        ),
        Index("ix_operator_external_identities_operator", "operator_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    operator_id: Mapped[int] = mapped_column(ForeignKey("operators.id"), index=True)
    provider: Mapped[str] = mapped_column(String(16), default="FEISHU", index=True)
    tenant_key: Mapped[str] = mapped_column(String(128))
    external_user_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChannelInboundEvent(Base):
    __tablename__ = "channel_inbound_events"
    __table_args__ = (
        UniqueConstraint("channel", "external_event_id", name="uq_channel_inbound_event"),
        CheckConstraint("channel IN ('FEISHU')", name="ck_channel_inbound_events_channel"),
        CheckConstraint(
            "status IN ('ACCEPTED', 'REJECTED')",
            name="ck_channel_inbound_events_status",
        ),
        Index("ix_channel_inbound_events_created", "channel", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    channel: Mapped[str] = mapped_column(String(16), default="FEISHU", index=True)
    external_event_id: Mapped[str] = mapped_column(String(256))
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    tenant_key: Mapped[str] = mapped_column(String(128))
    external_actor_id: Mapped[str] = mapped_column(String(128))
    payload_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), index=True)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operator_id: Mapped[int | None] = mapped_column(
        ForeignKey("operators.id"),
        nullable=True,
        index=True,
    )
    task_id: Mapped[int | None] = mapped_column(
        ForeignKey("tasks.id"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TaskChannelBinding(Base):
    __tablename__ = "task_channel_bindings"
    __table_args__ = (
        UniqueConstraint("channel", "external_message_id", name="uq_task_channel_message"),
        CheckConstraint("channel IN ('FEISHU')", name="ck_task_channel_bindings_channel"),
        Index("ix_task_channel_bindings_chat", "channel", "tenant_key", "external_chat_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), unique=True, index=True)
    channel: Mapped[str] = mapped_column(String(16), default="FEISHU", index=True)
    tenant_key: Mapped[str] = mapped_column(String(128))
    external_chat_id: Mapped[str] = mapped_column(String(256))
    external_message_id: Mapped[str] = mapped_column(String(256))
    operator_id: Mapped[int] = mapped_column(ForeignKey("operators.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ChannelInstance(Base):
    __tablename__ = "channel_instances"
    __table_args__ = (
        UniqueConstraint("channel", "instance_id", name="uq_channel_instance"),
        CheckConstraint("channel IN ('FEISHU')", name="ck_channel_instances_channel"),
        CheckConstraint(
            "status IN ('CONNECTED', 'DEGRADED', 'STOPPED')",
            name="ck_channel_instances_status",
        ),
        Index("ix_channel_instances_health", "channel", "status", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    channel: Mapped[str] = mapped_column(String(16), default="FEISHU", index=True)
    instance_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), index=True)
    detail_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotificationOutbox(Base):
    __tablename__ = "notification_outbox"
    __table_args__ = (
        CheckConstraint("channel IN ('FEISHU')", name="ck_notification_outbox_channel"),
        CheckConstraint(
            "kind IN ('TASK_ACCEPTED', 'TASK_RESULT', 'INCIDENT', 'INVESTIGATION', 'APPROVAL_REQUEST', "
            "'EXECUTION', 'VERIFICATION', 'ROLLBACK', 'CHANNEL_NOTICE')",
            name="ck_notification_outbox_kind",
        ),
        CheckConstraint(
            "recipient_type IN ('CHAT_ID', 'OPEN_ID')",
            name="ck_notification_outbox_recipient_type",
        ),
        CheckConstraint(
            "status IN ('PENDING', 'SENDING', 'SENT', 'FAILED', 'CANCELLED')",
            name="ck_notification_outbox_status",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_notification_outbox_attempt_count"),
        CheckConstraint("max_attempts > 0", name="ck_notification_outbox_max_attempts"),
        Index("ix_notification_outbox_claim", "status", "available_at", "id"),
        Index("ix_notification_outbox_lease", "status", "lease_expires_at"),
        Index("ix_notification_outbox_task", "task_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    channel: Mapped[str] = mapped_column(String(16), default="FEISHU", index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id"), nullable=True, index=True)
    task_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("task_events.id"),
        nullable=True,
        index=True,
    )
    proposal_id: Mapped[int | None] = mapped_column(
        ForeignKey("action_proposals.id"),
        nullable=True,
        index=True,
    )
    target_operator_id: Mapped[int | None] = mapped_column(
        ForeignKey("operators.id"),
        nullable=True,
        index=True,
    )
    recipient_type: Mapped[str] = mapped_column(String(16))
    recipient_id: Mapped[str] = mapped_column(String(256))
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    dedupe_key: Mapped[str] = mapped_column(String(256), unique=True)
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (
        UniqueConstraint("outbox_id", "attempt_no", name="uq_notification_delivery_attempt"),
        CheckConstraint("attempt_no > 0", name="ck_notification_deliveries_attempt_no"),
        CheckConstraint("duration_ms >= 0", name="ck_notification_deliveries_duration"),
        CheckConstraint(
            "status IN ('SENT', 'FAILED')",
            name="ck_notification_deliveries_status",
        ),
        Index("ix_notification_deliveries_created", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    outbox_id: Mapped[int] = mapped_column(ForeignKey("notification_outbox.id"), index=True)
    attempt_no: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), index=True)
    provider_message_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    provider_card_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApprovalDecisionToken(Base):
    __tablename__ = "approval_decision_tokens"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('APPROVE', 'REJECT')",
            name="ck_approval_decision_tokens_decision",
        ),
        CheckConstraint(
            "status IN ('ACTIVE', 'CONSUMED', 'REVOKED', 'EXPIRED')",
            name="ck_approval_decision_tokens_status",
        ),
        Index(
            "ix_approval_decision_tokens_lookup",
            "proposal_id",
            "operator_id",
            "status",
            "expires_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    proposal_id: Mapped[int] = mapped_column(ForeignKey("action_proposals.id"), index=True)
    operator_id: Mapped[int] = mapped_column(ForeignKey("operators.id"), index=True)
    decision: Mapped[str] = mapped_column(String(16))
    action_fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    inbound_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("channel_inbound_events.id"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApprovalDecisionJob(Base):
    __tablename__ = "approval_decision_jobs"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('APPROVE', 'REJECT')",
            name="ck_approval_decision_jobs_decision",
        ),
        CheckConstraint(
            "status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'NEEDS_OPERATOR')",
            name="ck_approval_decision_jobs_status",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_approval_decision_jobs_attempt_count"),
        Index("ix_approval_decision_jobs_claim", "status", "available_at", "id"),
        Index("ix_approval_decision_jobs_lease", "status", "lease_expires_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    proposal_id: Mapped[int] = mapped_column(ForeignKey("action_proposals.id"), unique=True, index=True)
    token_id: Mapped[int] = mapped_column(
        ForeignKey("approval_decision_tokens.id"),
        unique=True,
        index=True,
    )
    operator_id: Mapped[int] = mapped_column(ForeignKey("operators.id"), index=True)
    decision: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default="QUEUED", index=True)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IncidentCollaboration(Base):
    __tablename__ = "incident_collaborations"
    __table_args__ = (
        CheckConstraint(
            "status IN ("
            "'TRIAGING', 'INVESTIGATING', 'PLANNING', 'WAITING_EXECUTION', "
            "'VERIFYING', 'LEARNING', 'RESOLVED', 'NEEDS_OPERATOR', 'FAILED'"
            ")",
            name="ck_incident_collaborations_status",
        ),
        CheckConstraint(
            "evidence_gate_status IN ('PENDING', 'PASSED', 'FAILED', 'OVERRIDDEN')",
            name="ck_incident_collaborations_evidence_gate",
        ),
        CheckConstraint(
            "autonomy_mode IN ("
            "'UNDECIDED', 'OBSERVE_ONLY', 'AUTO_REVERSIBLE', 'HUMAN_GATED', 'BLOCKED'"
            ")",
            name="ck_incident_collaborations_autonomy_mode",
        ),
        Index(
            "ix_incident_collaborations_status_updated",
            "status",
            "updated_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    team_name: Mapped[str] = mapped_column(String(128), default="operations-response")
    status: Mapped[str] = mapped_column(String(32), default="TRIAGING", index=True)
    evidence_gate_status: Mapped[str] = mapped_column(String(16), default="PENDING")
    autonomy_mode: Mapped[str] = mapped_column(String(32), default="UNDECIDED")
    agentteams_room_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    context_version: Mapped[int] = mapped_column(Integer, default=1)
    shared_context_json: Mapped[dict] = mapped_column(JSON, default=dict)
    action_contract_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    action_contract_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    execution_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentWorkItem(Base):
    __tablename__ = "agent_work_items"
    __table_args__ = (
        UniqueConstraint(
            "collaboration_id",
            "work_key",
            name="uq_agent_work_items_collaboration_key",
        ),
        CheckConstraint(
            "status IN ("
            "'PENDING', 'READY', 'RUNNING', 'SUCCEEDED', 'FAILED', 'BLOCKED', 'CANCELLED'"
            ")",
            name="ck_agent_work_items_status",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_agent_work_items_attempt_count"),
        Index(
            "ix_agent_work_items_ready",
            "status",
            "role",
            "created_at",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    collaboration_id: Mapped[int] = mapped_column(
        ForeignKey("incident_collaborations.id", ondelete="CASCADE"),
        index=True,
    )
    work_key: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(64), index=True)
    skill_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    depends_on_json: Mapped[list] = mapped_column(JSON, default=list)
    input_json: Mapped[dict] = mapped_column(JSON, default=dict)
    output_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, default=list)
    assigned_agent: Mapped[str | None] = mapped_column(String(128), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CollaborationEvent(Base):
    __tablename__ = "collaboration_events"
    __table_args__ = (
        UniqueConstraint(
            "collaboration_id",
            "sequence",
            name="uq_collaboration_events_sequence",
        ),
        UniqueConstraint(
            "source_system",
            "source_event_id",
            name="uq_collaboration_events_source",
        ),
        CheckConstraint("sequence > 0", name="ck_collaboration_events_sequence"),
        CheckConstraint("length(payload_hash) = 64", name="ck_collaboration_events_payload_hash"),
        CheckConstraint("length(event_hash) = 64", name="ck_collaboration_events_event_hash"),
        CheckConstraint(
            "prev_hash IS NULL OR length(prev_hash) = 64",
            name="ck_collaboration_events_prev_hash",
        ),
        Index(
            "ix_collaboration_events_timeline",
            "collaboration_id",
            "sequence",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    collaboration_id: Mapped[int] = mapped_column(
        ForeignKey("incident_collaborations.id", ondelete="CASCADE"),
        index=True,
    )
    work_item_id: Mapped[int | None] = mapped_column(
        ForeignKey("agent_work_items.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    source_system: Mapped[str] = mapped_column(String(64), default="opscouncil")
    source_event_id: Mapped[str] = mapped_column(String(128))
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
