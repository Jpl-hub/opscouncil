from __future__ import annotations

from typing import Any, Literal

from backend.app.core.pydantic_compat import BaseModel, Field, field_validator


EvidenceRef = str


class CorrelatedSignal(BaseModel):
    signal_key: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    observed_at: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=500)
    evidence_ref: EvidenceRef = Field(min_length=1, max_length=256)


class TriageOutput(BaseModel):
    incident_boundary: str = Field(min_length=1, max_length=1000)
    correlated_signals: list[CorrelatedSignal] = Field(min_items=1, max_items=100)
    suppressed_alert_count: int = Field(default=0, ge=0)
    severity: Literal["INFO", "WARN", "CRITICAL"]
    affected_resources: list[str] = Field(default_factory=list, max_items=100)
    evidence_refs: list[EvidenceRef] = Field(min_items=1, max_items=200)


class CausalHypothesis(BaseModel):
    key: str = Field(min_length=1, max_length=64)
    claim: str = Field(min_length=1, max_length=1000)
    status: Literal["SUPPORTED", "REFUTED", "OPEN"]
    evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_items=100)
    counter_evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_items=100)


class InvestigationOutput(BaseModel):
    decision: Literal["COLLECT_MORE", "CONCLUDE"]
    hypotheses: list[CausalHypothesis] = Field(min_items=1, max_items=20)
    root_cause: str | None = Field(default=None, max_length=2000)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_items=300)
    counter_evidence_reviewed: bool = False
    missing_evidence: list[str] = Field(default_factory=list, max_items=20)


class ActionContract(BaseModel):
    proposal_id: int | None = Field(default=None, ge=1)
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    risk_level: Literal["R0", "R1", "R2", "R3", "R4"]
    environment: Literal["LAB", "STAGING", "PRODUCTION"]
    target_scope: list[str] = Field(min_items=1, max_items=100)
    preconditions: list[str] = Field(min_items=1, max_items=50)
    postconditions: list[str] = Field(min_items=1, max_items=50)
    rollback_steps: list[str] = Field(default_factory=list, max_items=50)
    reversible: bool
    canary: bool = False
    policy_authorization_ref: str | None = Field(default=None, max_length=256)
    rationale: str = Field(min_length=1, max_length=2000)

    @field_validator("rollback_steps")
    @classmethod
    def reversible_actions_require_rollback(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if item.strip()]


class RemediationOutput(BaseModel):
    action: ActionContract
    evidence_refs: list[EvidenceRef] = Field(min_items=1, max_items=200)
    alternatives_rejected: list[str] = Field(default_factory=list, max_items=20)


class ExecutionOutput(BaseModel):
    outcome: Literal["SUCCEEDED", "FAILED", "UNKNOWN", "SKIPPED"]
    controller: Literal["restricted-executor"] = "restricted-executor"
    action_contract_hash: str = Field(min_length=64, max_length=64)
    execution_ref: str = Field(min_length=1, max_length=256)
    evidence_refs: list[EvidenceRef] = Field(min_items=1, max_items=200)
    rollback_performed: bool = False
    detail: str = Field(min_length=1, max_length=2000)


class VerificationCheck(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    status: Literal["PASS", "FAIL", "UNKNOWN"]
    observed: str = Field(min_length=1, max_length=1000)
    evidence_ref: EvidenceRef = Field(min_length=1, max_length=256)


class VerificationOutput(BaseModel):
    verdict: Literal["HEALTHY", "UNHEALTHY", "INCONCLUSIVE"]
    checks: list[VerificationCheck] = Field(min_items=1, max_items=50)
    observation_window_seconds: int = Field(ge=1, le=86400)
    regression_detected: bool
    rollback_required: bool
    evidence_refs: list[EvidenceRef] = Field(min_items=1, max_items=200)
    summary: str = Field(min_length=1, max_length=2000)


class LearningOutput(BaseModel):
    incident_summary: str = Field(min_length=1, max_length=3000)
    reusable_pattern: str | None = Field(default=None, max_length=2000)
    skill_candidate: bool = False
    qualification_evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_items=200)


OUTPUT_MODELS: dict[str, type[BaseModel]] = {
    "triage": TriageOutput,
    "investigate": InvestigationOutput,
    "plan": RemediationOutput,
    "execute": ExecutionOutput,
    "verify": VerificationOutput,
    "learn": LearningOutput,
}


def validate_output(work_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    model = OUTPUT_MODELS.get(work_key)
    if model is None:
        raise ValueError(f"unsupported work item: {work_key}")
    return model.model_validate(payload).model_dump(mode="json")
