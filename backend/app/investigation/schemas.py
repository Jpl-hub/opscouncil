from __future__ import annotations

from typing import Any, Literal

from backend.app.ai.analysis import AIAnalysisResult
from backend.app.core.pydantic_compat import BaseModel, Field, field_validator


class DecisionContractError(ValueError):
    pass


class StrictDecisionModel(BaseModel):
    class Config:
        extra = "forbid"


class HypothesisUpdate(StrictDecisionModel):
    key: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    rationale: str = Field(min_length=1, max_length=400)
    evidence_gap: str = Field(min_length=1, max_length=300)


class EvidenceLinkRequest(StrictDecisionModel):
    hypothesis_key: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    evidence_id: int = Field(gt=0)
    relation: Literal["SUPPORTS", "REFUTES", "CONTEXT"]
    rationale: str = Field(min_length=1, max_length=300)


class InvestigationToolRequest(StrictDecisionModel):
    tool_name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,127}$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=300)


class InvestigationDecision(StrictDecisionModel):
    decision: Literal["COLLECT", "CONCLUDE"]
    hypotheses: list[HypothesisUpdate]
    evidence_links: list[EvidenceLinkRequest] = Field(default_factory=list)
    next_tool: InvestigationToolRequest | None = None
    conclusion: AIAnalysisResult | None = None
    stop_reason: str = Field(min_length=1, max_length=300)

    @field_validator("hypotheses")
    @classmethod
    def bound_hypotheses(cls, value: list[HypothesisUpdate]) -> list[HypothesisUpdate]:
        if not 1 <= len(value) <= 5:
            raise ValueError("hypotheses must contain between 1 and 5 items")
        return value

    @field_validator("evidence_links")
    @classmethod
    def bound_evidence_links(cls, value: list[EvidenceLinkRequest]) -> list[EvidenceLinkRequest]:
        if len(value) > 20:
            raise ValueError("evidence_links must contain at most 20 items")
        return value


def validate_decision_shape(decision: InvestigationDecision) -> None:
    keys = [item.key for item in decision.hypotheses]
    if len(keys) != len(set(keys)):
        raise DecisionContractError("duplicate hypothesis keys are not allowed")

    declared_keys = set(keys)
    for link in decision.evidence_links:
        if link.hypothesis_key not in declared_keys:
            raise DecisionContractError(
                f"evidence link references undeclared hypothesis {link.hypothesis_key}"
            )

    if decision.decision == "COLLECT":
        if decision.next_tool is None:
            raise DecisionContractError("COLLECT decision requires next_tool")
        if decision.conclusion is not None:
            raise DecisionContractError("COLLECT decision must not include conclusion")
        return

    if decision.next_tool is not None:
        raise DecisionContractError("CONCLUDE decision must not include next_tool")
    if decision.conclusion is None:
        raise DecisionContractError("CONCLUDE decision requires conclusion")
    if decision.conclusion.root_cause in declared_keys:
        raise DecisionContractError(
            "conclusion.root_cause must be user-facing natural language, not a hypothesis key"
        )
