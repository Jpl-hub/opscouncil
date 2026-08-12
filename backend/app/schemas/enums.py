from __future__ import annotations

from enum import Enum


class RiskLevel(str, Enum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


class TaskStatus(str, Enum):
    RECEIVED = "RECEIVED"
    PERCEIVE = "PERCEIVE"
    PLAN = "PLAN"
    STATIC_REVIEW = "STATIC_REVIEW"
    DRY_RUN = "DRY_RUN"
    DYNAMIC_REVIEW = "DYNAMIC_REVIEW"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    EXECUTE = "EXECUTE"
    VERIFY = "VERIFY"
    SUMMARIZE = "SUMMARIZE"
    SEALED = "SEALED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    NEEDS_OPERATOR = "NEEDS_OPERATOR"
    CANCELLED = "CANCELLED"
    ROLLED_BACK = "ROLLED_BACK"


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ReviewDecision(str, Enum):
    ALLOW = "ALLOW"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    REJECT = "REJECT"


RISK_ORDER = {
    RiskLevel.R0: 0,
    RiskLevel.R1: 1,
    RiskLevel.R2: 2,
    RiskLevel.R3: 3,
    RiskLevel.R4: 4,
}


def max_risk(*levels: RiskLevel) -> RiskLevel:
    return max(levels, key=lambda level: RISK_ORDER[level])
