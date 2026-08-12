from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkDefinition:
    key: str
    role: str
    skill_id: str
    depends_on: tuple[str, ...]
    stage: str


WORKFLOW = (
    WorkDefinition("triage", "signal_correlator", "signal-fusion", (), "TRIAGING"),
    WorkDefinition(
        "investigate",
        "rca_investigator",
        "causal-investigation",
        ("triage",),
        "INVESTIGATING",
    ),
    WorkDefinition(
        "plan",
        "remediation_planner",
        "bounded-remediation",
        ("investigate",),
        "PLANNING",
    ),
    WorkDefinition(
        "execute",
        "policy_controller",
        "restricted-action-control",
        ("plan",),
        "WAITING_EXECUTION",
    ),
    WorkDefinition(
        "verify",
        "recovery_verifier",
        "independent-recovery-verification",
        ("execute",),
        "VERIFYING",
    ),
    WorkDefinition(
        "learn",
        "incident_commander",
        "incident-learning",
        ("verify",),
        "LEARNING",
    ),
)

WORK_BY_KEY = {item.key: item for item in WORKFLOW}


def dependencies_satisfied(work_key: str, statuses: dict[str, str]) -> bool:
    definition = WORK_BY_KEY[work_key]
    return all(statuses.get(dependency) == "SUCCEEDED" for dependency in definition.depends_on)
