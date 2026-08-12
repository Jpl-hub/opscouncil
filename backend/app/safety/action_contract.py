from __future__ import annotations

from copy import deepcopy
from typing import Any

from backend.app.audit.service import stable_hash
from backend.app.models.entities import ActionProposal


class ActionContractIntegrityError(ValueError):
    pass


def build_bound_action(proposal: ActionProposal) -> dict[str, Any]:
    if proposal.id is None:
        raise ValueError("action proposal must be persisted before binding")
    return {
        "proposal_id": proposal.id,
        "task_id": proposal.task_id,
        "tool_name": proposal.tool_name,
        "input": deepcopy(proposal.input_json),
        "risk_level": proposal.risk_level,
    }


def action_contract_digest(contract: dict[str, Any]) -> str:
    return stable_hash(contract)


def assert_bound_action_matches(
    contract: dict[str, Any],
    proposal: ActionProposal,
) -> None:
    expected = build_bound_action(proposal)
    if contract != expected:
        raise ActionContractIntegrityError(
            "处置方案与已批准动作契约不一致。"
        )


def copy_bound_action(contract: dict[str, Any]) -> dict[str, Any]:
    required = {
        "proposal_id",
        "task_id",
        "tool_name",
        "input",
        "risk_level",
    }
    if not isinstance(contract, dict) or set(contract) != required:
        raise ActionContractIntegrityError("动作契约结构不完整。")
    if not isinstance(contract["input"], dict):
        raise ActionContractIntegrityError("动作契约参数不是结构化对象。")
    return deepcopy(contract)
