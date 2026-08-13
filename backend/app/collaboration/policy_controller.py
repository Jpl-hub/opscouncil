from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.agent.runner import AgentRunner
from backend.app.audit.service import stable_hash
from backend.app.collaboration.service import (
    CollaborationStateError,
    IncidentCollaborationService,
)
from backend.app.core.config import settings
from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    AgentWorkItem,
    Incident,
    IncidentCollaboration,
    Task,
    ToolCall,
    utcnow,
)


POLICY_CONTROLLER_ID = "policy-controller"
TERMINAL_PROPOSAL_STATUSES = frozenset(
    {"EXECUTED", "BLOCKED", "REJECTED", "NEEDS_OPERATOR"}
)


class PolicyContractBindingError(ValueError):
    pass


@dataclass(frozen=True)
class BoundExecution:
    collaboration_id: int
    action_contract_hash: str
    autonomy_mode: str
    policy_authorization_ref: str | None
    proposal_id: int | None


RunnerFactory = Callable[..., AgentRunner]
ReadyNotifier = Callable[[int, str], None]
logger = logging.getLogger(__name__)


class PolicyControllerProcessor:
    """Runs the non-model execution gate for AgentTeams incident work."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        registry: object,
        controller_id: str = POLICY_CONTROLLER_ID,
        *,
        runner_factory: RunnerFactory = AgentRunner,
        ready_notifier: ReadyNotifier | None = None,
        lease_seconds: int = 300,
    ) -> None:
        self.session_factory = session_factory
        self.registry = registry
        self.controller_id = _identifier(controller_id)
        self.runner_factory = runner_factory
        self.ready_notifier = ready_notifier
        self.lease_seconds = min(max(lease_seconds, 30), 3600)

    def run_once(self, *, now: datetime | None = None) -> bool:
        claimed_at = now or utcnow()
        with self.session_factory() as session:
            collaboration_id = self._claim_one(session, claimed_at)
            session.commit()
        if collaboration_id is None:
            return False

        try:
            output = self._process_claim(collaboration_id)
        except PolicyContractBindingError as exc:
            with self.session_factory() as session:
                IncidentCollaborationService(session).block_execution(
                    collaboration_id,
                    controller_id=self.controller_id,
                    reason=str(exc),
                )
                session.commit()
            return True
        except Exception as exc:
            output = self._unknown_output(collaboration_id, exc)

        with self.session_factory() as session:
            result = IncidentCollaborationService(session).record_execution(
                collaboration_id,
                controller_id=self.controller_id,
                output=output,
                source_event_id=f"policy-controller:{uuid.uuid4().hex}",
            )
            session.commit()
        if result.advanced_work_key is not None and self.ready_notifier is not None:
            try:
                self.ready_notifier(collaboration_id, result.advanced_work_key)
            except Exception:
                logger.exception(
                    "failed to notify AgentTeams about ready work %s for collaboration %s",
                    result.advanced_work_key,
                    collaboration_id,
                )
        return True

    def _claim_one(self, session: Session, now: datetime) -> int | None:
        service = IncidentCollaborationService(session)
        rows = list(
            session.execute(
                select(IncidentCollaboration, AgentWorkItem)
                .join(
                    AgentWorkItem,
                    AgentWorkItem.collaboration_id == IncidentCollaboration.id,
                )
                .where(
                    AgentWorkItem.work_key == "execute",
                    AgentWorkItem.status.in_(("READY", "RUNNING")),
                )
                .order_by(AgentWorkItem.updated_at.asc(), AgentWorkItem.id.asc())
                .with_for_update(skip_locked=True)
                .limit(100)
            )
        )
        for collaboration, item in rows:
            if item.status == "RUNNING":
                if (
                    item.lease_expires_at is None
                    or _as_utc(item.lease_expires_at) >= _as_utc(now)
                ):
                    continue
                service.adopt_expired_execution(
                    collaboration.id,
                    controller_id=self.controller_id,
                    lease_seconds=self.lease_seconds,
                )
                return collaboration.id
            if not self._ready_for_controller(session, collaboration):
                continue
            service.claim_execution(
                collaboration.id,
                controller_id=self.controller_id,
                lease_seconds=self.lease_seconds,
            )
            return collaboration.id
        return None

    def _ready_for_controller(
        self,
        session: Session,
        collaboration: IncidentCollaboration,
    ) -> bool:
        if collaboration.autonomy_mode in {"OBSERVE_ONLY", "AUTO_REVERSIBLE"}:
            return True
        if collaboration.autonomy_mode != "HUMAN_GATED":
            return False
        try:
            _, proposal = _bound_contract(session, collaboration)
        except PolicyContractBindingError:
            return True
        return proposal is not None and proposal.status in TERMINAL_PROPOSAL_STATUSES

    def _process_claim(self, collaboration_id: int) -> dict:
        with self.session_factory() as session:
            collaboration = session.get(IncidentCollaboration, collaboration_id)
            if collaboration is None:
                raise PolicyContractBindingError("协作事件不存在。")
            item = session.scalar(
                select(AgentWorkItem).where(
                    AgentWorkItem.collaboration_id == collaboration_id,
                    AgentWorkItem.work_key == "execute",
                )
            )
            if (
                item is None
                or item.status != "RUNNING"
                or item.assigned_agent != self.controller_id
            ):
                raise CollaborationStateError("policy controller lost execution ownership")

            binding, proposal = _bound_contract(session, collaboration)
            if binding.autonomy_mode == "OBSERVE_ONLY":
                return _skipped_output(
                    binding,
                    "动作契约为只观察模式，策略控制器没有执行系统变更。",
                )
            if proposal is None:
                raise PolicyContractBindingError("动作契约没有绑定可核验的处置方案。")

            if binding.autonomy_mode == "AUTO_REVERSIBLE":
                if binding.policy_authorization_ref not in settings.collaboration_auto_policy_refs:
                    raise PolicyContractBindingError("动作未命中已部署的自动处置策略。")
                if proposal.status == "PENDING_APPROVAL":
                    policy_ref = binding.policy_authorization_ref
                    assert policy_ref is not None

                    def checkpoint() -> None:
                        IncidentCollaborationService(session).renew_execution(
                            collaboration_id,
                            controller_id=self.controller_id,
                            lease_seconds=self.lease_seconds,
                        )
                        session.commit()

                    runner = self.runner_factory(
                        session,
                        self.registry,
                        event_checkpoint=checkpoint,
                    )
                    runner.execute_policy_authorized_proposal(
                        proposal.id,
                        controller_id=self.controller_id,
                        policy_authorization_ref=policy_ref,
                    )
                    session.commit()
                    session.refresh(proposal)
            elif binding.autonomy_mode == "HUMAN_GATED":
                if proposal.status not in TERMINAL_PROPOSAL_STATUSES:
                    raise PolicyContractBindingError("处置方案仍在等待人工授权。")
            else:
                raise PolicyContractBindingError(
                    f"自治模式 {binding.autonomy_mode} 不允许策略执行。"
                )
            return _proposal_output(session, binding, proposal)

    def _unknown_output(self, collaboration_id: int, exc: Exception) -> dict:
        with self.session_factory() as session:
            collaboration = session.get(IncidentCollaboration, collaboration_id)
            if collaboration is None or not collaboration.action_contract_hash:
                raise PolicyContractBindingError("无法恢复缺失动作契约的执行状态") from exc
            proposal_id = _proposal_id(collaboration.action_contract_json)
            refs = [f"collaboration:{collaboration_id}"]
            if proposal_id is not None:
                refs.append(f"proposal:{proposal_id}")
            return {
                "outcome": "UNKNOWN",
                "controller": "restricted-executor",
                "action_contract_hash": collaboration.action_contract_hash,
                "execution_ref": f"policy-controller-error:{uuid.uuid4().hex}",
                "evidence_refs": refs,
                "rollback_performed": False,
                "detail": (
                    "策略执行状态无法确定，系统已停止自动重试并转入独立复验："
                    f"{str(exc)[:800]}"
                ),
            }


def _bound_contract(
    session: Session,
    collaboration: IncidentCollaboration,
) -> tuple[BoundExecution, ActionProposal | None]:
    action = collaboration.action_contract_json
    if not isinstance(action, dict) or not action:
        raise PolicyContractBindingError("动作契约为空。")
    expected_hash = stable_hash(action)
    if collaboration.action_contract_hash != expected_hash:
        raise PolicyContractBindingError("动作契约哈希校验失败。")
    mode = collaboration.autonomy_mode
    policy_ref_value = action.get("policy_authorization_ref")
    policy_ref = policy_ref_value.strip() if isinstance(policy_ref_value, str) else None
    proposal_id = _proposal_id(action)
    binding = BoundExecution(
        collaboration_id=collaboration.id,
        action_contract_hash=expected_hash,
        autonomy_mode=mode,
        policy_authorization_ref=policy_ref,
        proposal_id=proposal_id,
    )
    if mode == "OBSERVE_ONLY":
        return binding, None
    if proposal_id is None:
        raise PolicyContractBindingError("动作契约缺少有效 proposal_id。")
    proposal = session.get(ActionProposal, proposal_id)
    if proposal is None:
        raise PolicyContractBindingError("动作契约引用的处置方案不存在。")
    incident = session.get(Incident, collaboration.incident_id)
    if incident is None or incident.task_id is None:
        raise PolicyContractBindingError("事件没有绑定产生处置方案的运维任务。")
    if proposal.task_id != incident.task_id:
        raise PolicyContractBindingError("处置方案不属于当前事件绑定的运维任务。")
    if proposal.tool_name != action.get("tool_name"):
        raise PolicyContractBindingError("动作契约工具与处置方案不一致。")
    if proposal.risk_level != action.get("risk_level"):
        raise PolicyContractBindingError("动作契约风险等级与处置方案不一致。")
    arguments = action.get("arguments")
    if not isinstance(arguments, dict) or deepcopy(proposal.input_json) != arguments:
        raise PolicyContractBindingError("动作契约参数与 dry-run 后封存的参数不一致。")
    return binding, proposal


def _proposal_output(
    session: Session,
    binding: BoundExecution,
    proposal: ActionProposal,
) -> dict:
    safety_case = session.scalar(
        select(ActionSafetyCase).where(ActionSafetyCase.proposal_id == proposal.id)
    )
    call = (
        session.get(ToolCall, safety_case.execution_call_id)
        if safety_case is not None and safety_case.execution_call_id is not None
        else None
    )
    task = session.get(Task, proposal.task_id)
    if proposal.status == "EXECUTED":
        outcome = "SUCCEEDED"
    elif proposal.status == "NEEDS_OPERATOR":
        outcome = "UNKNOWN"
    elif call is not None:
        outcome = "FAILED"
    else:
        outcome = "SKIPPED"
    refs = [f"proposal:{proposal.id}"]
    if safety_case is not None:
        refs.append(f"safety-case:{safety_case.id}")
        refs.extend(
            str(value)
            for value in safety_case.evidence_refs_json
            if isinstance(value, str) and value
        )
    if call is not None:
        refs.append(f"tool-call:{call.id}")
        refs.extend(
            str(value)
            for value in (call.output_json or {}).get("evidence_refs", [])
            if isinstance(value, str) and value
        )
    execution_ref = (
        f"tool-call:{call.id}"
        if call is not None
        else f"proposal:{proposal.id}:{proposal.status.lower()}"
    )
    return {
        "outcome": outcome,
        "controller": "restricted-executor",
        "action_contract_hash": binding.action_contract_hash,
        "execution_ref": execution_ref,
        "evidence_refs": list(dict.fromkeys(refs)),
        "rollback_performed": False,
        "detail": (
            (task.summary if task is not None else None)
            or f"处置方案状态为 {proposal.status}。"
        )[:2000],
    }


def _skipped_output(binding: BoundExecution, detail: str) -> dict:
    return {
        "outcome": "SKIPPED",
        "controller": "restricted-executor",
        "action_contract_hash": binding.action_contract_hash,
        "execution_ref": f"policy-skip:{uuid.uuid4().hex}",
        "evidence_refs": [f"collaboration:{binding.collaboration_id}"],
        "rollback_performed": False,
        "detail": detail,
    }


def _proposal_id(action: object) -> int | None:
    if not isinstance(action, dict):
        return None
    value = action.get("proposal_id")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        return None
    return value


def _identifier(value: str) -> str:
    normalized = " ".join(str(value).split())[:128]
    if not normalized:
        raise ValueError("controller_id is required")
    return normalized


def _as_utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )
