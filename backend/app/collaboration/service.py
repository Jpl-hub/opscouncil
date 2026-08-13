from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.service import stable_hash
from backend.app.collaboration.contracts import validate_output
from backend.app.collaboration.manifest import AGENT_NAME_BY_ROLE, ROLE_BY_WORK_KEY, TEAM_NAME
from backend.app.collaboration.workflow import WORKFLOW, WORK_BY_KEY, dependencies_satisfied
from backend.app.core.config import settings
from backend.app.models.entities import (
    ActionProposal,
    AgentWorkItem,
    CollaborationEvent,
    Incident,
    IncidentCollaboration,
    Task,
    utcnow,
)


class CollaborationStateError(ValueError):
    pass


class CollaborationAuthorizationError(PermissionError):
    pass


@dataclass(frozen=True)
class SubmissionResult:
    collaboration: IncidentCollaboration
    work_item: AgentWorkItem
    advanced_work_key: str | None


class IncidentCollaborationService:
    EVIDENCE_CONFIDENCE_THRESHOLD = 0.70

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_incident(
        self,
        *,
        host_key: str,
        signal_key: str,
        severity: str,
        title: str,
        summary: str,
        dedupe_key: str | None = None,
        initial_evidence_refs: list[str] | None = None,
        source: str = "operator",
        task_id: int | None = None,
    ) -> IncidentCollaboration:
        normalized_severity = severity.strip().upper()
        if normalized_severity not in {"WARN", "CRITICAL"}:
            raise ValueError("severity must be WARN or CRITICAL")
        if task_id is not None and self.session.get(Task, task_id) is None:
            raise LookupError("task not found")
        if dedupe_key:
            existing = self.session.scalar(
                select(Incident).where(Incident.dedupe_key == dedupe_key)
            )
            if existing is not None:
                if task_id is not None and existing.task_id not in {None, task_id}:
                    raise CollaborationStateError(
                        "deduplicated incident is bound to another task"
                    )
                if task_id is not None and existing.task_id is None:
                    existing.task_id = task_id
                collaboration = self.get_by_incident(existing.id)
                if collaboration is None:
                    return self.start(existing.id, initial_evidence_refs=initial_evidence_refs)
                return collaboration
        incident = Incident(
            host_key=host_key.strip(),
            signal_key=signal_key.strip(),
            dedupe_key=dedupe_key,
            status="OPEN",
            severity=normalized_severity,
            title=title.strip(),
            summary=summary.strip(),
            task_id=task_id,
        )
        self.session.add(incident)
        self.session.flush()
        collaboration = self.start(
            incident.id,
            initial_evidence_refs=initial_evidence_refs,
            source=source,
        )
        return collaboration

    def start(
        self,
        incident_id: int,
        *,
        initial_evidence_refs: list[str] | None = None,
        source: str = "operator",
    ) -> IncidentCollaboration:
        incident = self.session.get(Incident, incident_id)
        if incident is None:
            raise LookupError("incident not found")
        existing = self.get_by_incident(incident_id)
        if existing is not None:
            return existing

        evidence_refs = _normalized_refs(initial_evidence_refs or [])
        action_candidates = self._action_candidates(incident.task_id)
        collaboration = IncidentCollaboration(
            incident_id=incident.id,
            team_name=TEAM_NAME,
            status="TRIAGING",
            shared_context_json={
                "incident": {
                    "id": incident.id,
                    "host_key": incident.host_key,
                    "signal_key": incident.signal_key,
                    "severity": incident.severity,
                    "title": incident.title,
                    "summary": incident.summary,
                    "task_id": incident.task_id,
                },
                "initial_evidence_refs": evidence_refs,
                "action_candidates": action_candidates,
                "execution_policy": {
                    "auto_authorization_refs": list(
                        settings.collaboration_auto_policy_refs
                    ),
                    "unlisted_actions": "HUMAN_GATED",
                },
                "outputs": {},
            },
        )
        self.session.add(collaboration)
        self.session.flush()

        for definition in WORKFLOW:
            item = AgentWorkItem(
                collaboration_id=collaboration.id,
                work_key=definition.key,
                role=definition.role,
                skill_id=definition.skill_id,
                status="READY" if not definition.depends_on else "PENDING",
                depends_on_json=list(definition.depends_on),
                input_json={
                    "incident_id": incident.id,
                    "context_version": collaboration.context_version,
                    "evidence_refs": evidence_refs,
                },
            )
            self.session.add(item)
        self.session.flush()
        self._append_event(
            collaboration,
            actor=source,
            event_type="collaboration_started",
            payload={
                "team": TEAM_NAME,
                "incident_id": incident.id,
                "workflow": [item.key for item in WORKFLOW],
            },
        )
        incident.status = "INVESTIGATING"
        incident.updated_at = utcnow()
        return collaboration

    def _action_candidates(self, task_id: int | None) -> list[dict[str, Any]]:
        if task_id is None:
            return []
        proposals = list(
            self.session.scalars(
                select(ActionProposal)
                .where(
                    ActionProposal.task_id == task_id,
                    ActionProposal.status == "PENDING_APPROVAL",
                )
                .order_by(ActionProposal.id.asc())
            )
        )
        return [
            {
                "proposal_id": proposal.id,
                "tool_name": proposal.tool_name,
                "arguments": deepcopy(proposal.input_json),
                "risk_level": proposal.risk_level,
                "rationale": proposal.reason,
                "dry_run": deepcopy(proposal.dry_run_result_json),
            }
            for proposal in proposals
        ]

    def get(self, collaboration_id: int) -> IncidentCollaboration | None:
        return self.session.get(IncidentCollaboration, collaboration_id)

    def get_by_incident(self, incident_id: int) -> IncidentCollaboration | None:
        return self.session.scalar(
            select(IncidentCollaboration).where(
                IncidentCollaboration.incident_id == incident_id
            )
        )

    def list(self, *, limit: int = 50) -> list[IncidentCollaboration]:
        return list(
            self.session.scalars(
                select(IncidentCollaboration)
                .order_by(IncidentCollaboration.updated_at.desc(), IncidentCollaboration.id.desc())
                .limit(min(max(limit, 1), 200))
            )
        )

    def work_items(self, collaboration_id: int) -> list[AgentWorkItem]:
        return list(
            self.session.scalars(
                select(AgentWorkItem)
                .where(AgentWorkItem.collaboration_id == collaboration_id)
                .order_by(AgentWorkItem.id.asc())
            )
        )

    def events(self, collaboration_id: int) -> list[CollaborationEvent]:
        return list(
            self.session.scalars(
                select(CollaborationEvent)
                .where(CollaborationEvent.collaboration_id == collaboration_id)
                .order_by(CollaborationEvent.sequence.asc())
            )
        )

    def bind_agentteams_room(
        self,
        collaboration_id: int,
        *,
        room_id: str,
        actor: str = "incident-commander",
    ) -> IncidentCollaboration:
        collaboration = self._require_collaboration(collaboration_id)
        normalized = room_id.strip()
        if not normalized:
            raise ValueError("room_id is required")
        collaboration.agentteams_room_id = normalized
        collaboration.updated_at = utcnow()
        self._append_event(
            collaboration,
            actor=actor,
            event_type="agentteams_room_bound",
            payload={"room_id": normalized},
        )
        return collaboration

    def record_agentteams_dispatch(
        self,
        collaboration_id: int,
        *,
        event_id: str,
    ) -> CollaborationEvent:
        normalized_event_id = event_id.strip()
        if not normalized_event_id:
            raise ValueError("AgentTeams event id is required")
        collaboration = self._require_collaboration(collaboration_id)
        collaboration.updated_at = utcnow()
        return self._append_event(
            collaboration,
            actor="incident-commander",
            event_type="agentteams_dispatched",
            source_system="agentteams-matrix",
            source_event_id=normalized_event_id,
            payload={
                "team": collaboration.team_name,
                "incident_id": collaboration.incident_id,
                "context_version": collaboration.context_version,
            },
        )

    def claim(
        self,
        collaboration_id: int,
        work_key: str,
        *,
        role: str,
        agent_name: str,
        lease_seconds: int = 300,
    ) -> AgentWorkItem:
        item = self._require_work_item(collaboration_id, work_key, for_update=True)
        expected_role = ROLE_BY_WORK_KEY[work_key]
        if expected_role == "policy_controller":
            raise CollaborationAuthorizationError(
                "execution work is reserved for the deterministic policy controller"
            )
        if role != expected_role:
            raise CollaborationAuthorizationError(
                f"{work_key} requires role {expected_role}, received {role}"
            )
        expected_agent = AGENT_NAME_BY_ROLE.get(role)
        if expected_agent is not None and agent_name != expected_agent:
            raise CollaborationAuthorizationError(
                f"role {role} is bound to agent {expected_agent}"
            )
        statuses = self._statuses(collaboration_id)
        if not dependencies_satisfied(work_key, statuses):
            raise CollaborationStateError("work item dependencies are not satisfied")
        if item.status != "READY":
            raise CollaborationStateError(f"work item is {item.status}, not READY")
        now = utcnow()
        item.status = "RUNNING"
        item.assigned_agent = agent_name
        item.attempt_count += 1
        item.started_at = item.started_at or now
        item.updated_at = now
        item.lease_expires_at = now + timedelta(seconds=min(max(lease_seconds, 30), 3600))
        collaboration = self._require_collaboration(collaboration_id)
        collaboration.status = WORK_BY_KEY[work_key].stage
        collaboration.updated_at = now
        self._append_event(
            collaboration,
            work_item=item,
            actor=agent_name,
            event_type="work_claimed",
            payload={"work_key": work_key, "role": role, "attempt": item.attempt_count},
        )
        return item

    def submit(
        self,
        collaboration_id: int,
        work_key: str,
        *,
        role: str,
        agent_name: str,
        output: dict[str, Any],
        source_event_id: str | None = None,
    ) -> SubmissionResult:
        if work_key == "execute":
            raise CollaborationAuthorizationError(
                "execution results must be recorded by the policy controller"
            )
        item = self._require_work_item(collaboration_id, work_key, for_update=True)
        self._assert_submitter(item, role=role, agent_name=agent_name)
        normalized = validate_output(work_key, output)
        if work_key == "investigate":
            return self._submit_investigation(
                item,
                normalized,
                actor=agent_name,
                source_event_id=source_event_id,
            )
        if work_key == "plan":
            self._assert_planning_gate(collaboration_id, normalized)
        if work_key == "verify":
            self._assert_independent_verification(collaboration_id, normalized)
        if work_key == "learn":
            self._assert_learning_gate(collaboration_id, normalized)
        return self._complete(
            item,
            normalized,
            actor=agent_name,
            source_event_id=source_event_id,
        )

    def record_execution(
        self,
        collaboration_id: int,
        *,
        output: dict[str, Any],
        controller_id: str,
        source_event_id: str | None = None,
    ) -> SubmissionResult:
        item = self._require_work_item(collaboration_id, "execute", for_update=True)
        if item.status not in {"READY", "RUNNING"}:
            raise CollaborationStateError(
                f"execution work is {item.status}, not READY or RUNNING"
            )
        if item.status == "RUNNING" and item.assigned_agent != controller_id:
            raise CollaborationAuthorizationError(
                "execution lease is assigned to another policy controller"
            )
        collaboration = self._require_collaboration(collaboration_id)
        normalized = validate_output("execute", output)
        expected_hash = collaboration.action_contract_hash
        if not expected_hash or normalized["action_contract_hash"] != expected_hash:
            raise CollaborationStateError("execution result does not match the bound action contract")
        if collaboration.autonomy_mode in {"BLOCKED", "OBSERVE_ONLY", "UNDECIDED"}:
            if normalized["outcome"] != "SKIPPED":
                raise CollaborationStateError(
                    f"autonomy mode {collaboration.autonomy_mode} does not permit execution"
                )
        if item.status == "READY":
            item.status = "RUNNING"
            item.assigned_agent = controller_id
            item.attempt_count += 1
            item.started_at = item.started_at or utcnow()
        item.lease_expires_at = utcnow() + timedelta(minutes=5)
        collaboration.execution_json = deepcopy(normalized)
        return self._complete(
            item,
            normalized,
            actor=controller_id,
            source_event_id=source_event_id,
        )

    def claim_execution(
        self,
        collaboration_id: int,
        *,
        controller_id: str,
        lease_seconds: int = 300,
    ) -> AgentWorkItem:
        item = self._require_work_item(collaboration_id, "execute", for_update=True)
        if item.status != "READY":
            raise CollaborationStateError(f"execution work is {item.status}, not READY")
        now = utcnow()
        item.status = "RUNNING"
        item.assigned_agent = controller_id
        item.attempt_count += 1
        item.started_at = item.started_at or now
        item.updated_at = now
        item.lease_expires_at = now + timedelta(
            seconds=min(max(lease_seconds, 30), 3600)
        )
        collaboration = self._require_collaboration(collaboration_id)
        collaboration.status = "WAITING_EXECUTION"
        collaboration.updated_at = now
        self._append_event(
            collaboration,
            work_item=item,
            actor=controller_id,
            event_type="execution_claimed",
            payload={
                "autonomy_mode": collaboration.autonomy_mode,
                "attempt": item.attempt_count,
            },
        )
        return item

    def renew_execution(
        self,
        collaboration_id: int,
        *,
        controller_id: str,
        lease_seconds: int = 300,
    ) -> AgentWorkItem:
        item = self._require_work_item(collaboration_id, "execute", for_update=True)
        if item.status != "RUNNING" or item.assigned_agent != controller_id:
            raise CollaborationAuthorizationError(
                "policy controller does not own the running execution lease"
            )
        now = utcnow()
        item.lease_expires_at = now + timedelta(
            seconds=min(max(lease_seconds, 30), 3600)
        )
        item.updated_at = now
        return item

    def adopt_expired_execution(
        self,
        collaboration_id: int,
        *,
        controller_id: str,
        lease_seconds: int = 300,
    ) -> AgentWorkItem:
        item = self._require_work_item(collaboration_id, "execute", for_update=True)
        now = utcnow()
        if (
            item.status != "RUNNING"
            or item.lease_expires_at is None
            or _as_utc(item.lease_expires_at) >= _as_utc(now)
        ):
            raise CollaborationStateError("execution lease is not expired")
        previous_controller = item.assigned_agent
        item.assigned_agent = controller_id
        item.lease_expires_at = now + timedelta(
            seconds=min(max(lease_seconds, 30), 3600)
        )
        item.updated_at = now
        collaboration = self._require_collaboration(collaboration_id)
        collaboration.updated_at = now
        self._append_event(
            collaboration,
            work_item=item,
            actor=controller_id,
            event_type="execution_lease_recovered",
            payload={
                "previous_controller": previous_controller,
                "automatic_retry": False,
            },
        )
        return item

    def block_execution(
        self,
        collaboration_id: int,
        *,
        controller_id: str,
        reason: str,
    ) -> AgentWorkItem:
        item = self._require_work_item(collaboration_id, "execute", for_update=True)
        if item.status != "RUNNING" or item.assigned_agent != controller_id:
            raise CollaborationAuthorizationError(
                "policy controller does not own the running execution lease"
            )
        item.status = "BLOCKED"
        item.last_error = reason[:1000]
        item.lease_expires_at = None
        item.updated_at = utcnow()
        collaboration = self._require_collaboration(collaboration_id)
        collaboration.status = "NEEDS_OPERATOR"
        collaboration.updated_at = utcnow()
        self._append_event(
            collaboration,
            work_item=item,
            actor=controller_id,
            event_type="execution_policy_blocked",
            payload={"reason": reason[:1000], "automatic_retry": False},
        )
        return item

    def verify_chain(self, collaboration_id: int) -> dict[str, Any]:
        events = self.events(collaboration_id)
        previous_hash: str | None = None
        entries: list[dict[str, Any]] = []
        valid = True
        for event in events:
            expected_payload_hash = stable_hash(
                {
                    "collaboration_id": event.collaboration_id,
                    "work_item_id": event.work_item_id,
                    "sequence": event.sequence,
                    "actor": event.actor,
                    "event_type": event.event_type,
                    "source_system": event.source_system,
                    "source_event_id": event.source_event_id,
                    "payload": event.payload_json,
                }
            )
            expected_event_hash = stable_hash(
                {"prev_hash": previous_hash, "payload_hash": expected_payload_hash}
            )
            entry_valid = (
                event.prev_hash == previous_hash
                and event.payload_hash == expected_payload_hash
                and event.event_hash == expected_event_hash
            )
            valid = valid and entry_valid
            entries.append(
                {
                    "sequence": event.sequence,
                    "event_type": event.event_type,
                    "valid": entry_valid,
                }
            )
            previous_hash = event.event_hash
        return {
            "collaboration_id": collaboration_id,
            "valid": valid,
            "event_count": len(events),
            "head_hash": previous_hash,
            "entries": entries,
        }

    def _submit_investigation(
        self,
        item: AgentWorkItem,
        output: dict[str, Any],
        *,
        actor: str,
        source_event_id: str | None,
    ) -> SubmissionResult:
        collaboration = self._require_collaboration(item.collaboration_id)
        passed = (
            output["decision"] == "CONCLUDE"
            and bool(output.get("root_cause"))
            and float(output["confidence"]) >= self.EVIDENCE_CONFIDENCE_THRESHOLD
            and output["counter_evidence_reviewed"] is True
            and len(_normalized_refs(output["evidence_refs"])) >= 2
            and not output["missing_evidence"]
        )
        if not passed:
            collaboration.evidence_gate_status = "FAILED"
            collaboration.status = "INVESTIGATING"
            collaboration.updated_at = utcnow()
            item.status = "READY"
            item.output_json = deepcopy(output)
            item.evidence_refs_json = _normalized_refs(output["evidence_refs"])
            item.assigned_agent = None
            item.lease_expires_at = None
            item.updated_at = utcnow()
            self._append_event(
                collaboration,
                work_item=item,
                actor=actor,
                event_type="evidence_gate_failed",
                payload={
                    "work_key": item.work_key,
                    "confidence": output["confidence"],
                    "missing_evidence": output["missing_evidence"],
                    "counter_evidence_reviewed": output["counter_evidence_reviewed"],
                },
                source_event_id=source_event_id,
            )
            return SubmissionResult(collaboration, item, None)
        collaboration.evidence_gate_status = "PASSED"
        return self._complete(
            item,
            output,
            actor=actor,
            source_event_id=source_event_id,
        )

    def _complete(
        self,
        item: AgentWorkItem,
        output: dict[str, Any],
        *,
        actor: str,
        source_event_id: str | None,
    ) -> SubmissionResult:
        now = utcnow()
        evidence_refs = _normalized_refs(output.get("evidence_refs", []))
        item.status = "SUCCEEDED"
        item.output_json = deepcopy(output)
        item.evidence_refs_json = evidence_refs
        item.completed_at = now
        item.updated_at = now
        item.lease_expires_at = None
        collaboration = self._require_collaboration(item.collaboration_id)
        context = deepcopy(collaboration.shared_context_json)
        outputs = dict(context.get("outputs") or {})
        outputs[item.work_key] = deepcopy(output)
        context["outputs"] = outputs
        collaboration.shared_context_json = context
        collaboration.context_version += 1
        collaboration.updated_at = now

        if item.work_key == "plan":
            action = deepcopy(output["action"])
            collaboration.action_contract_json = action
            collaboration.action_contract_hash = stable_hash(action)
            collaboration.autonomy_mode = _autonomy_mode(action)
        elif item.work_key == "verify":
            collaboration.status = (
                "LEARNING" if output["verdict"] == "HEALTHY" else "NEEDS_OPERATOR"
            )
        elif item.work_key == "learn":
            collaboration.status = "RESOLVED"
            collaboration.completed_at = now
            incident = self.session.get(Incident, collaboration.incident_id)
            if incident is not None:
                incident.status = "RESOLVED"
                incident.updated_at = now
                incident.closed_at = now

        self._append_event(
            collaboration,
            work_item=item,
            actor=actor,
            event_type="work_completed",
            payload={
                "work_key": item.work_key,
                "role": item.role,
                "evidence_refs": evidence_refs,
                "context_version": collaboration.context_version,
                **(
                    {
                        "action_contract_hash": collaboration.action_contract_hash,
                        "autonomy_mode": collaboration.autonomy_mode,
                    }
                    if item.work_key == "plan"
                    else {}
                ),
            },
            source_event_id=source_event_id,
        )

        if item.work_key == "learn":
            self._append_event(
                collaboration,
                work_item=item,
                actor="incident-commander",
                event_type="incident_resolved",
                payload={
                    "incident_id": collaboration.incident_id,
                    "context_version": collaboration.context_version,
                    "skill_candidate": bool(output.get("skill_candidate")),
                },
            )

        advanced = self._advance_ready_item(collaboration.id)
        if collaboration.status not in {"RESOLVED", "NEEDS_OPERATOR", "FAILED"}:
            collaboration.status = (
                WORK_BY_KEY[advanced].stage if advanced is not None else collaboration.status
            )
        return SubmissionResult(collaboration, item, advanced)

    def _advance_ready_item(self, collaboration_id: int) -> str | None:
        statuses = self._statuses(collaboration_id)
        items = {item.work_key: item for item in self.work_items(collaboration_id)}
        for definition in WORKFLOW:
            item = items[definition.key]
            if item.status != "PENDING":
                continue
            if not dependencies_satisfied(definition.key, statuses):
                continue
            if definition.key == "learn":
                verification = items["verify"].output_json or {}
                if verification.get("verdict") != "HEALTHY":
                    item.status = "BLOCKED"
                    item.updated_at = utcnow()
                    return None
            if definition.key == "execute":
                collaboration = self._require_collaboration(collaboration_id)
                if collaboration.autonomy_mode == "BLOCKED":
                    item.status = "BLOCKED"
                    collaboration.status = "NEEDS_OPERATOR"
                    self._append_event(
                        collaboration,
                        work_item=item,
                        actor="policy-controller",
                        event_type="execution_blocked",
                        payload={"autonomy_mode": collaboration.autonomy_mode},
                    )
                    return None
            item.status = "READY"
            item.input_json = self._input_for(definition.key, collaboration_id)
            item.updated_at = utcnow()
            return definition.key
        return None

    def _input_for(self, work_key: str, collaboration_id: int) -> dict[str, Any]:
        collaboration = self._require_collaboration(collaboration_id)
        return {
            "incident_id": collaboration.incident_id,
            "context_version": collaboration.context_version,
            "shared_context": deepcopy(collaboration.shared_context_json),
            "action_contract_hash": collaboration.action_contract_hash,
            "autonomy_mode": collaboration.autonomy_mode,
            "work_key": work_key,
        }

    def _assert_submitter(self, item: AgentWorkItem, *, role: str, agent_name: str) -> None:
        expected_role = ROLE_BY_WORK_KEY[item.work_key]
        if role != expected_role:
            raise CollaborationAuthorizationError(
                f"{item.work_key} requires role {expected_role}, received {role}"
            )
        if item.status != "RUNNING":
            raise CollaborationStateError(f"work item is {item.status}, not RUNNING")
        if item.assigned_agent != agent_name:
            raise CollaborationAuthorizationError("work item is assigned to another agent")

    def _assert_planning_gate(self, collaboration_id: int, output: dict[str, Any]) -> None:
        collaboration = self._require_collaboration(collaboration_id)
        if collaboration.evidence_gate_status != "PASSED":
            raise CollaborationStateError("remediation planning requires a passed evidence gate")
        action = output["action"]
        context = collaboration.shared_context_json or {}
        candidates = [
            candidate
            for candidate in context.get("action_candidates") or []
            if isinstance(candidate, dict)
        ]
        if candidates:
            proposal_id = action.get("proposal_id")
            candidate = next(
                (
                    item
                    for item in candidates
                    if item.get("proposal_id") == proposal_id
                ),
                None,
            )
            if candidate is None:
                raise CollaborationStateError(
                    "action contract must bind one of the accepted dry-run proposals"
                )
            if action.get("tool_name") != candidate.get("tool_name"):
                raise CollaborationStateError(
                    "action contract tool differs from the bound dry-run proposal"
                )
            if action.get("arguments") != candidate.get("arguments"):
                raise CollaborationStateError(
                    "action contract arguments differ from the bound dry-run proposal"
                )
            if action.get("risk_level") != candidate.get("risk_level"):
                raise CollaborationStateError(
                    "action contract may not downgrade or change proposal risk"
                )
        if action["reversible"] and not action["rollback_steps"]:
            raise CollaborationStateError("reversible action contract requires rollback steps")
        if action["risk_level"] in {"R2", "R3"} and not action["policy_authorization_ref"]:
            raise CollaborationStateError("R2/R3 action requires a policy authorization reference")

    def _assert_independent_verification(
        self,
        collaboration_id: int,
        output: dict[str, Any],
    ) -> None:
        execution = self._require_work_item(collaboration_id, "execute")
        execution_refs = set(execution.evidence_refs_json)
        verification_refs = set(_normalized_refs(output["evidence_refs"]))
        if not verification_refs - execution_refs:
            raise CollaborationStateError(
                "recovery verification requires evidence independent from the execution receipt"
            )
        if output["verdict"] == "HEALTHY" and any(
            item["status"] != "PASS" for item in output["checks"]
        ):
            raise CollaborationStateError("HEALTHY verdict requires every verification check to pass")

    def _assert_learning_gate(self, collaboration_id: int, output: dict[str, Any]) -> None:
        verification = self._require_work_item(collaboration_id, "verify")
        verdict = (verification.output_json or {}).get("verdict")
        if verdict != "HEALTHY":
            raise CollaborationStateError("incident learning requires a healthy recovery verdict")
        if output["skill_candidate"] and len(output["qualification_evidence_refs"]) < 2:
            raise CollaborationStateError(
                "skill candidates require at least two qualification evidence references"
            )

    def _statuses(self, collaboration_id: int) -> dict[str, str]:
        return {item.work_key: item.status for item in self.work_items(collaboration_id)}

    def _require_collaboration(self, collaboration_id: int) -> IncidentCollaboration:
        collaboration = self.session.get(IncidentCollaboration, collaboration_id)
        if collaboration is None:
            raise LookupError("collaboration not found")
        return collaboration

    def _require_work_item(
        self,
        collaboration_id: int,
        work_key: str,
        *,
        for_update: bool = False,
    ) -> AgentWorkItem:
        if work_key not in WORK_BY_KEY:
            raise LookupError("work item not found")
        statement = select(AgentWorkItem).where(
            AgentWorkItem.collaboration_id == collaboration_id,
            AgentWorkItem.work_key == work_key,
        )
        if for_update:
            statement = statement.with_for_update()
        item = self.session.scalar(statement)
        if item is None:
            raise LookupError("work item not found")
        return item

    def _append_event(
        self,
        collaboration: IncidentCollaboration,
        *,
        actor: str,
        event_type: str,
        payload: dict[str, Any],
        work_item: AgentWorkItem | None = None,
        source_system: str = "opscouncil",
        source_event_id: str | None = None,
    ) -> CollaborationEvent:
        previous = self.session.scalar(
            select(CollaborationEvent)
            .where(CollaborationEvent.collaboration_id == collaboration.id)
            .order_by(CollaborationEvent.sequence.desc())
            .limit(1)
            .with_for_update()
        )
        sequence = 1 if previous is None else previous.sequence + 1
        resolved_source_event_id = source_event_id or uuid.uuid4().hex
        payload_hash = stable_hash(
            {
                "collaboration_id": collaboration.id,
                "work_item_id": work_item.id if work_item is not None else None,
                "sequence": sequence,
                "actor": actor,
                "event_type": event_type,
                "source_system": source_system,
                "source_event_id": resolved_source_event_id,
                "payload": payload,
            }
        )
        prev_hash = previous.event_hash if previous is not None else None
        event = CollaborationEvent(
            collaboration_id=collaboration.id,
            work_item_id=work_item.id if work_item is not None else None,
            sequence=sequence,
            actor=actor,
            event_type=event_type,
            source_system=source_system,
            source_event_id=resolved_source_event_id,
            payload_json=deepcopy(payload),
            prev_hash=prev_hash,
            payload_hash=payload_hash,
            event_hash=stable_hash({"prev_hash": prev_hash, "payload_hash": payload_hash}),
        )
        self.session.add(event)
        self.session.flush()
        return event


def _normalized_refs(values: list[Any]) -> list[str]:
    return list(
        dict.fromkeys(
            str(value).strip()
            for value in values
            if str(value).strip()
        )
    )


def _as_utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _autonomy_mode(action: dict[str, Any]) -> str:
    risk = action["risk_level"]
    environment = action["environment"]
    if risk == "R4":
        return "BLOCKED"
    if risk == "R0":
        return "OBSERVE_ONLY"
    policy_ref = action.get("policy_authorization_ref")
    policy_pre_authorized = (
        isinstance(action.get("proposal_id"), int)
        and not isinstance(action.get("proposal_id"), bool)
        and isinstance(policy_ref, str)
        and policy_ref in settings.collaboration_auto_policy_refs
    )
    if (
        policy_pre_authorized
        and action["reversible"]
        and action["rollback_steps"]
        and action["canary"]
        and environment in {"LAB", "STAGING"}
        and risk in {"R1", "R2"}
    ):
        return "AUTO_REVERSIBLE"
    if (
        policy_pre_authorized
        and environment == "PRODUCTION"
        and risk == "R1"
        and action["reversible"]
        and action["rollback_steps"]
        and action["policy_authorization_ref"]
    ):
        return "AUTO_REVERSIBLE"
    return "HUMAN_GATED"
