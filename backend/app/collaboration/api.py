from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.collaboration.agentteams import (
    AgentTeamsClient,
    AgentTeamsConfigurationError,
    AgentTeamsConnection,
    AgentTeamsProtocolError,
)
from backend.app.collaboration.auth import (
    CollaborationIdentityConfigurationError,
    callback_token_matches,
)
from backend.app.collaboration.manifest import TEAM_MANIFEST
from backend.app.collaboration.service import (
    CollaborationAuthorizationError,
    CollaborationStateError,
    IncidentCollaborationService,
)
from backend.app.core.config import settings
from backend.app.core.database import get_session
from backend.app.core.pydantic_compat import BaseModel, Field
from backend.app.models.entities import Finding, Incident


class IncidentCreateRequest(BaseModel):
    host_key: str = Field(min_length=1, max_length=256)
    signal_key: str = Field(min_length=1, max_length=128)
    severity: str = Field(pattern="^(WARN|CRITICAL)$")
    title: str = Field(min_length=1, max_length=256)
    summary: str = Field(min_length=1, max_length=4000)
    dedupe_key: str | None = Field(default=None, max_length=512)
    evidence_refs: list[str] = Field(default_factory=list, max_items=200)


class WorkClaimRequest(BaseModel):
    role: str = Field(min_length=1, max_length=64)
    agent_name: str = Field(min_length=1, max_length=128)
    lease_seconds: int = Field(default=300, ge=30, le=3600)


class WorkSubmitRequest(BaseModel):
    role: str = Field(min_length=1, max_length=64)
    agent_name: str = Field(min_length=1, max_length=128)
    output: dict[str, Any]
    source_event_id: str | None = Field(default=None, max_length=128)


class ExecutionRecordRequest(BaseModel):
    controller_id: str = Field(default="policy-controller", min_length=1, max_length=128)
    output: dict[str, Any]
    source_event_id: str | None = Field(default=None, max_length=128)


class AgentTeamsBindRequest(BaseModel):
    room_id: str = Field(min_length=1, max_length=255)


def build_collaboration_router() -> APIRouter:
    router = APIRouter(prefix="/collaboration", tags=["incident collaboration"])

    @router.get("/team")
    def read_team_manifest() -> dict[str, Any]:
        return TEAM_MANIFEST

    @router.get("/agentteams/status")
    def read_agentteams_status() -> dict[str, Any]:
        return _agentteams_client().status()

    @router.post(
        "/incidents",
        status_code=status.HTTP_201_CREATED,
    )
    def create_incident(
        payload: IncidentCreateRequest,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        service = IncidentCollaborationService(session)
        collaboration = service.create_incident(
            host_key=payload.host_key,
            signal_key=payload.signal_key,
            severity=payload.severity,
            title=payload.title,
            summary=payload.summary,
            dedupe_key=payload.dedupe_key,
            initial_evidence_refs=payload.evidence_refs,
        )
        session.commit()
        return _detail(service, collaboration.id)

    @router.get("/incidents")
    def list_incident_collaborations(
        limit: int = 50,
        session: Session = Depends(get_session),
    ) -> list[dict[str, Any]]:
        service = IncidentCollaborationService(session)
        return [
            _summary(item)
            for item in service.list(limit=limit)
        ]

    @router.get("/incidents/{collaboration_id}")
    def read_incident_collaboration(
        collaboration_id: int,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        return _detail_or_404(IncidentCollaborationService(session), collaboration_id)

    @router.post(
        "/patrol-incidents/{incident_id}",
        status_code=status.HTTP_201_CREATED,
    )
    def start_patrol_incident_collaboration(
        incident_id: int,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        evidence_refs = [
            ref
            for finding in session.scalars(
                select(Finding).where(Finding.incident_id == incident_id)
            )
            for ref in (
                finding.evidence_refs_json
                if isinstance(finding.evidence_refs_json, list)
                else []
            )
        ]
        service = IncidentCollaborationService(session)
        collaboration = service.start(
            incident_id,
            initial_evidence_refs=evidence_refs,
            source="operator",
        )
        session.commit()
        return _detail(service, collaboration.id)

    @router.post("/incidents/{collaboration_id}/agentteams/bind")
    def bind_agentteams_room(
        collaboration_id: int,
        payload: AgentTeamsBindRequest,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        service = IncidentCollaborationService(session)
        try:
            service.bind_agentteams_room(collaboration_id, room_id=payload.room_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        session.commit()
        return _detail(service, collaboration_id)

    @router.post("/incidents/{collaboration_id}/agentteams/dispatch")
    def dispatch_to_agentteams(
        collaboration_id: int,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        service = IncidentCollaborationService(session)
        detail = _detail_or_404(service, collaboration_id)
        try:
            event_id = _agentteams_client().dispatch_incident(detail)
        except (AgentTeamsConfigurationError, AgentTeamsProtocolError) as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        service.record_agentteams_dispatch(collaboration_id, event_id=event_id)
        session.commit()
        return {"collaboration_id": collaboration_id, "event_id": event_id}

    @router.post("/incidents/{collaboration_id}/work/{work_key}/claim")
    def claim_work(
        collaboration_id: int,
        work_key: str,
        payload: WorkClaimRequest,
        x_opscouncil_agent_token: str | None = Header(default=None),
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        _require_agent_token(payload.agent_name, x_opscouncil_agent_token)
        service = IncidentCollaborationService(session)
        try:
            item = service.claim(
                collaboration_id,
                work_key,
                role=payload.role,
                agent_name=payload.agent_name,
                lease_seconds=payload.lease_seconds,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except CollaborationAuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except CollaborationStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        session.commit()
        return _work_item(item)

    @router.post("/incidents/{collaboration_id}/work/{work_key}/submit")
    def submit_work(
        collaboration_id: int,
        work_key: str,
        payload: WorkSubmitRequest,
        x_opscouncil_agent_token: str | None = Header(default=None),
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        _require_agent_token(payload.agent_name, x_opscouncil_agent_token)
        service = IncidentCollaborationService(session)
        try:
            service.submit(
                collaboration_id,
                work_key,
                role=payload.role,
                agent_name=payload.agent_name,
                output=payload.output,
                source_event_id=payload.source_event_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except CollaborationAuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except CollaborationStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        session.commit()
        return _detail(service, collaboration_id)

    @router.post("/incidents/{collaboration_id}/execution")
    def record_execution(
        collaboration_id: int,
        payload: ExecutionRecordRequest,
        x_opscouncil_agent_token: str | None = Header(default=None),
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        _require_controller_token(payload.controller_id, x_opscouncil_agent_token)
        service = IncidentCollaborationService(session)
        try:
            service.record_execution(
                collaboration_id,
                output=payload.output,
                controller_id=payload.controller_id,
                source_event_id=payload.source_event_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except CollaborationStateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        session.commit()
        return _detail(service, collaboration_id)

    @router.get("/incidents/{collaboration_id}/audit/verify")
    def verify_collaboration_audit(
        collaboration_id: int,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        service = IncidentCollaborationService(session)
        if service.get(collaboration_id) is None:
            raise HTTPException(status_code=404, detail="collaboration not found")
        return service.verify_chain(collaboration_id)

    return router


def _agentteams_client() -> AgentTeamsClient:
    return AgentTeamsClient(
        AgentTeamsConnection(
            matrix_url=settings.agentteams_matrix_url,
            username=settings.agentteams_username,
            password=settings.agentteams_password,
            leader_room_id=settings.agentteams_leader_room_id,
        )
    )


def _require_agent_token(agent_name: str, received: str | None) -> None:
    _require_subject_token(f"agent:{agent_name}", received)


def _require_controller_token(controller_id: str, received: str | None) -> None:
    _require_subject_token(f"controller:{controller_id}", received)


def _require_subject_token(subject: str, received: str | None) -> None:
    try:
        matches = callback_token_matches(subject, received)
    except CollaborationIdentityConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not matches:
        raise HTTPException(status_code=401, detail="invalid AgentTeams callback identity")


def _detail_or_404(
    service: IncidentCollaborationService,
    collaboration_id: int,
) -> dict[str, Any]:
    if service.get(collaboration_id) is None:
        raise HTTPException(status_code=404, detail="collaboration not found")
    return _detail(service, collaboration_id)


def _detail(service: IncidentCollaborationService, collaboration_id: int) -> dict[str, Any]:
    collaboration = service.get(collaboration_id)
    if collaboration is None:
        raise LookupError("collaboration not found")
    incident = service.session.get(Incident, collaboration.incident_id)
    return {
        **_summary(collaboration),
        "incident": {
            "id": incident.id,
            "host_key": incident.host_key,
            "signal_key": incident.signal_key,
            "severity": incident.severity,
            "title": incident.title,
            "summary": incident.summary,
            "status": incident.status,
            "task_id": incident.task_id,
        } if incident is not None else None,
        "shared_context": collaboration.shared_context_json,
        "action_contract": collaboration.action_contract_json,
        "execution": collaboration.execution_json,
        "work_items": [_work_item(item) for item in service.work_items(collaboration_id)],
        "events": [_event(item) for item in service.events(collaboration_id)],
        "audit": service.verify_chain(collaboration_id),
    }


def _summary(collaboration: Any) -> dict[str, Any]:
    return {
        "id": collaboration.id,
        "incident_id": collaboration.incident_id,
        "team_name": collaboration.team_name,
        "status": collaboration.status,
        "evidence_gate_status": collaboration.evidence_gate_status,
        "autonomy_mode": collaboration.autonomy_mode,
        "agentteams_room_id": collaboration.agentteams_room_id,
        "context_version": collaboration.context_version,
        "action_contract_hash": collaboration.action_contract_hash,
        "created_at": collaboration.created_at.isoformat(),
        "updated_at": collaboration.updated_at.isoformat(),
        "completed_at": (
            collaboration.completed_at.isoformat()
            if collaboration.completed_at is not None
            else None
        ),
    }


def _work_item(item: Any) -> dict[str, Any]:
    return {
        "id": item.id,
        "work_key": item.work_key,
        "role": item.role,
        "skill_id": item.skill_id,
        "status": item.status,
        "depends_on": item.depends_on_json,
        "input": item.input_json,
        "output": item.output_json,
        "evidence_refs": item.evidence_refs_json,
        "assigned_agent": item.assigned_agent,
        "attempt_count": item.attempt_count,
        "started_at": item.started_at.isoformat() if item.started_at is not None else None,
        "completed_at": item.completed_at.isoformat() if item.completed_at is not None else None,
    }


def _event(item: Any) -> dict[str, Any]:
    return {
        "id": item.id,
        "sequence": item.sequence,
        "work_item_id": item.work_item_id,
        "actor": item.actor,
        "event_type": item.event_type,
        "source_system": item.source_system,
        "source_event_id": item.source_event_id,
        "payload": item.payload_json,
        "event_hash": item.event_hash,
        "created_at": item.created_at.isoformat(),
    }
