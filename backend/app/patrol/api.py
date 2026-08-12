from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.database import get_session
from backend.app.mcp.registry import ToolRegistry
from backend.app.models.entities import Finding, Incident, PatrolPolicy, PatrolRun, Task, utcnow
from backend.app.patrol.service import PatrolService
from backend.app.patrol.timeline import IncidentTimelineService


OPEN_FINDING_STATUSES = {"OPEN", "ACKNOWLEDGED"}
OPEN_INCIDENT_STATUSES = {"OPEN", "INVESTIGATING"}
TERMINAL_TASK_STATUSES = {
    "SEALED",
    "REJECTED",
    "BLOCKED",
    "FAILED",
    "NEEDS_OPERATOR",
    "CANCELLED",
    "ROLLED_BACK",
}
FINDING_STATUSES = OPEN_FINDING_STATUSES | {"RESOLVED"}
INCIDENT_STATUSES = OPEN_INCIDENT_STATUSES | {"RESOLVED", "CLOSED"}
SEVERITIES = {"WARN", "CRITICAL"}


def build_patrol_router(
    registry: ToolRegistry,
    session_factory: sessionmaker[Session],
) -> APIRouter:
    router = APIRouter()

    @router.get("/patrol/overview")
    def patrol_overview(session: Session = Depends(get_session)) -> dict[str, Any]:
        open_findings = session.scalar(
            select(func.count()).select_from(Finding).where(Finding.status.in_(OPEN_FINDING_STATUSES))
        )
        open_incidents = session.scalar(
            select(func.count()).select_from(Incident).where(Incident.status.in_(OPEN_INCIDENT_STATUSES))
        )
        latest_run = session.scalar(select(PatrolRun).order_by(PatrolRun.id.desc()).limit(1))
        policies = list(session.scalars(select(PatrolPolicy).order_by(PatrolPolicy.id.asc())))
        return {
            "open_finding_count": int(open_findings or 0),
            "open_incident_count": int(open_incidents or 0),
            "latest_run": _run_response(latest_run) if latest_run is not None else None,
            "policies": [_policy_response(policy) for policy in policies],
        }

    @router.get("/findings")
    def list_findings(
        status: str | None = None,
        severity: str | None = None,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        normalized_status = _optional_filter(status, FINDING_STATUSES, "finding status")
        normalized_severity = _optional_filter(severity, SEVERITIES, "finding severity")
        filters = []
        if normalized_status is not None:
            filters.append(Finding.status == normalized_status)
        if normalized_severity is not None:
            filters.append(Finding.severity == normalized_severity)
        total = session.scalar(select(func.count()).select_from(Finding).where(*filters))
        rows = list(
            session.scalars(
                select(Finding)
                .where(*filters)
                .order_by(Finding.last_observed_at.desc(), Finding.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        return _page([_finding_response(item) for item in rows], int(total or 0), page, page_size)

    @router.get("/incidents")
    def list_incidents(
        status: str | None = None,
        severity: str | None = None,
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        normalized_status = _optional_filter(status, INCIDENT_STATUSES, "incident status")
        normalized_severity = _optional_filter(severity, SEVERITIES, "incident severity")
        filters = []
        if normalized_status is not None:
            filters.append(Incident.status == normalized_status)
        if normalized_severity is not None:
            filters.append(Incident.severity == normalized_severity)
        total = session.scalar(select(func.count()).select_from(Incident).where(*filters))
        rows = list(
            session.scalars(
                select(Incident)
                .where(*filters)
                .order_by(Incident.updated_at.desc(), Incident.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        return _page(
            [_incident_response(item, session.get(Task, item.task_id) if item.task_id else None) for item in rows],
            int(total or 0),
            page,
            page_size,
        )

    @router.post("/patrol/policies/{policy_id}/run")
    def run_policy(policy_id: int) -> dict[str, Any]:
        try:
            run = PatrolService(
                session_factory,
                registry,
                seed_default_policy=False,
            ).run_policy(policy_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return _run_response(run)

    @router.get("/incidents/{incident_id}/timeline")
    def read_incident_timeline(
        incident_id: int,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            return IncidentTimelineService(session).read(incident_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.post("/findings/{finding_id}/acknowledge")
    def acknowledge_finding(
        finding_id: int,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        finding = session.execute(
            select(Finding).where(Finding.id == finding_id).with_for_update()
        ).scalar_one_or_none()
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        if finding.status == "RESOLVED":
            raise HTTPException(status_code=409, detail="resolved finding cannot be acknowledged")
        finding.status = "ACKNOWLEDGED"
        session.flush()
        return _finding_response(finding)

    @router.post("/incidents/{incident_id}/close")
    def close_incident(
        incident_id: int,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        incident = session.execute(
            select(Incident).where(Incident.id == incident_id).with_for_update()
        ).scalar_one_or_none()
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        task = session.get(Task, incident.task_id) if incident.task_id is not None else None
        if task is not None and task.status not in TERMINAL_TASK_STATUSES:
            raise HTTPException(status_code=409, detail="linked investigation task is still running")
        closed_at = utcnow()
        incident.status = "CLOSED"
        incident.dedupe_key = None
        incident.updated_at = closed_at
        incident.closed_at = closed_at
        findings = list(
            session.scalars(
                select(Finding)
                .where(
                    Finding.incident_id == incident.id,
                    Finding.status.in_(OPEN_FINDING_STATUSES),
                )
                .with_for_update()
            )
        )
        for finding in findings:
            finding.status = "RESOLVED"
            finding.resolved_at = closed_at
        session.flush()
        return _incident_response(incident, task)

    return router


def _finding_response(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "policy_id": finding.policy_id,
        "patrol_run_id": finding.patrol_run_id,
        "incident_id": finding.incident_id,
        "host_key": finding.host_key,
        "signal_key": finding.signal_key,
        "severity": finding.severity,
        "status": finding.status,
        "title": finding.title,
        "summary": finding.summary,
        "metric": finding.metric_json,
        "evidence_refs": finding.evidence_refs_json,
        "first_observed_at": _iso(finding.first_observed_at),
        "last_observed_at": _iso(finding.last_observed_at),
        "occurrence_count": finding.occurrence_count,
        "resolved_at": _iso(finding.resolved_at),
    }


def _incident_response(incident: Incident, task: Task | None) -> dict[str, Any]:
    return {
        "id": incident.id,
        "host_key": incident.host_key,
        "signal_key": incident.signal_key,
        "severity": incident.severity,
        "status": incident.status,
        "title": incident.title,
        "summary": incident.summary,
        "task_id": incident.task_id,
        "task_status": task.status if task is not None else None,
        "trace_id": task.trace_id if task is not None else None,
        "healthy_streak": incident.healthy_streak,
        "recovery_target": incident.recovery_target,
        "last_healthy_at": _iso(incident.last_healthy_at),
        "opened_at": _iso(incident.opened_at),
        "updated_at": _iso(incident.updated_at),
        "closed_at": _iso(incident.closed_at),
    }


def _run_response(run: PatrolRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "policy_id": run.policy_id,
        "host_key": run.host_key,
        "status": run.status,
        "error": run.error,
        "started_at": _iso(run.started_at),
        "completed_at": _iso(run.completed_at),
        "collection_status": (
            run.snapshot_json.get("collection_status")
            if isinstance(run.snapshot_json, dict)
            else None
        ),
    }


def _policy_response(policy: PatrolPolicy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "name": policy.name,
        "enabled": policy.enabled,
        "interval_seconds": policy.interval_seconds,
        "signal_keys": policy.signal_keys_json,
        "next_run_at": _iso(policy.next_run_at),
        "last_run_at": _iso(policy.last_run_at),
    }


def _page(items: list[dict[str, Any]], total: int, page: int, page_size: int) -> dict[str, Any]:
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "page_count": (total + page_size - 1) // page_size,
    }


def _optional_filter(value: str | None, allowed: set[str], label: str) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().upper()
    if normalized not in allowed:
        raise HTTPException(status_code=422, detail=f"invalid {label}")
    return normalized


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
