from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import platform
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.assets.reconciliation import reconcile_service_expectations
from backend.app.assets.exposure import reconcile_listener_expectations
from backend.app.assets.service import ServiceExpectationService
from backend.app.assets.serialization import service_expectation_to_dict
from backend.app.core.database import get_session
from backend.app.core.pydantic_compat import BaseModel, Field
from backend.app.mcp.types import ToolResult
from backend.app.models.entities import utcnow
from backend.app.perception.tools import (
    NetworkListenersInput,
    ServiceStatusInput,
    network_listeners,
    service_status,
)


class ListenerExpectationRequest(BaseModel):
    protocol: str = Field(min_length=3, max_length=3)
    port: int = Field(ge=1, le=65535)
    allowed_scope: str = Field(min_length=6, max_length=16)
    required: bool = True


class ServiceExpectationCreateRequest(BaseModel):
    host_key: str = Field(min_length=1, max_length=256)
    unit_name: str = Field(min_length=9, max_length=256)
    expected_active_state: str = Field(min_length=6, max_length=16)
    service_owner: str = Field(min_length=1, max_length=256)
    criticality: str = Field(min_length=3, max_length=16)
    environment: str = Field(min_length=4, max_length=16)
    listener_expectations: list[ListenerExpectationRequest] = Field(
        default_factory=list,
    )
    rationale: str = Field(min_length=5, max_length=2000)
    source_ref: str = Field(min_length=1, max_length=1000)
    approved_by: str = Field(default="admin", min_length=1, max_length=128)
    effective_from: datetime | None = None
    expires_at: datetime | None = None


class ServiceExpectationRetireRequest(BaseModel):
    host_key: str = Field(min_length=1, max_length=256)
    unit_name: str = Field(min_length=9, max_length=256)
    reason: str = Field(min_length=5, max_length=2000)
    source_ref: str = Field(min_length=1, max_length=1000)
    approved_by: str = Field(default="admin", min_length=1, max_length=128)


def build_service_catalog_router(
    *,
    service_observer: Callable[[ServiceStatusInput], ToolResult] = service_status,
    network_observer: Callable[[NetworkListenersInput], ToolResult] = network_listeners,
    host_name_provider: Callable[[], str] = platform.node,
) -> APIRouter:
    router = APIRouter(prefix="/service-expectations", tags=["service-catalog"])

    @router.get("")
    def list_service_expectations(
        host_key: str | None = None,
        include_retired: bool = False,
        limit: int = 100,
        session: Session = Depends(get_session),
    ) -> list[dict[str, Any]]:
        try:
            records = ServiceExpectationService(session).list_current(
                host_key=host_key,
                include_retired=include_retired,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return [service_expectation_to_dict(record) for record in records]

    @router.get("/reconciliation")
    def reconcile_service_catalog(
        host_key: str,
        limit: int = 100,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        observed_host = host_name_provider().strip()
        if not observed_host or host_key.strip().casefold() != observed_host.casefold():
            raise HTTPException(
                status_code=409,
                detail="服务运行状态只能在对应的本机 Agent 节点核对。",
            )
        try:
            records = ServiceExpectationService(session).list_current(
                host_key=host_key,
                limit=limit,
            )
            items, summary = reconcile_service_expectations(
                records,
                observer=service_observer,
            )
            exposure = reconcile_listener_expectations(
                records,
                network_observer(NetworkListenersInput(limit=500)),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        for item in items:
            item["network_exposure"] = exposure["by_service"].get(
                item["expectation"].id,
                {
                    "status": "NOT_DECLARED",
                    "reason": "未登记网络监听要求。",
                    "checks": [],
                },
            )
        if exposure["summary"]["drift_count"]:
            summary["overall_status"] = "DRIFT"
        elif (
            exposure["summary"]["unknown_count"]
            and summary["overall_status"] == "IN_SYNC"
        ):
            summary["overall_status"] = "UNKNOWN"
        summary.update(
            {
                "listener_expectation_count": exposure["summary"][
                    "listener_expectation_count"
                ],
                "network_drift_count": exposure["summary"]["drift_count"],
                "network_unknown_count": exposure["summary"]["unknown_count"],
                "unmanaged_listener_count": exposure["summary"][
                    "unmanaged_listener_count"
                ],
            }
        )
        return {
            "host_key": host_key,
            "observed_host": observed_host,
            "observed_at": utcnow().isoformat(),
            "summary": summary,
            "unmanaged_listeners": exposure["unmanaged_listeners"],
            "network_evidence_refs": exposure["evidence_refs"],
            "network_warnings": exposure["warnings"],
            "items": [
                {
                    **item,
                    "expectation": service_expectation_to_dict(item["expectation"]),
                }
                for item in items
            ],
        }

    @router.get("/history")
    def read_service_expectation_history(
        host_key: str,
        unit_name: str,
        limit: int = 50,
        session: Session = Depends(get_session),
    ) -> list[dict[str, Any]]:
        try:
            records = ServiceExpectationService(session).history(
                host_key=host_key,
                unit_name=unit_name,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return [service_expectation_to_dict(record) for record in records]

    @router.post("")
    def register_service_expectation(
        payload: ServiceExpectationCreateRequest,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            record = ServiceExpectationService(session).register(**payload.model_dump())
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        session.commit()
        return service_expectation_to_dict(record)

    @router.post("/retire")
    def retire_service_expectation(
        payload: ServiceExpectationRetireRequest,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            record = ServiceExpectationService(session).retire(**payload.model_dump())
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        session.commit()
        return service_expectation_to_dict(record)

    return router
