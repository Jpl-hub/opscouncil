from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_session
from backend.app.core.pydantic_compat import BaseModel, Field
from backend.app.operators.preferences import (
    OperatorPreferenceService,
    PreferenceVersionConflictError,
)


class OperatorPreferenceUpdateRequest(BaseModel):
    expected_version: int = Field(ge=1)
    summary_density: str = Field(min_length=1, max_length=16)
    evidence_view: str = Field(min_length=1, max_length=16)
    notification_route: str = Field(min_length=1, max_length=16)
    service_focus: list[str] = Field(default_factory=list, max_length=8)


class OperatorPreferenceForgetRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


def build_operator_preference_router() -> APIRouter:
    router = APIRouter()

    @router.get("/operator-context/{actor}")
    def read_operator_context(
        actor: str,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            return OperatorPreferenceService(session).context(actor)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.put("/operator-context/{actor}")
    def update_operator_context(
        actor: str,
        payload: OperatorPreferenceUpdateRequest,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            return OperatorPreferenceService(session).update(
                actor,
                expected_version=payload.expected_version,
                summary_density=payload.summary_density,
                evidence_view=payload.evidence_view,
                notification_route=payload.notification_route,
                service_focus=payload.service_focus,
            )
        except PreferenceVersionConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.delete("/operator-context/{actor}/learned-preferences")
    def forget_learned_operator_context(
        actor: str,
        payload: OperatorPreferenceForgetRequest,
        session: Session = Depends(get_session),
    ) -> dict[str, Any]:
        try:
            return OperatorPreferenceService(session).forget_learned(
                actor,
                reason=payload.reason,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return router
