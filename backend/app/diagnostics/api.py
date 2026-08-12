from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.service import AuditService
from backend.app.core.database import get_session
from backend.app.diagnostics.bundle import BUNDLE_SCHEMA, DiagnosticBundleService
from backend.app.models.entities import Task


_TERMINAL_TASK_STATUSES = {
    "SEALED",
    "REJECTED",
    "BLOCKED",
    "FAILED",
    "NEEDS_OPERATOR",
    "CANCELLED",
    "ROLLED_BACK",
}


def build_diagnostic_router() -> APIRouter:
    router = APIRouter()

    @router.post("/tasks/{task_id}/diagnostic-bundle")
    def export_task_diagnostic_bundle(
        task_id: int,
        session: Session = Depends(get_session),
    ) -> Response:
        task = session.scalar(
            select(Task).where(Task.id == task_id).with_for_update()
        )
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")

        try:
            bundle = DiagnosticBundleService(session).build(task.id)
            stage = "SEALED" if task.status in _TERMINAL_TASK_STATUSES else "INVESTIGATE"
            AuditService(session).append_event(
                task,
                stage,
                "diagnostic_bundle_exported",
                "导出任务诊断包。",
                {
                    "schema": BUNDLE_SCHEMA,
                    "filename": bundle.filename,
                    "sha256": bundle.sha256,
                    "bytes": len(bundle.content),
                },
            )
            session.commit()
        except Exception:
            session.rollback()
            raise

        return Response(
            content=bundle.content,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{bundle.filename}"',
                "X-OpsCouncil-Bundle-SHA256": bundle.sha256,
                "X-Content-Type-Options": "nosniff",
            },
        )

    return router
