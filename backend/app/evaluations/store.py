from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import EvaluationReport


class EvaluationReportStore:
    def __init__(self, session: Session, report_type: str, *, scope_key: str | None = None) -> None:
        self.session = session
        self.report_type = report_type
        self.scope_key = scope_key

    def save(self, report: dict[str, Any]) -> None:
        report_id = str(report.get("id") or "").strip()
        if not report_id:
            raise ValueError("evaluation report requires an id")
        self.session.add(
            EvaluationReport(
                report_type=self.report_type,
                report_id=report_id,
                scope_key=self.scope_key,
                payload_json=report,
            )
        )
        self.session.flush()

    def latest(self) -> dict[str, Any] | None:
        row = self.session.scalars(
            select(EvaluationReport)
            .where(
                EvaluationReport.report_type == self.report_type,
                EvaluationReport.scope_key == self.scope_key,
            )
            .order_by(EvaluationReport.created_at.desc(), EvaluationReport.id.desc())
            .limit(1)
        ).first()
        return dict(row.payload_json) if row is not None else None

    def latest_by_scope(self) -> dict[str, dict[str, Any]]:
        rows = self.session.scalars(
            select(EvaluationReport)
            .where(
                EvaluationReport.report_type == self.report_type,
                EvaluationReport.scope_key.is_not(None),
            )
            .order_by(EvaluationReport.created_at.desc(), EvaluationReport.id.desc())
        ).all()
        latest: dict[str, dict[str, Any]] = {}
        for row in rows:
            assert row.scope_key is not None
            latest.setdefault(row.scope_key, dict(row.payload_json))
        return latest
