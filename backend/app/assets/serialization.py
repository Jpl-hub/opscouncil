from __future__ import annotations

from typing import Any

from backend.app.models.entities import ServiceExpectation


def service_expectation_to_dict(
    record: ServiceExpectation,
) -> dict[str, Any]:
    return {
        "id": record.id,
        "host_key": record.host_key,
        "unit_name": record.unit_name,
        "version": record.version,
        "record_status": record.record_status,
        "expected_active_state": record.expected_active_state,
        "service_owner": record.service_owner,
        "criticality": record.criticality,
        "environment": record.environment,
        "listener_expectations": list(
            record.listener_expectations_json or []
        ),
        "rationale": record.rationale,
        "source_ref": record.source_ref,
        "approved_by": record.approved_by,
        "effective_from": record.effective_from.isoformat(),
        "expires_at": (
            record.expires_at.isoformat()
            if record.expires_at
            else None
        ),
        "created_at": record.created_at.isoformat(),
    }
