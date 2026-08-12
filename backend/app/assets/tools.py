from __future__ import annotations

import socket

from backend.app.core.pydantic_compat import BaseModel, Field
from sqlalchemy.orm import Session, sessionmaker

from backend.app.assets.service import ServiceExpectationService
from backend.app.assets.serialization import service_expectation_to_dict
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.schemas.enums import RiskLevel


class ServiceDesiredStateInput(BaseModel):
    unit: str = Field(min_length=9, max_length=256, pattern=r"^[A-Za-z0-9_.@:-]+\.service$")
    host_key: str | None = Field(default=None, max_length=256, pattern=r"^(?:\*|[A-Za-z0-9_.:-]+)$")


class ServiceCatalogSnapshotInput(BaseModel):
    host_key: str | None = Field(
        default=None,
        max_length=256,
        pattern=r"^(?:\*|[A-Za-z0-9_.:-]+)$",
    )
    limit: int = Field(default=100, ge=1, le=500)


def register_service_expectation_tool(
    registry: ToolRegistry,
    session_factory: sessionmaker[Session],
) -> None:
    def service_desired_state(payload: BaseModel) -> ToolResult:
        args = ServiceDesiredStateInput.model_validate(payload)
        host_key = args.host_key or socket.gethostname()
        with session_factory() as session:
            record = ServiceExpectationService(session).resolve(
                host_key=host_key,
                unit_name=args.unit,
            )
            if record is None:
                return ToolResult(
                    warnings=[f"{args.unit} 未登记有效的服务期望状态。"],
                    summary_fields={
                        "registered": False,
                        "host_key": host_key,
                        "unit": args.unit,
                    },
                    evidence_refs=[f"service-expectation:{host_key}:{args.unit}:missing"],
                )
            return ToolResult(
                observations=[
                    {
                        "unit": record.unit_name,
                        "host_key": record.host_key,
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
                        "version": record.version,
                        "record_status": record.record_status,
                        "effective_from": record.effective_from.isoformat(),
                        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
                    }
                ],
                evidence_refs=[f"service-expectation:{record.id}:v{record.version}"],
                summary_fields={
                    "registered": True,
                    "host_key": record.host_key,
                    "unit": record.unit_name,
                    "version": record.version,
                },
            )

    registry.register(
        ToolDefinition(
            name="service_desired_state",
            version="1.1.0",
            description=(
                "Read the operator-approved owner, criticality, environment, expected "
                "active state, and allowed network listeners for an observed systemd service."
            ),
            risk_level=RiskLevel.R0,
            input_model=ServiceDesiredStateInput,
            output_model=ToolResult,
            handler=service_desired_state,
        )
    )

    def service_catalog_snapshot(payload: BaseModel) -> ToolResult:
        args = ServiceCatalogSnapshotInput.model_validate(payload)
        host_key = args.host_key or socket.gethostname()
        with session_factory() as session:
            records = ServiceExpectationService(session).list_current(
                host_key=host_key,
                limit=args.limit,
            )
            observations = [
                service_expectation_to_dict(record)
                for record in records
            ]
            listener_count = sum(
                len(record.listener_expectations_json or [])
                for record in records
            )
            return ToolResult(
                observations=observations,
                warnings=(
                    []
                    if observations
                    else [f"{host_key} 尚未登记有效服务目录。"]
                ),
                evidence_refs=[
                    f"service-expectation:{record.id}:v{record.version}"
                    for record in records
                ],
                summary_fields={
                    "host_key": host_key,
                    "service_count": len(records),
                    "listener_expectation_count": listener_count,
                    "critical_service_count": sum(
                        record.criticality in {"CRITICAL", "HIGH"}
                        for record in records
                    ),
                },
            )

    registry.register(
        ToolDefinition(
            name="service_catalog_snapshot",
            version="1.0.0",
            description=(
                "Read the current operator-approved service catalog for this "
                "host, including owners, criticality, expected runtime state, "
                "and allowed listener scopes."
            ),
            risk_level=RiskLevel.R0,
            input_model=ServiceCatalogSnapshotInput,
            output_model=ToolResult,
            handler=service_catalog_snapshot,
        )
    )
