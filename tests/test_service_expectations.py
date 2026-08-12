from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.assets.api import build_service_catalog_router
from backend.app.assets.exposure import reconcile_listener_expectations
from backend.app.assets.service import ServiceExpectationService
from backend.app.assets.tools import register_service_expectation_tool
from backend.app.core.database import get_session
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolResult
from backend.app.models.entities import ServiceExpectation


def build_session_factory() -> sessionmaker[Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    ServiceExpectation.__table__.create(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def approved_record(service: ServiceExpectationService, *, host_key: str = "node-a") -> ServiceExpectation:
    return service.register(
        host_key=host_key,
        unit_name="checkout-api.service",
        expected_active_state="active",
        service_owner="交易平台组",
        criticality="CRITICAL",
        environment="PRODUCTION",
        listener_expectations=[
            {
                "protocol": "tcp",
                "port": 8443,
                "allowed_scope": "private",
                "required": True,
            }
        ],
        rationale="结算入口在生产节点必须持续运行。",
        source_ref="CMDB-SVC-1042",
        approved_by="ops-admin",
    )


def test_expectations_are_versioned_and_retirement_does_not_delete_history() -> None:
    factory = build_session_factory()
    with factory() as session:
        service = ServiceExpectationService(session)
        first = approved_record(service)
        second = service.register(
            host_key="node-a",
            unit_name="checkout-api.service",
            expected_active_state="inactive",
            service_owner="交易平台组",
            criticality="HIGH",
            environment="STAGING",
            rationale="灰度节点已退出流量，当前应保持停止。",
            source_ref="CHANGE-2088",
            approved_by="ops-admin",
        )
        retired = service.retire(
            host_key="node-a",
            unit_name="checkout-api.service",
            reason="该节点已从资产清单下线。",
            source_ref="CMDB-OFFBOARD-44",
            approved_by="ops-admin",
        )

        assert (first.version, second.version, retired.version) == (1, 2, 3)
        assert service.resolve(host_key="node-a", unit_name="checkout-api.service") is None
        history = service.history(host_key="node-a", unit_name="checkout-api.service")
        assert [item.record_status for item in history] == ["RETIRED", "ACTIVE", "ACTIVE"]
        assert [item.version for item in history] == [3, 2, 1]


def test_host_record_overrides_wildcard_and_expired_record_is_not_authoritative() -> None:
    factory = build_session_factory()
    with factory() as session:
        service = ServiceExpectationService(session)
        approved_record(service, host_key="*")
        service.register(
            host_key="node-a",
            unit_name="checkout-api.service",
            expected_active_state="inactive",
            service_owner="发布保障组",
            criticality="HIGH",
            environment="STAGING",
            rationale="节点维护窗口内应保持停止。",
            source_ref="CHANGE-2091",
            approved_by="ops-admin",
            effective_from=datetime.now(timezone.utc) - timedelta(hours=2),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )

        assert service.resolve(host_key="node-a", unit_name="checkout-api.service") is None
        wildcard = service.resolve(host_key="node-b", unit_name="checkout-api.service")
        assert wildcard is not None
        assert wildcard.host_key == "*"
        assert wildcard.expected_active_state == "active"


def test_failed_is_not_an_allowed_desired_service_state() -> None:
    factory = build_session_factory()
    with factory() as session:
        service = ServiceExpectationService(session)
        try:
            service.register(
                host_key="node-a",
                unit_name="checkout-api.service",
                expected_active_state="failed",
                service_owner="交易平台组",
                criticality="HIGH",
                environment="PRODUCTION",
                rationale="错误状态不能被包装成期望状态。",
                source_ref="CMDB-SVC-1042",
                approved_by="ops-admin",
            )
        except ValueError as exc:
            assert "unsupported expected service state" in str(exc)
        else:
            raise AssertionError("failed must not be accepted as a desired service state")


def test_mcp_tool_returns_only_the_effective_approved_record() -> None:
    factory = build_session_factory()
    with factory() as session:
        approved_record(ServiceExpectationService(session), host_key="*")
        session.commit()

    registry = ToolRegistry()
    register_service_expectation_tool(registry, factory)
    result = registry.call(
        "service_desired_state",
        {"unit": "checkout-api.service", "host_key": "node-a"},
    )

    assert result.status == "ok"
    assert result.observations[0]["expected_active_state"] == "active"
    assert result.observations[0]["service_owner"] == "交易平台组"
    assert result.observations[0]["listener_expectations"][0]["port"] == 8443
    assert result.observations[0]["source_ref"] == "CMDB-SVC-1042"
    assert result.evidence_refs[0].startswith("service-expectation:")


def test_mcp_catalog_snapshot_returns_all_effective_host_records() -> None:
    factory = build_session_factory()
    with factory() as session:
        approved_record(ServiceExpectationService(session), host_key="node-a")
        session.commit()

    registry = ToolRegistry()
    register_service_expectation_tool(registry, factory)
    result = registry.call(
        "service_catalog_snapshot",
        {"host_key": "node-a"},
    )

    assert result.status == "ok"
    assert result.summary_fields["service_count"] == 1
    assert result.summary_fields["listener_expectation_count"] == 1
    assert result.observations[0]["unit_name"] == "checkout-api.service"
    assert result.observations[0]["listener_expectations"][0] == {
        "protocol": "tcp",
        "port": 8443,
        "allowed_scope": "private",
        "required": True,
    }


def test_service_catalog_api_registers_lists_retires_and_preserves_history() -> None:
    factory = build_session_factory()
    app = FastAPI()
    app.include_router(build_service_catalog_router(), prefix="/api")

    def override_session():  # type: ignore[no-untyped-def]
        with factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    client = TestClient(app)
    payload = {
        "host_key": "node-a",
        "unit_name": "checkout-api.service",
        "expected_active_state": "active",
        "service_owner": "交易平台组",
        "criticality": "CRITICAL",
        "environment": "PRODUCTION",
        "listener_expectations": [
            {
                "protocol": "tcp",
                "port": 8443,
                "allowed_scope": "private",
                "required": True,
            }
        ],
        "rationale": "结算入口在生产节点必须持续运行。",
        "source_ref": "CMDB-SVC-1042",
        "approved_by": "ops-admin",
    }

    created = client.post("/api/service-expectations", json=payload)
    assert created.status_code == 200
    assert created.json()["version"] == 1
    assert created.json()["listener_expectations"][0]["port"] == 8443
    listed = client.get("/api/service-expectations", params={"host_key": "node-a"})
    assert listed.status_code == 200
    assert [item["unit_name"] for item in listed.json()] == ["checkout-api.service"]

    retired = client.post(
        "/api/service-expectations/retire",
        json={
            "host_key": "node-a",
            "unit_name": "checkout-api.service",
            "reason": "资产已下线。",
            "source_ref": "CMDB-OFFBOARD-44",
            "approved_by": "ops-admin",
        },
    )
    assert retired.status_code == 200
    assert retired.json()["record_status"] == "RETIRED"
    history = client.get(
        "/api/service-expectations/history",
        params={"host_key": "node-a", "unit_name": "checkout-api.service"},
    )
    assert [item["version"] for item in history.json()] == [2, 1]


def test_service_catalog_reconciles_live_systemd_state_against_approved_expectation() -> None:
    factory = build_session_factory()

    def observe_service(payload):  # type: ignore[no-untyped-def]
        return ToolResult(
            observations=[
                {
                    "unit": payload.unit,
                    "load_state": "loaded",
                    "active_state": "failed",
                    "sub_state": "failed",
                    "result": "exit-code",
                    "main_pid": 0,
                    "restart_count": 0,
                }
            ],
            evidence_refs=["systemctl"],
        )

    def observe_network(payload):  # type: ignore[no-untyped-def]
        return ToolResult(
            observations=[],
            evidence_refs=["ss -H -lntupe"],
        )

    with factory() as session:
        service = ServiceExpectationService(session)
        service.register(
            host_key="node-a",
            unit_name="demo-lab.service",
            expected_active_state="inactive",
            service_owner="平台测试组",
            criticality="LOW",
            environment="TEST",
            rationale="受控服务常态应保持停止。",
            source_ref="LAB-SVC-1",
            approved_by="ops-admin",
        )
        session.commit()

    app = FastAPI()
    app.include_router(
        build_service_catalog_router(
            service_observer=observe_service,
            network_observer=observe_network,
            host_name_provider=lambda: "node-a",
        ),
        prefix="/api",
    )

    def override_session():  # type: ignore[no-untyped-def]
        with factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    response = TestClient(app).get(
        "/api/service-expectations/reconciliation",
        params={"host_key": "node-a"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"] == {
        "total_count": 1,
        "in_sync_count": 0,
        "drift_count": 1,
        "unknown_count": 0,
        "overall_status": "DRIFT",
        "listener_expectation_count": 0,
        "network_drift_count": 0,
        "network_unknown_count": 0,
        "unmanaged_listener_count": 0,
    }
    assert payload["items"][0]["runtime"]["active_state"] == "failed"
    assert payload["items"][0]["expectation"]["expected_active_state"] == "inactive"
    assert "当前 failed" in payload["items"][0]["reason"]


def test_listener_expectation_detects_scope_and_process_identity_drift() -> None:
    factory = build_session_factory()
    with factory() as session:
        record = approved_record(ServiceExpectationService(session))
        report = reconcile_listener_expectations(
            [record],
            ToolResult(
                observations=[
                    {
                        "protocol": "tcp",
                        "local_address": "0.0.0.0:8443",
                        "exposure_scope": "wildcard",
                        "pid": 42,
                        "process": "checkout-api",
                        "systemd_unit": "checkout-api.service",
                    }
                ],
                evidence_refs=["ss -H -lntupe"],
            ),
        )

        service_result = report["by_service"][record.id]
        assert service_result["status"] == "DRIFT"
        assert service_result["checks"][0]["status"] == "OVEREXPOSED"
        assert report["summary"]["drift_count"] == 1

        identity_report = reconcile_listener_expectations(
            [record],
            ToolResult(
                observations=[
                    {
                        "protocol": "tcp",
                        "local_address": "10.0.0.7:8443",
                        "exposure_scope": "private",
                        "pid": 71,
                        "process": "shadow-listener",
                        "systemd_unit": "unknown.service",
                    }
                ],
                evidence_refs=["ss -H -lntupe"],
            ),
        )
        assert (
            identity_report["by_service"][record.id]["checks"][0]["status"]
            == "IDENTITY_MISMATCH"
        )


def test_listener_expectations_reject_duplicates_and_inactive_listeners() -> None:
    factory = build_session_factory()
    with factory() as session:
        service = ServiceExpectationService(session)
        common = {
            "host_key": "node-a",
            "unit_name": "checkout-api.service",
            "service_owner": "交易平台组",
            "criticality": "CRITICAL",
            "environment": "PRODUCTION",
            "rationale": "结算入口的网络开放范围必须经过批准。",
            "source_ref": "CMDB-SVC-1042",
            "approved_by": "ops-admin",
        }
        duplicate = [
            {"protocol": "tcp", "port": 8443, "allowed_scope": "private"},
            {"protocol": "TCP", "port": 8443, "allowed_scope": "public"},
        ]
        try:
            service.register(
                **common,
                expected_active_state="active",
                listener_expectations=duplicate,
            )
        except ValueError as exc:
            assert "duplicate listener expectation" in str(exc)
        else:
            raise AssertionError("duplicate listener expectations must be rejected")

        try:
            service.register(
                **common,
                expected_active_state="inactive",
                listener_expectations=[
                    {
                        "protocol": "tcp",
                        "port": 8443,
                        "allowed_scope": "private",
                    }
                ],
            )
        except ValueError as exc:
            assert "inactive service expectation" in str(exc)
        else:
            raise AssertionError("inactive service cannot require listeners")


def test_service_catalog_refuses_to_reconcile_a_remote_host_with_local_state() -> None:
    factory = build_session_factory()
    observer_called = False

    def observe_service(payload):  # type: ignore[no-untyped-def]
        nonlocal observer_called
        observer_called = True
        return ToolResult()

    app = FastAPI()
    app.include_router(
        build_service_catalog_router(
            service_observer=observe_service,
            host_name_provider=lambda: "node-a",
        ),
        prefix="/api",
    )

    def override_session():  # type: ignore[no-untyped-def]
        with factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    response = TestClient(app).get(
        "/api/service-expectations/reconciliation",
        params={"host_key": "node-b"},
    )

    assert response.status_code == 409
    assert "本机 Agent 节点" in response.json()["detail"]
    assert observer_called is False
