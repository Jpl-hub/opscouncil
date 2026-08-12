from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.channels.feishu.identity import (
    ExternalIdentityConflictError,
    ExternalIdentityDeniedError,
    ExternalIdentityNotFoundError,
    OperatorIdentityService,
)
from backend.app.models.entities import ChannelInboundEvent, Operator, OperatorExternalIdentity


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Operator.__table__.create(engine)
    OperatorExternalIdentity.__table__.create(engine)
    ChannelInboundEvent.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


def test_explicit_mapping_resolves_only_the_same_tenant_and_active_operator() -> None:
    with build_session() as session:
        service = OperatorIdentityService(session)
        operator = service.create_operator(
            username="oncall-a",
            display_name="值班工程师",
            role="OPERATOR",
        )
        identity = service.map_feishu_identity(
            operator.id,
            tenant_key="tenant-a",
            open_id="open-a",
        )

        resolved = service.resolve_feishu_identity("tenant-a", "open-a")

        assert identity.operator_id == operator.id
        assert resolved.id == operator.id
        try:
            service.resolve_feishu_identity("tenant-b", "open-a")
        except ExternalIdentityNotFoundError as exc:
            assert exc.code == "IDENTITY_NOT_MAPPED"
        else:
            raise AssertionError("an identity must not cross tenant boundaries")


def test_disabled_identity_or_viewer_cannot_submit_operations() -> None:
    with build_session() as session:
        service = OperatorIdentityService(session)
        viewer = service.create_operator(
            username="viewer-a",
            display_name="只读观察员",
            role="VIEWER",
        )
        identity = service.map_feishu_identity(
            viewer.id,
            tenant_key="tenant-a",
            open_id="open-viewer",
        )

        try:
            service.resolve_feishu_identity(
                "tenant-a",
                "open-viewer",
                allowed_roles={"OPERATOR", "APPROVER", "ADMIN"},
            )
        except ExternalIdentityDeniedError as exc:
            assert exc.code == "ROLE_NOT_ALLOWED"
        else:
            raise AssertionError("viewer identities must not create tasks")

        service.set_identity_status(identity.id, "DISABLED")
        try:
            service.resolve_feishu_identity("tenant-a", "open-viewer")
        except ExternalIdentityDeniedError as exc:
            assert exc.code == "IDENTITY_DISABLED"
        else:
            raise AssertionError("disabled identities must not resolve")


def test_external_identity_cannot_be_silently_reassigned() -> None:
    with build_session() as session:
        service = OperatorIdentityService(session)
        first = service.create_operator("first", "一线值班", "OPERATOR")
        second = service.create_operator("second", "二线值班", "APPROVER")
        service.map_feishu_identity(first.id, tenant_key="tenant-a", open_id="open-a")

        try:
            service.map_feishu_identity(second.id, tenant_key="tenant-a", open_id="open-a")
        except ExternalIdentityConflictError as exc:
            assert exc.code == "IDENTITY_ALREADY_MAPPED"
        else:
            raise AssertionError("identity reassignment must require an explicit disable/remap flow")


def test_unmapped_inbound_identity_is_grouped_until_explicitly_bound() -> None:
    with build_session() as session:
        service = OperatorIdentityService(session)
        operator = service.create_operator("oncall-a", "值班工程师", "OPERATOR")
        for index in range(2):
            session.add(
                ChannelInboundEvent(
                    channel="FEISHU",
                    external_event_id=f"event-{index}",
                    event_type="im.message.receive_v1",
                    tenant_key="tenant-a",
                    external_actor_id="open-a",
                    payload_hash=f"{index:064d}",
                    status="REJECTED",
                    reason_code="IDENTITY_NOT_MAPPED",
                )
            )
        session.flush()

        pending = service.list_pending_feishu_identities()

        assert len(pending) == 1
        assert pending[0].tenant_key == "tenant-a"
        assert pending[0].open_id == "open-a"
        assert pending[0].attempt_count == 2

        service.map_feishu_identity(operator.id, tenant_key="tenant-a", open_id="open-a")

        assert service.list_pending_feishu_identities() == []
