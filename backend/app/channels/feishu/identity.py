from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.models.entities import ChannelInboundEvent, Operator, OperatorExternalIdentity, utcnow


OPERATOR_ROLES = frozenset({"VIEWER", "OPERATOR", "APPROVER", "ADMIN"})
OPERATOR_STATUSES = frozenset({"ACTIVE", "DISABLED"})
OPERATION_ROLES = frozenset({"OPERATOR", "APPROVER", "ADMIN"})


@dataclass(frozen=True)
class PendingFeishuIdentity:
    tenant_key: str
    open_id: str
    first_seen_at: str
    last_seen_at: str
    attempt_count: int


class ExternalIdentityError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ExternalIdentityNotFoundError(ExternalIdentityError):
    pass


class ExternalIdentityDeniedError(ExternalIdentityError):
    pass


class ExternalIdentityConflictError(ExternalIdentityError):
    pass


class OperatorIdentityService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_operator(
        self,
        username: str,
        display_name: str,
        role: str = "OPERATOR",
    ) -> Operator:
        normalized_username = _bounded_required(username, "username", 128)
        normalized_name = _bounded_required(display_name, "display_name", 128)
        normalized_role = role.strip().upper()
        if normalized_role not in OPERATOR_ROLES:
            raise ValueError("unknown operator role")
        existing = self.session.scalar(
            select(Operator).where(Operator.username == normalized_username)
        )
        if existing is not None:
            raise ExternalIdentityConflictError(
                "OPERATOR_ALREADY_EXISTS",
                "operator username already exists",
            )
        operator = Operator(
            username=normalized_username,
            display_name=normalized_name,
            role=normalized_role,
            status="ACTIVE",
        )
        self.session.add(operator)
        self.session.flush()
        return operator

    def map_feishu_identity(
        self,
        operator_id: int,
        *,
        tenant_key: str,
        open_id: str,
    ) -> OperatorExternalIdentity:
        operator = self.session.get(Operator, operator_id)
        if operator is None:
            raise LookupError("operator not found")
        tenant = _bounded_required(tenant_key, "tenant_key", 128)
        external_user_id = _bounded_required(open_id, "open_id", 128)
        existing = self.session.scalar(
            select(OperatorExternalIdentity).where(
                OperatorExternalIdentity.provider == "FEISHU",
                OperatorExternalIdentity.tenant_key == tenant,
                OperatorExternalIdentity.external_user_id == external_user_id,
            )
        )
        if existing is not None:
            if existing.operator_id == operator.id:
                return existing
            raise ExternalIdentityConflictError(
                "IDENTITY_ALREADY_MAPPED",
                "external identity is already mapped to another operator",
            )
        identity = OperatorExternalIdentity(
            operator_id=operator.id,
            provider="FEISHU",
            tenant_key=tenant,
            external_user_id=external_user_id,
            status="ACTIVE",
        )
        self.session.add(identity)
        self.session.flush()
        return identity

    def resolve_feishu_identity(
        self,
        tenant_key: str,
        open_id: str,
        *,
        allowed_roles: Iterable[str] | None = None,
    ) -> Operator:
        tenant = _bounded_required(tenant_key, "tenant_key", 128)
        external_user_id = _bounded_required(open_id, "open_id", 128)
        row = self.session.execute(
            select(OperatorExternalIdentity, Operator)
            .join(Operator, Operator.id == OperatorExternalIdentity.operator_id)
            .where(
                OperatorExternalIdentity.provider == "FEISHU",
                OperatorExternalIdentity.tenant_key == tenant,
                OperatorExternalIdentity.external_user_id == external_user_id,
            )
        ).one_or_none()
        if row is None:
            raise ExternalIdentityNotFoundError(
                "IDENTITY_NOT_MAPPED",
                "Feishu identity is not mapped",
            )
        identity, operator = row
        if identity.status != "ACTIVE":
            raise ExternalIdentityDeniedError(
                "IDENTITY_DISABLED",
                "Feishu identity is disabled",
            )
        if operator.status != "ACTIVE":
            raise ExternalIdentityDeniedError(
                "OPERATOR_DISABLED",
                "operator is disabled",
            )
        permitted = {item.strip().upper() for item in (allowed_roles or OPERATOR_ROLES)}
        if operator.role not in permitted:
            raise ExternalIdentityDeniedError(
                "ROLE_NOT_ALLOWED",
                "operator role is not allowed for this operation",
            )
        return operator

    def set_identity_status(self, identity_id: int, status: str) -> OperatorExternalIdentity:
        normalized_status = status.strip().upper()
        if normalized_status not in OPERATOR_STATUSES:
            raise ValueError("unknown identity status")
        identity = self.session.get(OperatorExternalIdentity, identity_id)
        if identity is None:
            raise LookupError("external identity not found")
        identity.status = normalized_status
        identity.updated_at = utcnow()
        self.session.flush()
        return identity

    def set_operator_status(self, operator_id: int, status: str) -> Operator:
        normalized_status = status.strip().upper()
        if normalized_status not in OPERATOR_STATUSES:
            raise ValueError("unknown operator status")
        operator = self.session.get(Operator, operator_id)
        if operator is None:
            raise LookupError("operator not found")
        operator.status = normalized_status
        operator.updated_at = utcnow()
        self.session.flush()
        return operator

    def list_operators(self) -> list[Operator]:
        return list(self.session.scalars(select(Operator).order_by(Operator.username.asc())))

    def list_feishu_identities(self) -> list[OperatorExternalIdentity]:
        return list(
            self.session.scalars(
                select(OperatorExternalIdentity)
                .where(OperatorExternalIdentity.provider == "FEISHU")
                .order_by(OperatorExternalIdentity.id.asc())
            )
        )

    def list_pending_feishu_identities(self) -> list[PendingFeishuIdentity]:
        mapped_identity = (
            select(OperatorExternalIdentity.id)
            .where(
                OperatorExternalIdentity.provider == "FEISHU",
                OperatorExternalIdentity.tenant_key == ChannelInboundEvent.tenant_key,
                OperatorExternalIdentity.external_user_id == ChannelInboundEvent.external_actor_id,
            )
            .exists()
        )
        rows = self.session.execute(
            select(
                ChannelInboundEvent.tenant_key,
                ChannelInboundEvent.external_actor_id,
                func.min(ChannelInboundEvent.created_at),
                func.max(ChannelInboundEvent.created_at),
                func.count(ChannelInboundEvent.id),
            )
            .where(
                ChannelInboundEvent.channel == "FEISHU",
                ChannelInboundEvent.status == "REJECTED",
                ChannelInboundEvent.reason_code == "IDENTITY_NOT_MAPPED",
                ~mapped_identity,
            )
            .group_by(ChannelInboundEvent.tenant_key, ChannelInboundEvent.external_actor_id)
            .order_by(func.max(ChannelInboundEvent.created_at).desc())
        ).all()
        return [
            PendingFeishuIdentity(
                tenant_key=tenant_key,
                open_id=open_id,
                first_seen_at=first_seen_at.isoformat(),
                last_seen_at=last_seen_at.isoformat(),
                attempt_count=int(attempt_count),
            )
            for tenant_key, open_id, first_seen_at, last_seen_at, attempt_count in rows
        ]


def _bounded_required(value: str, field: str, max_length: int) -> str:
    normalized = " ".join(str(value).split())
    if not normalized:
        raise ValueError(f"{field} is required")
    if len(normalized) > max_length:
        raise ValueError(f"{field} is too long")
    return normalized
