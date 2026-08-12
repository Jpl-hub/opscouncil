from __future__ import annotations

from backend.app.core.pydantic_compat import BaseModel, Field


class FeishuMessageRequest(BaseModel):
    event_id: str = Field(min_length=1, max_length=256)
    tenant_key: str = Field(min_length=1, max_length=128)
    open_id: str = Field(min_length=1, max_length=128)
    chat_id: str = Field(min_length=1, max_length=256)
    message_id: str = Field(min_length=1, max_length=256)
    text: str = Field(max_length=4001)
    chat_type: str = Field(default="p2p", min_length=1, max_length=32)


class FeishuActionRequest(BaseModel):
    event_id: str = Field(min_length=1, max_length=256)
    tenant_key: str = Field(min_length=1, max_length=128)
    open_id: str = Field(min_length=1, max_length=128)
    token: str = Field(min_length=32, max_length=512)


class OutboxClaimRequest(BaseModel):
    worker_id: str = Field(min_length=1, max_length=128)
    lease_seconds: int = Field(default=30, ge=10, le=300)


class OutboxDeliveredRequest(BaseModel):
    worker_id: str = Field(min_length=1, max_length=128)
    provider_message_id: str | None = Field(default=None, max_length=256)
    provider_card_id: str | None = Field(default=None, max_length=256)
    duration_ms: int = Field(default=0, ge=0, le=300_000)


class OutboxFailedRequest(BaseModel):
    worker_id: str = Field(min_length=1, max_length=128)
    error_code: str = Field(min_length=1, max_length=64)
    error_message: str = Field(default="通道投递失败", max_length=2000)
    duration_ms: int = Field(default=0, ge=0, le=300_000)
    retryable: bool = True


class FeishuHeartbeatRequest(BaseModel):
    instance_id: str = Field(min_length=1, max_length=128)
    status: str = Field(pattern="^(CONNECTED|DEGRADED|STOPPED)$")
    detail_code: str | None = Field(default=None, max_length=64)


class OperatorCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=128)
    role: str = Field(default="OPERATOR", pattern="^(VIEWER|OPERATOR|APPROVER|ADMIN)$")


class FeishuIdentityCreateRequest(BaseModel):
    operator_id: int = Field(ge=1)
    tenant_key: str = Field(min_length=1, max_length=128)
    open_id: str = Field(min_length=1, max_length=128)


class IdentityStatusRequest(BaseModel):
    status: str = Field(pattern="^(ACTIVE|DISABLED)$")
