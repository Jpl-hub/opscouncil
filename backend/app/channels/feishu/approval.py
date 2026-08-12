from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.service import stable_hash
from backend.app.channels.feishu.identity import (
    ExternalIdentityError,
    OperatorIdentityService,
)
from backend.app.models.entities import (
    ActionProposal,
    ApprovalDecisionJob,
    ApprovalDecisionToken,
    ChannelInboundEvent,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    utcnow,
)
from backend.app.safety.safety_case import action_fingerprint


APPROVER_ROLES = frozenset({"APPROVER", "ADMIN"})


@dataclass(frozen=True)
class IssuedDecisionTokens:
    approve_token: str
    reject_token: str
    expires_at: datetime


@dataclass(frozen=True)
class DecisionAcceptance:
    accepted: bool
    duplicate: bool
    decision: str | None
    job_id: int | None
    reason_code: str | None


class ApprovalDecisionService:
    def __init__(
        self,
        session: Session,
        *,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.session = session
        self.identities = OperatorIdentityService(session)
        self.token_factory = token_factory or (lambda: secrets.token_urlsafe(32))

    def issue_for_delivery(
        self,
        outbox_id: int,
        *,
        now: datetime | None = None,
        ttl_seconds: int = 300,
    ) -> IssuedDecisionTokens:
        issued_at = now or utcnow()
        outbox = self.session.scalar(
            select(NotificationOutbox)
            .where(NotificationOutbox.id == outbox_id)
            .with_for_update()
        )
        if outbox is None:
            raise LookupError("notification outbox item not found")
        if outbox.status != "SENDING":
            raise ValueError("approval tokens require a leased sending item")
        if outbox.kind not in {"APPROVAL_REQUEST", "ROLLBACK"}:
            raise ValueError("outbox item is not an approval delivery")
        if outbox.proposal_id is None or outbox.target_operator_id is None:
            raise ValueError("approval delivery is missing its proposal or operator binding")
        proposal = self.session.get(ActionProposal, outbox.proposal_id)
        operator = self.session.get(Operator, outbox.target_operator_id)
        if proposal is None or proposal.status != "PENDING_APPROVAL":
            raise ValueError("proposal is no longer pending approval")
        if operator is None or operator.status != "ACTIVE" or operator.role not in APPROVER_ROLES:
            raise ValueError("target operator is not an active approver")
        identity = self.session.scalar(
            select(OperatorExternalIdentity).where(
                OperatorExternalIdentity.operator_id == operator.id,
                OperatorExternalIdentity.provider == "FEISHU",
                OperatorExternalIdentity.status == "ACTIVE",
                OperatorExternalIdentity.external_user_id == outbox.recipient_id,
            )
        )
        if identity is None:
            raise ValueError("approval recipient is not an active mapped identity")

        for token in self.session.scalars(
            select(ApprovalDecisionToken)
            .where(
                ApprovalDecisionToken.proposal_id == proposal.id,
                ApprovalDecisionToken.operator_id == operator.id,
                ApprovalDecisionToken.status == "ACTIVE",
            )
            .with_for_update()
        ):
            token.status = "REVOKED"

        expires_at = issued_at + timedelta(seconds=min(max(ttl_seconds, 30), 900))
        raw_tokens: dict[str, str] = {}
        reserved_hashes: set[str] = set()
        fingerprint = action_fingerprint(proposal)
        for decision in ("APPROVE", "REJECT"):
            raw = self._new_token(reserved_hashes)
            reserved_hashes.add(_token_hash(raw))
            raw_tokens[decision] = raw
            self.session.add(
                ApprovalDecisionToken(
                    token_hash=_token_hash(raw),
                    proposal_id=proposal.id,
                    operator_id=operator.id,
                    decision=decision,
                    action_fingerprint=fingerprint,
                    status="ACTIVE",
                    expires_at=expires_at,
                )
            )
        self.session.flush()
        return IssuedDecisionTokens(
            approve_token=raw_tokens["APPROVE"],
            reject_token=raw_tokens["REJECT"],
            expires_at=expires_at,
        )

    def consume(
        self,
        *,
        external_event_id: str,
        tenant_key: str,
        open_id: str,
        token: str,
        now: datetime | None = None,
    ) -> DecisionAcceptance:
        consumed_at = now or utcnow()
        event_key = _bounded_required(external_event_id, "external_event_id", 256)
        tenant = _bounded_required(tenant_key, "tenant_key", 128)
        actor_open_id = _bounded_required(open_id, "open_id", 128)
        token_hash = _token_hash(_bounded_required(token, "token", 512))
        payload_hash = stable_hash(
            {
                "external_event_id": event_key,
                "tenant_key": tenant,
                "open_id": actor_open_id,
                "token_hash": token_hash,
            }
        )
        existing_event = self.session.scalar(
            select(ChannelInboundEvent).where(
                ChannelInboundEvent.channel == "FEISHU",
                ChannelInboundEvent.external_event_id == event_key,
            )
        )
        if existing_event is not None:
            if existing_event.payload_hash != payload_hash:
                return DecisionAcceptance(False, True, None, None, "EVENT_PAYLOAD_MISMATCH")
            existing_token = self.session.scalar(
                select(ApprovalDecisionToken).where(
                    ApprovalDecisionToken.inbound_event_id == existing_event.id
                )
            )
            existing_job = (
                self.session.scalar(
                    select(ApprovalDecisionJob).where(
                        ApprovalDecisionJob.token_id == existing_token.id
                    )
                )
                if existing_token is not None
                else None
            )
            return DecisionAcceptance(
                accepted=existing_event.status == "ACCEPTED",
                duplicate=True,
                decision=existing_token.decision if existing_token is not None else None,
                job_id=existing_job.id if existing_job is not None else None,
                reason_code=existing_event.reason_code,
            )

        try:
            operator = self.identities.resolve_feishu_identity(
                tenant,
                actor_open_id,
                allowed_roles=APPROVER_ROLES,
            )
        except ExternalIdentityError as exc:
            self._record_event(
                event_key,
                tenant,
                actor_open_id,
                payload_hash,
                status="REJECTED",
                reason_code=exc.code,
            )
            return DecisionAcceptance(False, False, None, None, exc.code)

        decision_token = self.session.scalar(
            select(ApprovalDecisionToken)
            .where(ApprovalDecisionToken.token_hash == token_hash)
            .with_for_update()
        )
        if decision_token is None:
            return self._reject(
                event_key,
                tenant,
                actor_open_id,
                payload_hash,
                operator_id=operator.id,
                reason_code="TOKEN_INVALID",
            )
        if decision_token.operator_id != operator.id:
            return self._reject(
                event_key,
                tenant,
                actor_open_id,
                payload_hash,
                operator_id=operator.id,
                task_id=_proposal_task_id(self.session, decision_token.proposal_id),
                reason_code="TOKEN_WRONG_OPERATOR",
            )
        if _as_utc(decision_token.expires_at) < _as_utc(consumed_at):
            decision_token.status = "EXPIRED"
            return self._reject(
                event_key,
                tenant,
                actor_open_id,
                payload_hash,
                operator_id=operator.id,
                task_id=_proposal_task_id(self.session, decision_token.proposal_id),
                reason_code="TOKEN_EXPIRED",
            )
        if decision_token.status != "ACTIVE":
            return self._reject(
                event_key,
                tenant,
                actor_open_id,
                payload_hash,
                operator_id=operator.id,
                task_id=_proposal_task_id(self.session, decision_token.proposal_id),
                reason_code=f"TOKEN_{decision_token.status}",
            )
        proposal = self.session.get(ActionProposal, decision_token.proposal_id)
        if proposal is None or proposal.status != "PENDING_APPROVAL":
            decision_token.status = "REVOKED"
            return self._reject(
                event_key,
                tenant,
                actor_open_id,
                payload_hash,
                operator_id=operator.id,
                task_id=proposal.task_id if proposal is not None else None,
                reason_code="PROPOSAL_NOT_PENDING",
            )
        if decision_token.action_fingerprint != action_fingerprint(proposal):
            decision_token.status = "REVOKED"
            return self._reject(
                event_key,
                tenant,
                actor_open_id,
                payload_hash,
                operator_id=operator.id,
                task_id=proposal.task_id,
                reason_code="PROPOSAL_CHANGED",
            )
        existing_job = self.session.scalar(
            select(ApprovalDecisionJob).where(
                ApprovalDecisionJob.proposal_id == proposal.id
            )
        )
        if existing_job is not None:
            decision_token.status = "REVOKED"
            return self._reject(
                event_key,
                tenant,
                actor_open_id,
                payload_hash,
                operator_id=operator.id,
                task_id=proposal.task_id,
                reason_code="DECISION_ALREADY_QUEUED",
            )

        event = self._record_event(
            event_key,
            tenant,
            actor_open_id,
            payload_hash,
            status="ACCEPTED",
            operator_id=operator.id,
            task_id=proposal.task_id,
        )
        decision_token.status = "CONSUMED"
        decision_token.consumed_at = consumed_at
        decision_token.inbound_event_id = event.id
        for sibling in self.session.scalars(
            select(ApprovalDecisionToken)
            .where(
                ApprovalDecisionToken.proposal_id == proposal.id,
                ApprovalDecisionToken.id != decision_token.id,
                ApprovalDecisionToken.status == "ACTIVE",
            )
            .with_for_update()
        ):
            sibling.status = "REVOKED"
        job = ApprovalDecisionJob(
            proposal_id=proposal.id,
            token_id=decision_token.id,
            operator_id=operator.id,
            decision=decision_token.decision,
            status="QUEUED",
            available_at=consumed_at,
        )
        self.session.add(job)
        self.session.flush()
        return DecisionAcceptance(True, False, decision_token.decision, job.id, None)

    def _reject(
        self,
        event_id: str,
        tenant_key: str,
        open_id: str,
        payload_hash: str,
        *,
        operator_id: int | None,
        reason_code: str,
        task_id: int | None = None,
    ) -> DecisionAcceptance:
        self._record_event(
            event_id,
            tenant_key,
            open_id,
            payload_hash,
            status="REJECTED",
            reason_code=reason_code,
            operator_id=operator_id,
            task_id=task_id,
        )
        return DecisionAcceptance(False, False, None, None, reason_code)

    def _record_event(
        self,
        event_id: str,
        tenant_key: str,
        open_id: str,
        payload_hash: str,
        *,
        status: str,
        reason_code: str | None = None,
        operator_id: int | None = None,
        task_id: int | None = None,
    ) -> ChannelInboundEvent:
        timestamp = utcnow()
        event = ChannelInboundEvent(
            channel="FEISHU",
            external_event_id=event_id,
            event_type="card.action.trigger",
            tenant_key=tenant_key,
            external_actor_id=open_id,
            payload_hash=payload_hash,
            status=status,
            reason_code=reason_code,
            operator_id=operator_id,
            task_id=task_id,
            created_at=timestamp,
            processed_at=timestamp,
        )
        self.session.add(event)
        self.session.flush()
        return event

    def _new_token(self, reserved_hashes: set[str]) -> str:
        for _ in range(8):
            token = str(self.token_factory())
            if len(token) < 32:
                raise ValueError("decision token source returned insufficient entropy")
            token_hash = _token_hash(token)
            if token_hash in reserved_hashes:
                continue
            existing = self.session.scalar(
                select(ApprovalDecisionToken.id).where(
                    ApprovalDecisionToken.token_hash == token_hash
                )
            )
            if existing is None:
                return token
        raise RuntimeError("decision token source repeatedly returned collisions")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bounded_required(value: str, field: str, max_chars: int) -> str:
    normalized = " ".join(str(value).split())
    if not normalized:
        raise ValueError(f"{field} is required")
    if len(normalized) > max_chars:
        raise ValueError(f"{field} is too long")
    return normalized


def _proposal_task_id(session: Session, proposal_id: int) -> int | None:
    proposal = session.get(ActionProposal, proposal_id)
    return proposal.task_id if proposal is not None else None


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
