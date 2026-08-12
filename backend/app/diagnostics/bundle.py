from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.service import AuditService
from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    EvidenceItem,
    Hypothesis,
    HypothesisEvidence,
    Investigation,
    SafetyReview,
    Task,
    TaskEvent,
    ToolCall,
    utcnow,
)


BUNDLE_SCHEMA = "opscouncil.task-diagnostic-bundle.v1"
_MAX_TEXT_LENGTH = 4000
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "authorization",
    "credential",
    "密码",
    "密钥",
    "令牌",
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_API_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
_URL_CREDENTIAL_RE = re.compile(r"(://[^/\s:@]+:)[^@\s/]+(@)")
_ASSIGNED_SECRET_RE = re.compile(
    r"(?i)([\"']?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"authorization|credential|app[_\s-]?secret|client[_\s-]?secret|密码|密钥|令牌)"
    r"[\"']?\s*[:=：]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_RULE_FIELDS = (
    "id",
    "rule_id",
    "name",
    "label",
    "category",
    "risk_level",
    "action",
)
_SAFETY_SCOPE_FIELDS = (
    "resource_type",
    "paths",
    "units",
    "operation",
    "target_mode",
    "expected_sha256",
    "baseline_id",
    "baseline_check_id",
    "side_effects",
)


@dataclass(frozen=True)
class DiagnosticBundle:
    filename: str
    content: bytes
    sha256: str
    generated_at: str


class DiagnosticBundleService:
    """Builds a minimum-necessary diagnostic snapshot for one task."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def build(self, task_id: int) -> DiagnosticBundle:
        task = self.session.scalar(select(Task).where(Task.id == task_id))
        if task is None:
            raise LookupError("task not found")

        generated_at = _iso(utcnow())
        investigation = self.session.scalar(
            select(Investigation).where(Investigation.task_id == task.id)
        )
        tool_calls = list(
            self.session.scalars(
                select(ToolCall)
                .where(ToolCall.task_id == task.id)
                .order_by(ToolCall.id.asc())
            )
        )
        reviews = list(
            self.session.scalars(
                select(SafetyReview)
                .where(SafetyReview.task_id == task.id)
                .order_by(SafetyReview.id.asc())
            )
        )
        proposals = list(
            self.session.scalars(
                select(ActionProposal)
                .where(ActionProposal.task_id == task.id)
                .order_by(ActionProposal.id.asc())
            )
        )
        safety_cases = list(
            self.session.scalars(
                select(ActionSafetyCase)
                .where(ActionSafetyCase.task_id == task.id)
                .order_by(ActionSafetyCase.id.asc())
            )
        )
        events = list(
            self.session.scalars(
                select(TaskEvent)
                .where(TaskEvent.task_id == task.id)
                .order_by(TaskEvent.id.asc())
            )
        )

        evidence_items: list[EvidenceItem] = []
        hypotheses: list[Hypothesis] = []
        hypothesis_links: list[HypothesisEvidence] = []
        if investigation is not None:
            evidence_items = list(
                self.session.scalars(
                    select(EvidenceItem)
                    .where(EvidenceItem.investigation_id == investigation.id)
                    .order_by(EvidenceItem.id.asc())
                )
            )
            hypotheses = list(
                self.session.scalars(
                    select(Hypothesis)
                    .where(Hypothesis.investigation_id == investigation.id)
                    .order_by(Hypothesis.id.asc())
                )
            )
            hypothesis_ids = [item.id for item in hypotheses]
            if hypothesis_ids:
                hypothesis_links = list(
                    self.session.scalars(
                        select(HypothesisEvidence)
                        .where(HypothesisEvidence.hypothesis_id.in_(hypothesis_ids))
                        .order_by(
                            HypothesisEvidence.hypothesis_id.asc(),
                            HypothesisEvidence.evidence_item_id.asc(),
                        )
                    )
                )

        links_by_hypothesis: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for link in hypothesis_links:
            links_by_hypothesis[link.hypothesis_id].append(
                {
                    "evidence_item_id": link.evidence_item_id,
                    "relation": link.relation,
                    "rationale": _redact_text(link.rationale),
                }
            )

        audit_verification = AuditService(self.session).verify_trace(task.trace_id)
        payloads = {
            "task.json": {
                "schema": BUNDLE_SCHEMA,
                "id": task.id,
                "trace_id": task.trace_id,
                "request": _redact_text(task.user_input),
                "intent": task.intent,
                "status": task.status,
                "risk_level": task.risk_level,
                "summary": _redact_text(task.summary),
                "created_at": _iso(task.created_at),
                "updated_at": _iso(task.updated_at),
                "sealed_at": _iso(task.sealed_at),
                "investigation": _investigation_summary(investigation),
            },
            "evidence.json": {
                "schema": BUNDLE_SCHEMA,
                "items": [
                    {
                        "id": item.id,
                        "source_type": item.source_type,
                        "source_key": _redact_text(item.source_key),
                        "source_ref": _redact_text(item.source_ref),
                        "tool_call_id": item.tool_call_id,
                        "title": _redact_text(item.title),
                        "summary": _redact_text(item.summary),
                        "trust_level": item.trust_level,
                        "observed_at": _iso(item.observed_at),
                    }
                    for item in evidence_items
                ],
            },
            "hypotheses.json": {
                "schema": BUNDLE_SCHEMA,
                "items": [
                    {
                        "id": item.id,
                        "key": item.key,
                        "title": _redact_text(item.title),
                        "rationale": _redact_text(item.rationale),
                        "evidence_gap": _redact_text(item.evidence_gap),
                        "status": item.status,
                        "confidence_level": item.confidence_level,
                        "confidence_score": item.confidence_score,
                        "first_seen_iteration": item.first_seen_iteration,
                        "last_updated_iteration": item.last_updated_iteration,
                        "evidence_relations": links_by_hypothesis.get(item.id, []),
                    }
                    for item in hypotheses
                ],
            },
            "safety.json": {
                "schema": BUNDLE_SCHEMA,
                "reviews": [_review_summary(item) for item in reviews],
                "action_proposals": [_proposal_summary(item) for item in proposals],
                "action_safety_cases": [_safety_case_summary(item) for item in safety_cases],
            },
            "tool-calls.json": {
                "schema": BUNDLE_SCHEMA,
                "items": [_tool_call_summary(item) for item in tool_calls],
            },
            "audit.json": {
                "schema": BUNDLE_SCHEMA,
                "events": [
                    {
                        "id": item.id,
                        "stage": item.stage,
                        "event_type": item.event_type,
                        "message": _redact_text(item.message),
                        "created_at": _iso(item.created_at),
                    }
                    for item in events
                ],
                "verification": audit_verification,
            },
        }

        encoded_payloads = {
            name: _json_bytes(payload)
            for name, payload in payloads.items()
        }
        manifest = {
            "schema": BUNDLE_SCHEMA,
            "product": "OpsCouncil",
            "task_id": task.id,
            "trace_id": task.trace_id,
            "generated_at": generated_at,
            "audit_head_hash": audit_verification["head_hash"],
            "privacy": {
                "scope": "single_task",
                "redaction": "enabled",
                "excluded": [
                    "tool_inputs",
                    "tool_raw_outputs",
                    "event_payloads",
                    "configuration_content",
                    "raw_log_content",
                ],
            },
            "files": [
                {
                    "name": name,
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
                for name, content in encoded_payloads.items()
            ],
        }

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in encoded_payloads.items():
                archive.writestr(name, content)
            archive.writestr("manifest.json", _json_bytes(manifest))
        content = buffer.getvalue()
        filename = f"opscouncil-task-{task.id}-diagnostic.zip"
        return DiagnosticBundle(
            filename=filename,
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            generated_at=generated_at,
        )


def _investigation_summary(investigation: Investigation | None) -> dict[str, Any] | None:
    if investigation is None:
        return None
    return {
        "id": investigation.id,
        "status": investigation.status,
        "current_iteration": investigation.current_iteration,
        "max_iterations": investigation.max_iterations,
        "max_tool_calls": investigation.max_tool_calls,
        "max_elapsed_ms": investigation.max_elapsed_ms,
        "stop_reason": _redact_text(investigation.stop_reason),
        "started_at": _iso(investigation.started_at),
        "completed_at": _iso(investigation.completed_at),
    }


def _tool_call_summary(call: ToolCall) -> dict[str, Any]:
    output = call.output_json if isinstance(call.output_json, Mapping) else {}
    return {
        "id": call.id,
        "tool_name": call.tool_name,
        "tool_version": call.tool_version,
        "risk_level": call.risk_level,
        "status": call.status,
        "duration_ms": call.duration_ms,
        "observation_count": _list_count(output.get("observations")),
        "evidence_refs": _redact_value(_string_list(output.get("evidence_refs"))),
        "warning_count": _list_count(output.get("warnings")),
        "started_at": _iso(call.started_at),
        "ended_at": _iso(call.ended_at),
    }


def _review_summary(review: SafetyReview) -> dict[str, Any]:
    rules = review.matched_rules_json if isinstance(review.matched_rules_json, list) else []
    return {
        "id": review.id,
        "review_type": review.review_type,
        "risk_level": review.risk_level,
        "decision": review.decision,
        "matched_rules": [_rule_summary(item) for item in rules],
        "reason": _redact_text(review.reason),
        "created_at": _iso(review.created_at),
    }


def _rule_summary(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _redact_value({key: value[key] for key in _RULE_FIELDS if key in value})
    return _redact_text(str(value))


def _proposal_summary(proposal: ActionProposal) -> dict[str, Any]:
    return {
        "id": proposal.id,
        "tool_name": proposal.tool_name,
        "risk_level": proposal.risk_level,
        "status": proposal.status,
        "reason": _redact_text(proposal.reason),
        "created_at": _iso(proposal.created_at),
        "updated_at": _iso(proposal.updated_at),
    }


def _safety_case_summary(safety_case: ActionSafetyCase) -> dict[str, Any]:
    scope = safety_case.scope_json if isinstance(safety_case.scope_json, Mapping) else {}
    rollback = (
        safety_case.rollback_strategy_json
        if isinstance(safety_case.rollback_strategy_json, Mapping)
        else {}
    )
    return {
        "id": safety_case.id,
        "proposal_id": safety_case.proposal_id,
        "tool_name": safety_case.tool_name,
        "risk_level": safety_case.risk_level,
        "policy_version": safety_case.policy_version,
        "status": safety_case.status,
        "action_fingerprint": safety_case.action_fingerprint,
        "scope": _redact_value(
            {key: scope[key] for key in _SAFETY_SCOPE_FIELDS if key in scope}
        ),
        "preconditions": _condition_summaries(safety_case.preconditions_json),
        "postconditions": _condition_summaries(safety_case.postconditions_json),
        "verifier_tool": safety_case.verifier_tool,
        "rollback_strategy": _redact_value(
            {
                key: rollback[key]
                for key in ("mode", "tool_name", "summary")
                if key in rollback
            }
        ),
        "outcome": _safety_case_outcome(safety_case.result_json),
        "evidence_refs": _redact_value(_string_list(safety_case.evidence_refs_json)),
        "case_hash": safety_case.case_hash,
        "approved_by": _redact_text(safety_case.approved_by),
        "approved_at": _iso(safety_case.approved_at),
        "created_at": _iso(safety_case.created_at),
        "updated_at": _iso(safety_case.updated_at),
    }


def _condition_summaries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    summaries: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        summaries.append(
            _redact_value(
                {key: item[key] for key in ("code", "statement") if key in item}
            )
        )
    return summaries


def _safety_case_outcome(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    outcome: dict[str, Any] = {}
    allowed_fields = {
        "precondition": ("valid", "reason"),
        "execution": ("outcome", "succeeded", "status", "reason"),
        "postcondition": ("valid", "reason"),
        "blocked": ("stage", "reason"),
        "rejection": ("operator", "comment"),
        "revocation": ("reason",),
    }
    for section, fields in allowed_fields.items():
        section_value = value.get(section)
        if isinstance(section_value, Mapping):
            outcome[section] = {
                key: section_value[key]
                for key in fields
                if key in section_value
            }
    return _redact_value(outcome)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))]


def _list_count(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _redact_value(value: Any, *, key: str | None = None) -> Any:
    if key is not None and _is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): _redact_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact_value(item) for item in value]
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_").replace(" ", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _API_KEY_RE.sub("sk-[REDACTED]", text)
    text = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]\2", text)
    text = _ASSIGNED_SECRET_RE.sub(r"\1[REDACTED]", text)
    if len(text) > _MAX_TEXT_LENGTH:
        return f"{text[:_MAX_TEXT_LENGTH]}...[TRUNCATED]"
    return text


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
