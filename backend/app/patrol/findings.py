from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import Finding, Incident, PatrolPolicy, PatrolRun, utcnow


ACTIVE_STATUSES = {"warn": "WARN", "critical": "CRITICAL"}
RESOLVABLE_FINDING_STATUSES = {"OPEN", "ACKNOWLEDGED"}
SEVERITY_ORDER = {"WARN": 1, "CRITICAL": 2}


class FindingService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def apply_run(
        self,
        policy: PatrolPolicy,
        run: PatrolRun,
        report: dict[str, Any],
        *,
        now: datetime | None = None,
    ) -> list[Finding]:
        observed_at = now or utcnow()
        selected_keys = {
            str(item)
            for item in (policy.signal_keys_json if isinstance(policy.signal_keys_json, list) else [])
            if isinstance(item, str) and item.strip()
        }
        raw_signals = report.get("signals") if isinstance(report, dict) else None
        signals = raw_signals if isinstance(raw_signals, list) else []
        active_findings: list[Finding] = []
        healthy_keys: set[str] = set()
        active_keys: set[str] = set()

        for raw_signal in signals:
            signal = _validated_signal(raw_signal, selected_keys)
            if signal is None:
                continue
            signal_key = signal["key"]
            status = signal["status"]
            if status == "ok":
                healthy_keys.add(signal_key)
                continue
            severity = ACTIVE_STATUSES.get(status)
            if severity is None:
                continue
            active_keys.add(signal_key)
            active_findings.append(
                self._upsert_active_finding(
                    policy,
                    run,
                    signal,
                    severity,
                    observed_at,
                )
            )

        for signal_key in healthy_keys - active_keys:
            self._observe_healthy_signal(policy.id, run.host_key, signal_key, observed_at)
        self.session.flush()
        return active_findings

    def _upsert_active_finding(
        self,
        policy: PatrolPolicy,
        run: PatrolRun,
        signal: dict[str, Any],
        severity: str,
        observed_at: datetime,
    ) -> Finding:
        fingerprint = _fingerprint(
            policy.id,
            run.host_key,
            signal["key"],
            observed_at,
            _dedupe_window_seconds(policy),
        )
        finding = self.session.scalar(
            select(Finding).where(Finding.fingerprint == fingerprint).with_for_update()
        )
        incident = self._open_incident(policy, run.host_key, signal, severity, observed_at)
        self._supersede_previous_windows(
            policy_id=policy.id,
            host_key=run.host_key,
            signal_key=signal["key"],
            current_fingerprint=fingerprint,
            observed_at=observed_at,
        )
        if finding is None:
            finding = Finding(
                policy_id=policy.id,
                patrol_run_id=run.id,
                incident_id=incident.id,
                host_key=run.host_key,
                signal_key=signal["key"],
                fingerprint=fingerprint,
                severity=severity,
                status="OPEN",
                title=signal["title"],
                summary=signal["detail"],
                metric_json=_metric_payload(signal),
                evidence_refs_json=_evidence_refs(signal),
                first_observed_at=observed_at,
                last_observed_at=observed_at,
                occurrence_count=1,
            )
            self.session.add(finding)
            self.session.flush()
            return finding

        finding.patrol_run_id = run.id
        finding.incident_id = incident.id
        finding.severity = _max_severity(finding.severity, severity)
        finding.status = "OPEN" if finding.status == "RESOLVED" else finding.status
        finding.title = signal["title"]
        finding.summary = signal["detail"]
        finding.metric_json = _metric_payload(signal)
        finding.evidence_refs_json = _evidence_refs(signal)
        finding.last_observed_at = observed_at
        finding.occurrence_count += 1
        finding.resolved_at = None
        self.session.flush()
        return finding

    def _supersede_previous_windows(
        self,
        *,
        policy_id: int,
        host_key: str,
        signal_key: str,
        current_fingerprint: str,
        observed_at: datetime,
    ) -> None:
        previous = list(
            self.session.scalars(
                select(Finding)
                .where(
                    Finding.policy_id == policy_id,
                    Finding.host_key == host_key,
                    Finding.signal_key == signal_key,
                    Finding.status.in_(RESOLVABLE_FINDING_STATUSES),
                    Finding.fingerprint != current_fingerprint,
                )
                .with_for_update()
            )
        )
        for finding in previous:
            finding.status = "RESOLVED"
            finding.resolved_at = observed_at

    def _open_incident(
        self,
        policy: PatrolPolicy,
        host_key: str,
        signal: dict[str, Any],
        severity: str,
        observed_at: datetime,
    ) -> Incident:
        dedupe_key = f"{host_key}:{signal['key']}"
        incident = self.session.scalar(
            select(Incident).where(Incident.dedupe_key == dedupe_key).with_for_update()
        )
        if incident is None:
            incident = Incident(
                host_key=host_key,
                signal_key=signal["key"],
                dedupe_key=dedupe_key,
                status="OPEN",
                severity=severity,
                title=signal["title"],
                summary=signal["detail"],
                healthy_streak=0,
                recovery_target=_recovery_target(policy),
                opened_at=observed_at,
                updated_at=observed_at,
            )
            self.session.add(incident)
            self.session.flush()
            return incident

        incident.severity = _max_severity(incident.severity, severity)
        incident.title = signal["title"]
        incident.summary = signal["detail"]
        incident.healthy_streak = 0
        incident.recovery_target = _recovery_target(policy)
        incident.last_healthy_at = None
        incident.updated_at = observed_at
        self.session.flush()
        return incident

    def _observe_healthy_signal(
        self,
        policy_id: int,
        host_key: str,
        signal_key: str,
        observed_at: datetime,
    ) -> None:
        findings = list(
            self.session.scalars(
                select(Finding)
                .where(
                    Finding.policy_id == policy_id,
                    Finding.host_key == host_key,
                    Finding.signal_key == signal_key,
                    Finding.status.in_(RESOLVABLE_FINDING_STATUSES),
                )
                .with_for_update()
            )
        )
        incident_ids = {
            finding.incident_id for finding in findings if finding.incident_id is not None
        }

        for incident_id in incident_ids:
            incident = self.session.execute(
                select(Incident).where(Incident.id == incident_id).with_for_update()
            ).scalar_one_or_none()
            if incident is None or incident.status in {"RESOLVED", "CLOSED"}:
                continue
            incident.healthy_streak += 1
            incident.last_healthy_at = observed_at
            incident.updated_at = observed_at
            if incident.healthy_streak < incident.recovery_target:
                continue
            for finding in findings:
                if finding.incident_id != incident_id:
                    continue
                finding.status = "RESOLVED"
                finding.resolved_at = observed_at
                finding.last_observed_at = observed_at
            self.session.flush()
            remaining = self.session.scalar(
                select(Finding.id)
                .where(
                    Finding.incident_id == incident_id,
                    Finding.status.in_(RESOLVABLE_FINDING_STATUSES),
                )
                .limit(1)
            )
            if remaining is not None:
                continue
            incident.status = "RESOLVED"
            incident.dedupe_key = None
            incident.updated_at = observed_at
            incident.closed_at = observed_at


def _validated_signal(raw: Any, selected_keys: set[str]) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    key = raw.get("key")
    title = raw.get("title")
    detail = raw.get("detail")
    status = raw.get("status")
    if not all(isinstance(value, str) and value.strip() for value in (key, title, detail, status)):
        return None
    normalized_key = str(key).strip()
    if normalized_key not in selected_keys:
        return None
    return {
        **raw,
        "key": normalized_key[:128],
        "title": str(title).strip()[:256],
        "detail": str(detail).strip()[:2000],
        "status": str(status).strip().lower(),
    }


def _dedupe_window_seconds(policy: PatrolPolicy) -> int:
    thresholds = policy.thresholds_json if isinstance(policy.thresholds_json, dict) else {}
    raw_value = thresholds.get("dedupe_window_seconds", max(policy.interval_seconds, 900))
    if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
        return max(policy.interval_seconds, 900)
    return min(max(int(raw_value), 60), 86400)


def _recovery_target(policy: PatrolPolicy) -> int:
    thresholds = policy.thresholds_json if isinstance(policy.thresholds_json, dict) else {}
    raw_value = thresholds.get("resolve_after_healthy_runs", 2)
    if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
        return 2
    return min(max(int(raw_value), 1), 12)


def _fingerprint(
    policy_id: int,
    host_key: str,
    signal_key: str,
    observed_at: datetime,
    window_seconds: int,
) -> str:
    instant = observed_at if observed_at.tzinfo is not None else observed_at.replace(tzinfo=timezone.utc)
    window_start = int(instant.timestamp()) // window_seconds * window_seconds
    raw = f"{policy_id}:{host_key}:{signal_key}:{window_start}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _max_severity(current: str, candidate: str) -> str:
    return candidate if SEVERITY_ORDER.get(candidate, 0) > SEVERITY_ORDER.get(current, 0) else current


def _metric_payload(signal: dict[str, Any]) -> dict[str, Any]:
    metric = signal.get("metric")
    if isinstance(metric, str):
        metric = metric[:256]
    elif not isinstance(metric, (int, float, bool)) and metric is not None:
        metric = str(metric)[:256]
    return {"metric": metric, "status": signal["status"]}


def _evidence_refs(signal: dict[str, Any]) -> list[str]:
    refs = signal.get("evidence_refs")
    if not isinstance(refs, list):
        return []
    return [item.strip()[:512] for item in refs[:16] if isinstance(item, str) and item.strip()]
