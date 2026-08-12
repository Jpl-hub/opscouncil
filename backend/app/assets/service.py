from __future__ import annotations

from datetime import datetime, timezone
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import ServiceExpectation, utcnow


ACTIVE = "ACTIVE"
RETIRED = "RETIRED"
EXPECTED_ACTIVE_STATES = frozenset({"active", "inactive"})
CRITICALITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
ENVIRONMENTS = frozenset({"PRODUCTION", "STAGING", "TEST", "DEVELOPMENT"})
LISTENER_PROTOCOLS = frozenset({"tcp", "udp"})
LISTENER_SCOPES = frozenset(
    {"loopback", "link_local", "private", "public", "wildcard"}
)
_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+\.service$")
_HOST_RE = re.compile(r"^(?:\*|[A-Za-z0-9_.:-]+)$")


class ServiceExpectationService:
    """Maintain immutable, versioned service expectations approved by operators."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def register(
        self,
        *,
        host_key: str,
        unit_name: str,
        expected_active_state: str,
        service_owner: str,
        criticality: str,
        environment: str,
        listener_expectations: list[dict[str, object]] | None = None,
        rationale: str,
        source_ref: str,
        approved_by: str,
        effective_from: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> ServiceExpectation:
        normalized_host = _normalize_host(host_key)
        normalized_unit = _normalize_unit(unit_name)
        normalized_state = expected_active_state.strip().lower()
        normalized_criticality = criticality.strip().upper()
        normalized_environment = environment.strip().upper()
        if normalized_state not in EXPECTED_ACTIVE_STATES:
            raise ValueError(f"unsupported expected service state: {expected_active_state}")
        if normalized_criticality not in CRITICALITIES:
            raise ValueError(f"unsupported service criticality: {criticality}")
        if normalized_environment not in ENVIRONMENTS:
            raise ValueError(f"unsupported service environment: {environment}")
        normalized_listeners = _normalize_listener_expectations(
            listener_expectations or []
        )
        if normalized_state == "inactive" and normalized_listeners:
            raise ValueError(
                "an inactive service expectation cannot require network listeners"
            )

        owner = _required_text(service_owner, "service owner", max_length=256)
        reason = _required_text(rationale, "expectation rationale", max_length=2000)
        source = _required_text(source_ref, "expectation source", max_length=1000)
        approver = _required_text(approved_by, "approver", max_length=128)
        starts_at = _normalize_datetime(effective_from or utcnow())
        ends_at = _normalize_datetime(expires_at) if expires_at is not None else None
        if ends_at is not None and ends_at <= starts_at:
            raise ValueError("expectation expiry must be later than its effective time")

        latest = self._latest_exact(normalized_host, normalized_unit)
        record = ServiceExpectation(
            host_key=normalized_host,
            unit_name=normalized_unit,
            version=(latest.version + 1) if latest is not None else 1,
            record_status=ACTIVE,
            expected_active_state=normalized_state,
            service_owner=owner,
            criticality=normalized_criticality,
            environment=normalized_environment,
            listener_expectations_json=normalized_listeners,
            rationale=reason,
            source_ref=source,
            approved_by=approver,
            effective_from=starts_at,
            expires_at=ends_at,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def retire(
        self,
        *,
        host_key: str,
        unit_name: str,
        reason: str,
        source_ref: str,
        approved_by: str,
    ) -> ServiceExpectation:
        normalized_host = _normalize_host(host_key)
        normalized_unit = _normalize_unit(unit_name)
        latest = self._latest_exact(normalized_host, normalized_unit)
        if latest is None or latest.record_status == RETIRED:
            raise LookupError(f"active service expectation not found: {normalized_unit}")

        record = ServiceExpectation(
            host_key=normalized_host,
            unit_name=normalized_unit,
            version=latest.version + 1,
            record_status=RETIRED,
            expected_active_state=latest.expected_active_state,
            service_owner=latest.service_owner,
            criticality=latest.criticality,
            environment=latest.environment,
            listener_expectations_json=list(
                latest.listener_expectations_json or []
            ),
            rationale=_required_text(reason, "retirement reason", max_length=2000),
            source_ref=_required_text(source_ref, "retirement source", max_length=1000),
            approved_by=_required_text(approved_by, "approver", max_length=128),
            effective_from=utcnow(),
            expires_at=None,
        )
        self.session.add(record)
        self.session.flush()
        return record

    def resolve(
        self,
        *,
        host_key: str,
        unit_name: str,
        at: datetime | None = None,
    ) -> ServiceExpectation | None:
        normalized_host = _normalize_host(host_key)
        normalized_unit = _normalize_unit(unit_name)
        exact = self._latest_exact(normalized_host, normalized_unit)
        selected = exact or self._latest_exact("*", normalized_unit)
        if selected is None or not expectation_is_effective(selected, at=at):
            return None
        return selected

    def list_current(
        self,
        *,
        host_key: str | None = None,
        include_retired: bool = False,
        limit: int = 100,
    ) -> list[ServiceExpectation]:
        bounded_limit = min(max(limit, 1), 500)
        if host_key is None:
            rows = list(
                self.session.scalars(
                    select(ServiceExpectation).order_by(
                        ServiceExpectation.host_key.asc(),
                        ServiceExpectation.unit_name.asc(),
                        ServiceExpectation.version.desc(),
                    )
                )
            )
            latest: dict[tuple[str, str], ServiceExpectation] = {}
            for row in rows:
                latest.setdefault((row.host_key, row.unit_name), row)
            selected = list(latest.values())
        else:
            normalized_host = _normalize_host(host_key)
            rows = list(
                self.session.scalars(
                    select(ServiceExpectation)
                    .where(ServiceExpectation.host_key.in_((normalized_host, "*")))
                    .order_by(
                        ServiceExpectation.host_key.asc(),
                        ServiceExpectation.unit_name.asc(),
                        ServiceExpectation.version.desc(),
                    )
                )
            )
            exact: dict[str, ServiceExpectation] = {}
            wildcard: dict[str, ServiceExpectation] = {}
            for row in rows:
                target = exact if row.host_key == normalized_host else wildcard
                target.setdefault(row.unit_name, row)
            selected = [exact.get(unit_name, row) for unit_name, row in wildcard.items()]
            selected.extend(row for unit_name, row in exact.items() if unit_name not in wildcard)

        selected.sort(key=lambda item: (item.unit_name, item.host_key))
        if not include_retired:
            selected = [item for item in selected if expectation_is_effective(item)]
        return selected[:bounded_limit]

    def history(self, *, host_key: str, unit_name: str, limit: int = 50) -> list[ServiceExpectation]:
        normalized_host = _normalize_host(host_key)
        normalized_unit = _normalize_unit(unit_name)
        return list(
            self.session.scalars(
                select(ServiceExpectation)
                .where(
                    ServiceExpectation.host_key == normalized_host,
                    ServiceExpectation.unit_name == normalized_unit,
                )
                .order_by(ServiceExpectation.version.desc())
                .limit(min(max(limit, 1), 200))
            )
        )

    def _latest_exact(self, host_key: str, unit_name: str) -> ServiceExpectation | None:
        return self.session.execute(
            select(ServiceExpectation)
            .where(
                ServiceExpectation.host_key == host_key,
                ServiceExpectation.unit_name == unit_name,
            )
            .order_by(ServiceExpectation.version.desc())
            .limit(1)
        ).scalar_one_or_none()


def expectation_is_effective(
    record: ServiceExpectation,
    *,
    at: datetime | None = None,
) -> bool:
    now = _normalize_datetime(at or utcnow())
    starts_at = _normalize_datetime(record.effective_from)
    expires_at = _normalize_datetime(record.expires_at) if record.expires_at is not None else None
    return (
        record.record_status == ACTIVE
        and starts_at <= now
        and (expires_at is None or expires_at > now)
    )


def _normalize_unit(value: str) -> str:
    normalized = value.strip()
    if not _UNIT_RE.fullmatch(normalized):
        raise ValueError("service unit must be a complete systemd .service name")
    return normalized


def _normalize_host(value: str) -> str:
    normalized = value.strip()
    if not _HOST_RE.fullmatch(normalized):
        raise ValueError("host key contains unsupported characters")
    return normalized


def _normalize_listener_expectations(
    values: list[dict[str, object]],
) -> list[dict[str, object]]:
    if len(values) > 20:
        raise ValueError("listener expectations must contain at most 20 items")
    normalized: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()
    for raw in values:
        if not isinstance(raw, dict):
            raise ValueError("listener expectation must be an object")
        protocol = str(raw.get("protocol") or "").strip().lower()
        if protocol not in LISTENER_PROTOCOLS:
            raise ValueError(f"unsupported listener protocol: {protocol or '-'}")
        port_value = raw.get("port")
        if isinstance(port_value, bool):
            raise ValueError("listener port must be an integer")
        try:
            port = int(port_value)
        except (TypeError, ValueError) as exc:
            raise ValueError("listener port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"listener port is out of range: {port}")
        allowed_scope = str(raw.get("allowed_scope") or "").strip().lower()
        if allowed_scope not in LISTENER_SCOPES:
            raise ValueError(
                f"unsupported listener exposure scope: {allowed_scope or '-'}"
            )
        key = (protocol, port)
        if key in seen:
            raise ValueError(
                f"duplicate listener expectation: {protocol}/{port}"
            )
        seen.add(key)
        normalized.append(
            {
                "protocol": protocol,
                "port": port,
                "allowed_scope": allowed_scope,
                "required": bool(raw.get("required", True)),
            }
        )
    return sorted(
        normalized,
        key=lambda item: (str(item["protocol"]), int(item["port"])),
    )


def _required_text(value: str, label: str, *, max_length: int) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} is required")
    if len(normalized) > max_length:
        raise ValueError(f"{label} exceeds {max_length} characters")
    return normalized


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
