from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
import json
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.audit.service import AuditService
from backend.app.channels.feishu.outbox import NotificationOutboxService
from backend.app.collaboration.service import IncidentCollaborationService
from backend.app.core.config import settings
from backend.app.mcp.registry import ToolRegistry
from backend.app.models.entities import Finding, Incident, PatrolPolicy, PatrolRun, utcnow
from backend.app.patrol.findings import FindingService
from backend.app.patrol.collector import PatrolCollector
from backend.app.runtime.intake import TaskIntakeService


DEFAULT_POLICY_NAME = "核心主机巡检"
DEFAULT_SIGNAL_KEYS = [
    "disk_pressure",
    "inode_pressure",
    "memory_pressure",
    "failed_service",
    "process_pressure",
    "network_exposure",
    "config_drift",
    "service_expectation",
    "time_sync",
    "mcp_health",
    "baseline_regression",
    "capacity_forecast",
]
MAX_SNAPSHOT_BYTES = 1024 * 1024
SIGNAL_INVESTIGATION_SCOPES = {
    "disk_pressure": "重点核验磁盘容量、大文件、日志占用与 inode 使用情况。",
    "inode_pressure": "重点核验 inode 使用率、小文件聚集目录与文件增长来源。",
    "memory_pressure": "重点核验内存、交换区、PSI 与高占用进程。",
    "failed_service": "重点核验 systemd 失败单元、服务状态与关联日志元数据。",
    "process_pressure": "重点核验 CPU、内存、PSI、进程资源上限与服务归属。",
    "network_exposure": "重点核验监听地址、端口、进程归属与暴露范围。",
    "config_drift": "重点核验关键配置的权限、时间戳与哈希基线。",
    "service_expectation": "重点核验服务实际状态、登记期望、责任归属与近期 systemd 日志。",
    "time_sync": "重点核验时钟同步服务、同步状态与时间偏差。",
    "mcp_health": "重点核验 MCP 感知工具状态、异常分类与证据完整性。",
    "baseline_regression": "该信号来自系统资源动态基线，重点核验 CPU、内存、负载、PSI 与高占用进程。",
    "capacity_forecast": "该信号属于容量时序预警，重点核验磁盘增长来源、日志写入速率和可安全回收对象。",
}


class PostureReader(Protocol):
    def read(self) -> dict[str, Any]: ...


PostureFactory = Callable[[ToolRegistry, Session], PostureReader]


class PatrolService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        registry: ToolRegistry,
        *,
        posture_factory: PostureFactory | None = None,
        seed_default_policy: bool = True,
        default_interval_seconds: int = 300,
    ) -> None:
        self.session_factory = session_factory
        self.registry = registry
        self.posture_factory = posture_factory or (
            lambda target_registry, session: PatrolCollector(target_registry, session)
        )
        self.seed_default_policy = seed_default_policy
        self.default_interval_seconds = max(int(default_interval_seconds), 60)

    def ensure_default_policy(self, *, now: datetime | None = None) -> PatrolPolicy:
        created_at = now or utcnow()
        with self.session_factory() as session:
            policy = session.scalar(
                select(PatrolPolicy).where(PatrolPolicy.name == DEFAULT_POLICY_NAME)
            )
            if policy is None:
                policy = PatrolPolicy(
                    name=DEFAULT_POLICY_NAME,
                    enabled=True,
                    interval_seconds=self.default_interval_seconds,
                    signal_keys_json=list(DEFAULT_SIGNAL_KEYS),
                    thresholds_json={
                        "dedupe_window_seconds": 900,
                        "resolve_after_healthy_runs": 2,
                    },
                    next_run_at=created_at,
                    created_at=created_at,
                    updated_at=created_at,
                )
                session.add(policy)
                session.commit()
            else:
                signal_keys = [
                    str(item)
                    for item in (policy.signal_keys_json if isinstance(policy.signal_keys_json, list) else [])
                    if isinstance(item, str) and item.strip()
                ]
                missing_keys = [key for key in DEFAULT_SIGNAL_KEYS if key not in signal_keys]
                if missing_keys:
                    policy.signal_keys_json = [*signal_keys, *missing_keys]
                    policy.updated_at = created_at
                    session.commit()
            return policy

    def run_due_once(
        self,
        worker_id: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        claimed_at = now or utcnow()
        if self.seed_default_policy:
            self.ensure_default_policy(now=claimed_at)
        run_id = self._claim_due_policy(worker_id, claimed_at)
        if run_id is None:
            return False
        self._execute_run(run_id, completed_at=claimed_at)
        return True

    def run_policy(self, policy_id: int, *, now: datetime | None = None) -> PatrolRun:
        claimed_at = now or utcnow()
        run_id = self._claim_policy(policy_id, "manual", claimed_at)
        if run_id is None:
            raise LookupError("patrol policy not found")
        self._execute_run(run_id, completed_at=claimed_at)
        with self.session_factory() as session:
            run = session.get(PatrolRun, run_id)
            if run is None:
                raise LookupError("patrol run not found after execution")
            session.expunge(run)
            return run

    def _claim_due_policy(self, worker_id: str, claimed_at: datetime) -> int | None:
        with self.session_factory() as session:
            policy = session.execute(
                select(PatrolPolicy)
                .where(
                    PatrolPolicy.enabled.is_(True),
                    PatrolPolicy.next_run_at <= claimed_at,
                )
                .order_by(PatrolPolicy.next_run_at.asc(), PatrolPolicy.id.asc())
                .with_for_update(skip_locked=True)
                .limit(1)
            ).scalar_one_or_none()
            if policy is None:
                session.commit()
                return None
            run = self._schedule_claimed_policy(session, policy, worker_id, claimed_at)
            session.commit()
            return run.id

    def _claim_policy(
        self,
        policy_id: int,
        worker_id: str,
        claimed_at: datetime,
    ) -> int | None:
        with self.session_factory() as session:
            policy = session.execute(
                select(PatrolPolicy)
                .where(PatrolPolicy.id == policy_id)
                .with_for_update()
            ).scalar_one_or_none()
            if policy is None:
                return None
            run = self._schedule_claimed_policy(session, policy, worker_id, claimed_at)
            session.commit()
            return run.id

    def _schedule_claimed_policy(
        self,
        session: Session,
        policy: PatrolPolicy,
        worker_id: str,
        claimed_at: datetime,
    ) -> PatrolRun:
        policy.last_run_at = claimed_at
        policy.next_run_at = claimed_at + timedelta(seconds=max(policy.interval_seconds, 60))
        policy.updated_at = claimed_at
        run = PatrolRun(
            policy_id=policy.id,
            host_key="unresolved",
            status="RUNNING",
            snapshot_json={"claim": {"worker_id": _bounded_text(worker_id, 128)}},
            started_at=claimed_at,
        )
        session.add(run)
        session.flush()
        return run

    def _execute_run(self, run_id: int, *, completed_at: datetime) -> None:
        try:
            with self.session_factory() as session:
                run = session.get(PatrolRun, run_id)
                if run is None:
                    raise LookupError("claimed patrol run not found")
                policy = session.get(PatrolPolicy, run.policy_id)
                if policy is None:
                    raise LookupError("patrol policy disappeared after claim")
                report = self.posture_factory(self.registry, session).read()
                snapshot = _bounded_snapshot(report)
                host_key = _host_key(snapshot)
                run.host_key = host_key
                run.snapshot_json = snapshot
                findings = FindingService(session).apply_run(
                    policy,
                    run,
                    snapshot,
                    now=completed_at,
                )
                self._ensure_incident_tasks(session, policy, run, findings)
                collection_status = snapshot.get("collection_status")
                collection_failed = (
                    collection_status == "error"
                    if isinstance(collection_status, str)
                    else snapshot.get("status") == "error"
                )
                run.status = "FAILED" if collection_failed else "SUCCEEDED"
                run.error = _report_error(snapshot) if run.status == "FAILED" else None
                run.completed_at = completed_at
                session.commit()
        except Exception as exc:
            with self.session_factory() as session:
                run = session.get(PatrolRun, run_id)
                if run is None:
                    raise
                run.status = "FAILED"
                run.error = _sanitize_error(str(exc))
                run.completed_at = completed_at
                session.commit()

    @staticmethod
    def _ensure_incident_tasks(
        session: Session,
        policy: PatrolPolicy,
        run: PatrolRun,
        findings: list[Finding],
    ) -> None:
        incidents: dict[int, tuple[Incident, Finding]] = {}
        for finding in findings:
            if finding.incident_id is None:
                continue
            incident = session.get(Incident, finding.incident_id)
            if incident is not None:
                incidents.setdefault(incident.id, (incident, finding))

        for incident, finding in incidents.values():
            if incident.task_id is not None:
                continue
            accepted = TaskIntakeService(session).accept(_incident_prompt(incident))
            incident.task_id = accepted.task.id
            incident.status = "INVESTIGATING"
            incident.updated_at = run.completed_at or run.started_at
            notification_outbox = NotificationOutboxService(
                session,
                default_chat_id=settings.feishu_default_chat_id,
            )
            AuditService(
                session,
                event_sink=notification_outbox.enqueue_task_event,
            ).append_event(
                accepted.task,
                accepted.task.status,
                "patrol_incident_created",
                "巡检发现已聚合为事件，并进入证据驱动调查队列。",
                {
                    "policy_id": policy.id,
                    "patrol_run_id": run.id,
                    "finding_id": finding.id,
                    "incident_id": incident.id,
                    "host_key": incident.host_key,
                    "signal_key": incident.signal_key,
                },
            )
            IncidentCollaborationService(session).start(
                incident.id,
                initial_evidence_refs=(
                    finding.evidence_refs_json
                    if isinstance(finding.evidence_refs_json, list)
                    else []
                ),
                source="patrol",
            )


def _bounded_snapshot(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError("patrol collector returned a non-object report")
    encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(encoded.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise ValueError("patrol report exceeded the persisted size limit")
    return json.loads(encoded)


def _host_key(report: dict[str, Any]) -> str:
    snapshot = report.get("snapshot")
    hostname = snapshot.get("hostname") if isinstance(snapshot, dict) else None
    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("system_snapshot did not return a hostname")
    return hostname.strip()[:256]


def _incident_prompt(incident: Incident) -> str:
    scope = SIGNAL_INVESTIGATION_SCOPES.get(
        incident.signal_key,
        "重点核验该信号对应的实时系统证据。",
    )
    return (
        f"巡检发现：{incident.title}。主机 {incident.host_key}，{incident.summary}"
        f"{scope}"
        "请基于实时系统证据调查根因，并给出符合最小权限原则的安全处置建议。"
    )


def _report_error(report: dict[str, Any]) -> str:
    warnings = report.get("warnings")
    if isinstance(warnings, list):
        messages = [_bounded_text(item, 160) for item in warnings if isinstance(item, str) and item.strip()]
        if messages:
            return _sanitize_error("；".join(messages[:3]))
    return "巡检采集链路存在错误，已保留有效证据并停止健康结论。"


def _sanitize_error(value: str) -> str:
    compact = " ".join(value.replace("\x00", "").split())
    return compact[:500] or "unknown patrol error"


def _bounded_text(value: Any, limit: int) -> str:
    return str(value).strip()[:limit]
