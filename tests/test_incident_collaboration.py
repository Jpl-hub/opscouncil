from __future__ import annotations

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.collaboration.service import (
    CollaborationAuthorizationError,
    CollaborationStateError,
    IncidentCollaborationService,
)
from backend.app.models.entities import (
    AgentWorkItem,
    CollaborationEvent,
    Incident,
    IncidentCollaboration,
)


TABLES = [
    Incident.__table__,
    IncidentCollaboration.__table__,
    AgentWorkItem.__table__,
    CollaborationEvent.__table__,
]


class IncidentCollaborationServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in TABLES:
            table.create(engine)
        self.session = Session(engine, expire_on_commit=False)
        self.service = IncidentCollaborationService(self.session)
        self.collaboration = self.service.create_incident(
            host_key="edge-01",
            signal_key="api-latency",
            severity="CRITICAL",
            title="订单 API 延迟升高",
            summary="最近五分钟 P99 延迟持续高于 1.8 秒。",
            dedupe_key="edge-01:api-latency:20260812",
            initial_evidence_refs=["metric:api-p99:1001"],
        )

    def tearDown(self) -> None:
        self.session.close()

    def test_complete_closed_loop_is_evidence_gated_and_hash_verified(self) -> None:
        self._submit_triage()
        self._submit_investigation()
        self._submit_plan()

        collaboration = self.service.get(self.collaboration.id)
        assert collaboration is not None
        self.assertEqual(collaboration.evidence_gate_status, "PASSED")
        self.assertEqual(collaboration.autonomy_mode, "HUMAN_GATED")
        self.assertIsNotNone(collaboration.action_contract_hash)

        self.service.record_execution(
            collaboration.id,
            controller_id="policy-controller",
            output={
                "outcome": "SUCCEEDED",
                "controller": "restricted-executor",
                "action_contract_hash": collaboration.action_contract_hash,
                "execution_ref": "execution:2001",
                "evidence_refs": ["execution:2001"],
                "rollback_performed": False,
                "detail": "灰度重启完成，执行器返回退出码 0。",
            },
        )
        self._claim("verify", "recovery_verifier", "recovery-verifier")
        self.service.submit(
            collaboration.id,
            "verify",
            role="recovery_verifier",
            agent_name="recovery-verifier",
            output={
                "verdict": "HEALTHY",
                "checks": [
                    {
                        "name": "订单 API 健康检查",
                        "status": "PASS",
                        "observed": "连续三次返回 200，P99 恢复至 210ms。",
                        "evidence_ref": "probe:order-api:post-2001",
                    }
                ],
                "observation_window_seconds": 90,
                "regression_detected": False,
                "rollback_required": False,
                "evidence_refs": ["probe:order-api:post-2001", "metric:api-p99:post-2001"],
                "summary": "独立探针和指标窗口均确认恢复。",
            },
        )
        self._claim("learn", "incident_commander", "incident-commander")
        result = self.service.submit(
            collaboration.id,
            "learn",
            role="incident_commander",
            agent_name="incident-commander",
            output={
                "incident_summary": "连接池耗尽导致订单 API 延迟，灰度重启后恢复。",
                "reusable_pattern": "连接池耗尽且重启影响受控时执行灰度重启。",
                "skill_candidate": True,
                "qualification_evidence_refs": [
                    "probe:order-api:post-2001",
                    "metric:api-p99:post-2001",
                ],
            },
        )

        self.assertEqual(result.collaboration.status, "RESOLVED")
        incident = self.session.get(Incident, result.collaboration.incident_id)
        assert incident is not None
        self.assertEqual(incident.status, "RESOLVED")
        verification = self.service.verify_chain(result.collaboration.id)
        self.assertTrue(verification["valid"])
        self.assertGreaterEqual(verification["event_count"], 13)

    def test_agent_cannot_claim_controller_execution_or_another_role(self) -> None:
        with self.assertRaises(CollaborationAuthorizationError):
            self.service.claim(
                self.collaboration.id,
                "triage",
                role="rca_investigator",
                agent_name="rca-investigator",
            )

        self._submit_triage()
        self._submit_investigation()
        self._submit_plan()
        with self.assertRaises(CollaborationAuthorizationError):
            self.service.claim(
                self.collaboration.id,
                "execute",
                role="remediation_planner",
                agent_name="remediation-planner",
            )

    def test_agentteams_dispatch_receipt_is_part_of_verified_chain(self) -> None:
        event = self.service.record_agentteams_dispatch(
            self.collaboration.id,
            event_id="$matrix-event-1001",
        )

        self.assertEqual(event.event_type, "agentteams_dispatched")
        self.assertEqual(event.source_system, "agentteams-matrix")
        self.assertEqual(event.source_event_id, "$matrix-event-1001")
        self.assertTrue(self.service.verify_chain(self.collaboration.id)["valid"])

    def test_evidence_gate_keeps_investigation_open(self) -> None:
        self._submit_triage()
        self._claim("investigate", "rca_investigator", "rca-investigator")
        result = self.service.submit(
            self.collaboration.id,
            "investigate",
            role="rca_investigator",
            agent_name="rca-investigator",
            output={
                "decision": "COLLECT_MORE",
                "hypotheses": [
                    {
                        "key": "h1",
                        "claim": "连接池可能耗尽。",
                        "status": "OPEN",
                        "evidence_refs": ["metric:api-p99:1001"],
                        "counter_evidence_refs": [],
                    }
                ],
                "root_cause": None,
                "confidence": 0.42,
                "evidence_refs": ["metric:api-p99:1001"],
                "counter_evidence_reviewed": False,
                "missing_evidence": ["连接池运行时状态"],
            },
        )

        self.assertEqual(result.collaboration.status, "INVESTIGATING")
        self.assertEqual(result.collaboration.evidence_gate_status, "FAILED")
        self.assertEqual(result.work_item.status, "READY")
        statuses = {item.work_key: item.status for item in self.service.work_items(self.collaboration.id)}
        self.assertEqual(statuses["plan"], "PENDING")

    def test_verifier_cannot_reuse_only_execution_receipt(self) -> None:
        self._submit_triage()
        self._submit_investigation()
        self._submit_plan()
        collaboration = self.service.get(self.collaboration.id)
        assert collaboration is not None and collaboration.action_contract_hash is not None
        self.service.record_execution(
            collaboration.id,
            controller_id="policy-controller",
            output={
                "outcome": "SUCCEEDED",
                "controller": "restricted-executor",
                "action_contract_hash": collaboration.action_contract_hash,
                "execution_ref": "execution:3001",
                "evidence_refs": ["execution:3001"],
                "rollback_performed": False,
                "detail": "动作完成。",
            },
        )
        self._claim("verify", "recovery_verifier", "recovery-verifier")

        with self.assertRaises(CollaborationStateError):
            self.service.submit(
                collaboration.id,
                "verify",
                role="recovery_verifier",
                agent_name="recovery-verifier",
                output={
                    "verdict": "HEALTHY",
                    "checks": [
                        {
                            "name": "执行状态",
                            "status": "PASS",
                            "observed": "执行器报告成功。",
                            "evidence_ref": "execution:3001",
                        }
                    ],
                    "observation_window_seconds": 30,
                    "regression_detected": False,
                    "rollback_required": False,
                    "evidence_refs": ["execution:3001"],
                    "summary": "仅复述执行结果。",
                },
            )

    def test_planner_cannot_change_an_accepted_dry_run_candidate(self) -> None:
        self._submit_triage()
        self._submit_investigation()
        collaboration = self.service.get(self.collaboration.id)
        assert collaboration is not None
        context = dict(collaboration.shared_context_json)
        context["action_candidates"] = [
            {
                "proposal_id": 17,
                "tool_name": "safe_log_rotate",
                "arguments": {"path": "/var/log/app.log", "dry_run": False},
                "risk_level": "R2",
            }
        ]
        collaboration.shared_context_json = context
        self._claim("plan", "remediation_planner", "remediation-planner")

        with self.assertRaisesRegex(CollaborationStateError, "downgrade"):
            self.service.submit(
                self.collaboration.id,
                "plan",
                role="remediation_planner",
                agent_name="remediation-planner",
                output={
                    "action": {
                        "proposal_id": 17,
                        "tool_name": "safe_log_rotate",
                        "arguments": {"path": "/var/log/app.log", "dry_run": False},
                        "risk_level": "R1",
                        "environment": "LAB",
                        "target_scope": ["/var/log/app.log"],
                        "preconditions": ["文件存在"],
                        "postconditions": ["备份存在"],
                        "rollback_steps": ["恢复备份"],
                        "reversible": True,
                        "canary": True,
                        "policy_authorization_ref": "policy:lab-log-rotate:v1",
                        "rationale": "轮转日志。",
                    },
                    "evidence_refs": ["proposal:17"],
                    "alternatives_rejected": [],
                },
            )

    def _claim(self, work_key: str, role: str, agent_name: str) -> None:
        self.service.claim(
            self.collaboration.id,
            work_key,
            role=role,
            agent_name=agent_name,
        )

    def _submit_triage(self) -> None:
        self._claim("triage", "signal_correlator", "signal-correlator")
        self.service.submit(
            self.collaboration.id,
            "triage",
            role="signal_correlator",
            agent_name="signal-correlator",
            output={
                "incident_boundary": "edge-01 上订单 API 延迟与连接池异常属于同一事件。",
                "correlated_signals": [
                    {
                        "signal_key": "api-latency",
                        "source": "prometheus",
                        "observed_at": "2026-08-12T10:00:00Z",
                        "summary": "P99 延迟高于 1.8 秒。",
                        "evidence_ref": "metric:api-p99:1001",
                    }
                ],
                "suppressed_alert_count": 7,
                "severity": "CRITICAL",
                "affected_resources": ["service:order-api", "host:edge-01"],
                "evidence_refs": ["metric:api-p99:1001"],
            },
        )

    def _submit_investigation(self) -> None:
        self._claim("investigate", "rca_investigator", "rca-investigator")
        self.service.submit(
            self.collaboration.id,
            "investigate",
            role="rca_investigator",
            agent_name="rca-investigator",
            output={
                "decision": "CONCLUDE",
                "hypotheses": [
                    {
                        "key": "connection-pool",
                        "claim": "订单服务连接池耗尽。",
                        "status": "SUPPORTED",
                        "evidence_refs": ["metric:pool-wait:1002", "log:order-api:1003"],
                        "counter_evidence_refs": ["probe:database:1004"],
                    }
                ],
                "root_cause": "订单服务连接池耗尽；数据库独立探针正常，排除数据库不可达。",
                "confidence": 0.88,
                "evidence_refs": [
                    "metric:pool-wait:1002",
                    "log:order-api:1003",
                    "probe:database:1004",
                ],
                "counter_evidence_reviewed": True,
                "missing_evidence": [],
            },
        )

    def _submit_plan(self) -> None:
        self._claim("plan", "remediation_planner", "remediation-planner")
        self.service.submit(
            self.collaboration.id,
            "plan",
            role="remediation_planner",
            agent_name="remediation-planner",
            output={
                "action": {
                    "proposal_id": 101,
                    "tool_name": "restart_managed_service",
                    "arguments": {"unit": "order-api.service"},
                    "risk_level": "R2",
                    "environment": "STAGING",
                    "target_scope": ["service:order-api@edge-01"],
                    "preconditions": ["至少一个健康副本可承载流量"],
                    "postconditions": ["三次健康检查通过", "P99 延迟低于 500ms"],
                    "rollback_steps": ["恢复被摘除副本并撤销本次流量切换"],
                    "reversible": True,
                    "canary": True,
                    "policy_authorization_ref": "policy:staging-canary-restart:v2",
                    "rationale": "先重启单个灰度副本，限制影响范围。",
                },
                "evidence_refs": ["impact:order-api:1005", "policy:staging-canary-restart:v2"],
                "alternatives_rejected": ["全量重启会扩大影响范围"],
            },
        )


if __name__ == "__main__":
    unittest.main()
