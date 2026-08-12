from __future__ import annotations

import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.assets.service import ServiceExpectationService
from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    ServiceExpectation,
    Task,
    ToolCall,
)
from backend.app.safety.safety_case import (
    ActionSafetyCaseService,
    SafetyCaseIntegrityError,
)


class ActionSafetyCaseTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in (
            Task.__table__,
            ToolCall.__table__,
            ActionProposal.__table__,
            ActionSafetyCase.__table__,
            ServiceExpectation.__table__,
        ):
            table.create(engine)
        self.session = Session(engine, expire_on_commit=False)
        self.service = ActionSafetyCaseService(self.session)

    def tearDown(self) -> None:
        self.session.close()

    def test_builds_exact_contract_from_successful_dry_run(self) -> None:
        proposal = self._proposal()

        safety_case = self.service.create_for_proposal(proposal)

        self.assertEqual(safety_case.status, "READY")
        self.assertEqual(safety_case.verifier_tool, "file_integrity_state")
        self.assertEqual(safety_case.scope_json["paths"], ["/tmp/opscouncil-lab/app.log"])
        self.assertEqual(
            safety_case.rollback_strategy_json["tool_name"],
            "restore_log_backup",
        )
        self.assertEqual(
            safety_case.bound_action_json["input"]["path"],
            "/tmp/opscouncil-lab/app.log",
        )
        self.assertEqual(
            self.service.bound_action(safety_case, proposal),
            safety_case.bound_action_json,
        )
        self.assertEqual(len(safety_case.case_hash), 64)
        self.assertIn("proposal:1", safety_case.evidence_refs_json)

    def test_tampered_proposal_is_revoked_before_approval(self) -> None:
        proposal = self._proposal()
        safety_case = self.service.create_for_proposal(proposal)
        proposal.input_json = {
            **proposal.input_json,
            "path": "/tmp/opscouncil-lab/other.log",
        }
        self.session.flush()

        with self.assertRaisesRegex(
            SafetyCaseIntegrityError,
            "处置方案与执行依据不一致",
        ):
            self.service.assert_ready(proposal)

        self.assertEqual(safety_case.status, "REVOKED")

    def test_bound_action_copy_cannot_mutate_sealed_contract(self) -> None:
        proposal = self._proposal()
        safety_case = self.service.create_for_proposal(proposal)

        bound_action = self.service.bound_action(safety_case, proposal)
        bound_action["input"]["path"] = "/tmp/changed.log"

        self.assertEqual(
            safety_case.bound_action_json["input"]["path"],
            "/tmp/opscouncil-lab/app.log",
        )
        self.service.assert_ready(proposal)

    def test_lifecycle_records_independent_evidence_and_verification(self) -> None:
        proposal = self._proposal()
        safety_case = self.service.create_for_proposal(proposal)
        pre_call = self._tool_call("file_integrity_state")
        action_call = self._tool_call("safe_log_rotate")
        post_call = self._tool_call("file_integrity_state")

        ready = self.service.assert_ready(proposal)
        self.service.record_approval(ready, operator="ops-admin", comment="变更窗口内执行")
        self.service.record_precondition(
            ready,
            call_id=pre_call.id,
            valid=True,
            reason="源日志完整哈希已记录。",
            details={"source_sha256": "a" * 64},
        )
        self.service.record_execution_started(ready)
        self.service.record_execution(
            ready,
            call_id=action_call.id,
            outcome="SUCCEEDED",
            output={
                "status": "ok",
                "artifacts": [{"path": "/tmp/opscouncil-lab/app.log.gz"}],
                "evidence_refs": ["/tmp/opscouncil-lab/app.log.gz"],
            },
        )
        self.service.record_postcondition(
            ready,
            call_id=post_call.id,
            valid=True,
            reason="备份内容与执行前哈希一致。",
            details={"artifact_content_sha256": "a" * 64},
        )

        self.assertEqual(ready.status, "VERIFIED")
        self.assertEqual(ready.approved_by, "ops-admin")
        self.assertEqual(ready.pre_verifier_call_id, pre_call.id)
        self.assertEqual(ready.execution_call_id, action_call.id)
        self.assertEqual(ready.post_verifier_call_id, post_call.id)
        self.assertIn(f"tool_call:{post_call.id}", ready.evidence_refs_json)
        self.assertTrue(ready.result_json["postcondition"]["valid"])
        self.assertEqual(ready.result_json["execution"]["outcome"], "SUCCEEDED")
        self.assertIs(self.service.get_for_proposal(proposal.id), ready)

    def test_unknown_outcome_requires_operator_and_disables_success_claim(self) -> None:
        proposal = self._proposal()
        safety_case = self.service.create_for_proposal(proposal)
        action_call = self._tool_call("safe_log_rotate")

        ready = self.service.assert_ready(proposal)
        self.service.record_approval(ready, operator="ops-admin", comment=None)
        self.service.record_execution_started(ready)
        self.service.record_execution(
            ready,
            call_id=action_call.id,
            outcome="UNKNOWN",
            output={"status": "unknown", "warnings": ["connection lost"]},
            reason="connection lost",
        )

        self.assertEqual(ready.status, "NEEDS_OPERATOR")
        self.assertEqual(ready.result_json["execution"]["outcome"], "UNKNOWN")
        self.assertIsNone(ready.result_json["execution"]["succeeded"])

    def test_missing_dry_run_cannot_create_safety_case(self) -> None:
        proposal = self._proposal(dry_run=None)

        with self.assertRaisesRegex(ValueError, "successful dry-run"):
            self.service.create_for_proposal(proposal)

    def test_restart_contract_freezes_change_impact_and_service_ownership(self) -> None:
        proposal = self._restart_proposal(include_impact=True)

        safety_case = self.service.create_for_proposal(proposal)

        impact = safety_case.scope_json["change_impact"]
        self.assertEqual(impact["status"], "ASSESSED")
        self.assertEqual(impact["propagated_unit_count"], 1)
        self.assertEqual(impact["catalogued_unit_count"], 2)
        by_unit = {item["unit"]: item for item in impact["predicted_units"]}
        self.assertEqual(by_unit["demo.service"]["service_owner"], "业务平台组")
        self.assertEqual(by_unit["worker.service"]["criticality"], "MEDIUM")
        self.assertIn(
            "change_impact_assessed",
            {item["code"] for item in safety_case.preconditions_json},
        )
        self.assertTrue(
            any(
                reference.startswith("tool_call:")
                for reference in safety_case.evidence_refs_json
            )
        )

    def test_restart_contract_rejects_missing_change_impact(self) -> None:
        proposal = self._restart_proposal(include_impact=False)

        with self.assertRaisesRegex(ValueError, "change-impact assessment"):
            self.service.create_for_proposal(proposal)

    def test_partial_restart_impact_creates_non_approvable_contract(self) -> None:
        proposal = self._restart_proposal(include_impact=True)
        call = self.session.scalar(
            select(ToolCall).where(
                ToolCall.task_id == proposal.task_id,
                ToolCall.tool_name == "service_dependency_snapshot",
            )
        )
        assert call is not None
        impact = call.output_json["observations"][0]["change_impact"]
        impact["status"] = "PARTIAL"
        impact["coverage"] = "PARTIAL"
        impact["evidence_gaps"] = [
            {
                "code": "SOCKET_OWNER_UNAVAILABLE",
                "count": 1,
                "reason": "关注连接缺少所属进程。",
            }
        ]

        safety_case = self.service.create_for_proposal(proposal)

        self.assertEqual(safety_case.status, "BLOCKED")
        self.assertEqual(
            safety_case.result_json["readiness"]["blockers"][0]["code"],
            "IMPACT_COVERAGE_INCOMPLETE",
        )
        with self.assertRaisesRegex(SafetyCaseIntegrityError, "BLOCKED"):
            self.service.assert_ready(proposal)

    def test_uncatalogued_propagated_service_blocks_approval(self) -> None:
        proposal = self._restart_proposal(include_impact=True)
        worker = self.session.scalar(
            select(ServiceExpectation).where(
                ServiceExpectation.unit_name == "worker.service"
            )
        )
        assert worker is not None
        self.session.delete(worker)
        self.session.flush()

        safety_case = self.service.create_for_proposal(proposal)

        self.assertEqual(safety_case.status, "BLOCKED")
        self.assertEqual(
            safety_case.result_json["readiness"]["uncatalogued_units"],
            ["worker.service"],
        )

    def test_restart_contract_is_revoked_when_service_expectation_changes(self) -> None:
        proposal = self._restart_proposal(include_impact=True)
        safety_case = self.service.create_for_proposal(proposal)
        record = self.session.scalar(
            select(ServiceExpectation).where(
                ServiceExpectation.unit_name == "demo.service"
            )
        )
        assert record is not None
        record.service_owner = "未确认责任方"
        record.version += 1
        self.session.flush()

        with self.assertRaisesRegex(
            SafetyCaseIntegrityError,
            "服务责任方或期望状态",
        ):
            self.service.assert_ready(proposal)

        self.assertEqual(safety_case.status, "REVOKED")

    def _proposal(
        self,
        *,
        dry_run: dict | None = {
            "status": "ok",
            "evidence_refs": ["/tmp/opscouncil-lab/app.log"],
        },
    ) -> ActionProposal:
        task = Task(
            trace_id=f"trace-safety-case-{id(self)}-{len(self.session.new)}",
            user_input="安全轮转测试日志",
            intent="disk_pressure_analysis",
            status="SEALED",
            risk_level="R2",
            summary="等待审批。",
        )
        self.session.add(task)
        self.session.flush()
        proposal = ActionProposal(
            task_id=task.id,
            tool_name="safe_log_rotate",
            input_json={
                "path": "/tmp/opscouncil-lab/app.log",
                "backup": True,
                "compress": True,
                "keep_days": 30,
                "dry_run": False,
            },
            risk_level="R2",
            reason="测试动作安全证明。",
            status="PENDING_APPROVAL",
            dry_run_result_json=dry_run,
        )
        self.session.add(proposal)
        self.session.flush()
        return proposal

    def _tool_call(self, name: str) -> ToolCall:
        proposal = self.session.query(ActionProposal).order_by(ActionProposal.id.desc()).first()
        assert proposal is not None
        call = ToolCall(
            task_id=proposal.task_id,
            tool_name=name,
            tool_version="1.0.0",
            input_json={},
            output_json={"status": "ok"},
            risk_level="R0",
            status="ok",
        )
        self.session.add(call)
        self.session.flush()
        return call

    def _restart_proposal(self, *, include_impact: bool) -> ActionProposal:
        task = Task(
            trace_id=f"trace-restart-impact-{id(self)}-{len(self.session.new)}",
            user_input="重启 demo.service",
            intent="log_analysis",
            status="SEALED",
            risk_level="R3",
            summary="等待审批。",
        )
        self.session.add(task)
        self.session.flush()
        catalog = ServiceExpectationService(self.session)
        for unit, owner, criticality in (
            ("demo.service", "业务平台组", "HIGH"),
            ("worker.service", "任务平台组", "MEDIUM"),
        ):
            catalog.register(
                host_key="*",
                unit_name=unit,
                expected_active_state="active",
                service_owner=owner,
                criticality=criticality,
                environment="TEST",
                rationale="测试服务必须保持运行。",
                source_ref="test-fixture",
                approved_by="ops-admin",
            )
        desired_call = ToolCall(
            task_id=task.id,
            tool_name="service_desired_state",
            tool_version="1.0.0",
            input_json={"unit": "demo.service"},
            output_json={
                "status": "ok",
                "observations": [
                    {
                        "unit": "demo.service",
                        "expected_active_state": "active",
                        "criticality": "HIGH",
                    }
                ],
                "evidence_refs": ["service-expectation:test"],
            },
            risk_level="R0",
            status="ok",
        )
        self.session.add(desired_call)
        if include_impact:
            self.session.add(
                ToolCall(
                    task_id=task.id,
                    tool_name="service_dependency_snapshot",
                    tool_version="1.1.0",
                    input_json={
                        "focus_units": ["demo.service"],
                        "change_action": "restart",
                    },
                    output_json={
                        "status": "ok",
                        "observations": [
                            {
                                "change_impact": {
                                    "status": "ASSESSED",
                                    "coverage": "FULL",
                                    "action": "restart",
                                    "target_units": ["demo.service"],
                                    "propagated_unit_count": 1,
                                    "possible_client_count": 0,
                                    "predicted_units": [
                                        {
                                            "unit": "demo.service",
                                            "role": "TARGET",
                                            "certainty": "DIRECT",
                                            "mechanism": "DIRECT_TARGET",
                                            "path": ["service:demo.service"],
                                        },
                                        {
                                            "unit": "worker.service",
                                            "role": "PROPAGATED",
                                            "certainty": "CERTAIN",
                                            "mechanism": "PART_OF",
                                            "path": [
                                                "service:demo.service",
                                                "service:worker.service",
                                            ],
                                        },
                                    ],
                                    "predicted_clients": [],
                                    "mechanism_counts": {"PART_OF": 1},
                                    "evidence_gaps": [],
                                }
                            }
                        ],
                        "evidence_refs": ["systemctl show demo.service"],
                    },
                    risk_level="R0",
                    status="ok",
                )
            )
        proposal = ActionProposal(
            task_id=task.id,
            tool_name="restart_managed_service",
            input_json={"unit": "demo.service", "dry_run": False},
            risk_level="R3",
            reason="测试服务重启影响证明。",
            status="PENDING_APPROVAL",
            dry_run_result_json={"status": "ok", "evidence_refs": ["systemd:demo.service"]},
        )
        self.session.add(proposal)
        self.session.flush()
        return proposal


if __name__ == "__main__":
    unittest.main()
