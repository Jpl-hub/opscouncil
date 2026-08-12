from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    ExecutionRecord,
    Finding,
    Hypothesis,
    Incident,
    Investigation,
    PatrolPolicy,
    PatrolRun,
    Task,
    TaskEvent,
    ToolCall,
)
from backend.app.patrol.timeline import IncidentTimelineService
from backend.app.safety.safety_case import ActionSafetyCaseService


class IncidentTimelineTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        for table in (
            Task.__table__,
            TaskEvent.__table__,
            ToolCall.__table__,
            Investigation.__table__,
            Hypothesis.__table__,
            PatrolPolicy.__table__,
            PatrolRun.__table__,
            Incident.__table__,
            Finding.__table__,
            ActionProposal.__table__,
            ActionSafetyCase.__table__,
            ExecutionRecord.__table__,
        ):
            table.create(engine)
        self.session = Session(engine, expire_on_commit=False)

    def tearDown(self) -> None:
        self.session.close()

    def test_reconstructs_detection_investigation_change_and_verification(self) -> None:
        started = datetime(2026, 7, 29, 1, 0, tzinfo=timezone.utc)
        task = Task(
            trace_id="trace-incident-timeline",
            user_input="调查配置权限漂移",
            intent="config_integrity_analysis",
            status="SEALED",
            risk_level="R3",
            summary="配置权限已恢复并验证。",
            created_at=started + timedelta(seconds=3),
            updated_at=started + timedelta(seconds=18),
        )
        policy = PatrolPolicy(
            name="关键配置巡检",
            signal_keys_json=["config_integrity"],
            next_run_at=started,
        )
        self.session.add_all([task, policy])
        self.session.flush()
        run = PatrolRun(
            policy_id=policy.id,
            host_key="linux-node-01",
            status="SUCCEEDED",
            started_at=started,
            completed_at=started + timedelta(seconds=2),
        )
        incident = Incident(
            host_key="linux-node-01",
            signal_key="config_integrity",
            dedupe_key="linux-node-01:config_integrity",
            status="RESOLVED",
            severity="CRITICAL",
            title="关键配置发生漂移",
            summary="/etc/example.conf 权限偏离基线。",
            task_id=task.id,
            healthy_streak=2,
            recovery_target=2,
            last_healthy_at=started + timedelta(seconds=25),
            opened_at=started,
            updated_at=started + timedelta(seconds=25),
            closed_at=started + timedelta(seconds=25),
        )
        self.session.add_all([run, incident])
        self.session.flush()
        self.session.add(
            Finding(
                policy_id=policy.id,
                patrol_run_id=run.id,
                incident_id=incident.id,
                host_key=incident.host_key,
                signal_key=incident.signal_key,
                fingerprint="a" * 64,
                severity="CRITICAL",
                status="RESOLVED",
                title=incident.title,
                summary=incident.summary,
                metric_json={"metric": "mode 0o666"},
                evidence_refs_json=["config-check:7"],
                first_observed_at=started,
                last_observed_at=started,
                occurrence_count=1,
                resolved_at=started + timedelta(seconds=25),
            )
        )
        investigation = Investigation(
            task_id=task.id,
            status="CONCLUDED",
            current_iteration=2,
            max_iterations=4,
            max_tool_calls=8,
            max_elapsed_ms=30000,
            started_at=started + timedelta(seconds=4),
            completed_at=started + timedelta(seconds=9),
        )
        self.session.add(investigation)
        self.session.flush()
        self.session.add(
            Hypothesis(
                investigation_id=investigation.id,
                key="mode-drift",
                title="权限位漂移",
                rationale="完整内容哈希与属主均未变化，仅权限位偏离确认基线。",
                evidence_gap="",
                status="SUPPORTED",
                confidence_level="HIGH",
                confidence_score=94,
                first_seen_iteration=1,
                last_updated_iteration=2,
                created_at=started + timedelta(seconds=6),
                updated_at=started + timedelta(seconds=9),
            )
        )
        proposal = ActionProposal(
            task_id=task.id,
            tool_name="restore_config_mode",
            input_json={
                "path": "/tmp/opscouncil-lab/example.conf",
                "target_mode": "0o640",
                "expected_sha256": "b" * 64,
                "baseline_id": 1,
                "baseline_check_id": 7,
                "dry_run": False,
            },
            risk_level="R3",
            reason="恢复确认基线中的权限位。",
            status="EXECUTED",
            dry_run_result_json={
                "status": "ok",
                "evidence_refs": ["config-check:7"],
            },
            created_at=started + timedelta(seconds=10),
        )
        self.session.add(proposal)
        self.session.flush()
        pre_call = self._call(task, "config_integrity_scan", started + timedelta(seconds=12))
        action_call = self._call(task, "restore_config_mode", started + timedelta(seconds=14))
        post_call = self._call(task, "config_integrity_scan", started + timedelta(seconds=16))
        safety_cases = ActionSafetyCaseService(self.session)
        safety_case = safety_cases.create_for_proposal(proposal)
        safety_cases.record_approval(safety_case, operator="ops-admin", comment=None)
        safety_cases.record_precondition(
            safety_case,
            call_id=pre_call.id,
            valid=True,
            reason="执行前证据完整。",
            details={},
        )
        safety_cases.record_execution_started(safety_case)
        safety_cases.record_execution(
            safety_case,
            call_id=action_call.id,
            outcome="SUCCEEDED",
            output={"status": "ok"},
        )
        safety_cases.record_postcondition(
            safety_case,
            call_id=post_call.id,
            valid=True,
            reason="权限恢复且内容哈希未变化。",
            details={},
        )
        self.session.add(
            ExecutionRecord(
                task_id=task.id,
                proposal_id=proposal.id,
                tool_call_id=action_call.id,
                tool_name=proposal.tool_name,
                risk_level="R3",
                executor_mode="restricted-local",
                runtime_user="opscouncil-agent",
                runtime_uid=1001,
                target_user="opscouncil-agent",
                allowed="true",
                reason="目标路径和执行身份均在策略范围内。",
                scope_json={"target_path": proposal.input_json["path"]},
                created_at=started + timedelta(seconds=14),
            )
        )
        self.session.add_all(
            [
                TaskEvent(
                    task_id=task.id,
                    stage="INVESTIGATE",
                    event_type="investigation_started",
                    message="开始证据驱动调查。",
                    payload_json={},
                    created_at=started + timedelta(seconds=4),
                ),
                TaskEvent(
                    task_id=task.id,
                    stage="SUMMARIZE",
                    event_type="action_safety_case_created",
                    message="动作范围和验证条件已固化。",
                    payload_json={
                        "proposal_id": proposal.id,
                        "safety_case_id": safety_case.id,
                        "case_hash": safety_case.case_hash,
                    },
                    created_at=started + timedelta(seconds=11),
                ),
                TaskEvent(
                    task_id=task.id,
                    stage="EXECUTE",
                    event_type="tool_call",
                    message="配置权限恢复工具执行完成。",
                    payload_json={
                        "proposal_id": proposal.id,
                        "tool_call_id": action_call.id,
                        "tool_name": proposal.tool_name,
                        "execution_record_id": 1,
                    },
                    created_at=started + timedelta(seconds=14),
                ),
                TaskEvent(
                    task_id=task.id,
                    stage="VERIFY",
                    event_type="verify_result",
                    message="权限、哈希和属主均通过独立核验。",
                    payload_json={
                        "proposal_id": proposal.id,
                        "action_tool_call_id": action_call.id,
                        "verifier_tool_call_ids": [pre_call.id, post_call.id],
                        "valid": True,
                    },
                    created_at=started + timedelta(seconds=16),
                ),
            ]
        )
        self.session.commit()

        result = IncidentTimelineService(self.session).read(incident.id)

        self.assertEqual(result["correlation"]["root_cause"]["score"], 94)
        self.assertEqual(result["correlation"]["change_count"], 1)
        self.assertEqual(result["correlation"]["verification_status"], "VERIFIED")
        phases = [item["phase"] for item in result["events"]]
        self.assertIn("DETECTION", phases)
        self.assertIn("INVESTIGATION", phases)
        self.assertIn("DECISION", phases)
        self.assertIn("CHANGE", phases)
        self.assertIn("VERIFICATION", phases)
        self.assertIn("RECOVERY", phases)
        change = next(item for item in result["events"] if item["phase"] == "CHANGE")
        self.assertIn(f"execution:1", change["references"])
        timestamps = [item["occurred_at"] for item in result["events"]]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_missing_incident_is_not_synthesized(self) -> None:
        with self.assertRaisesRegex(LookupError, "incident not found"):
            IncidentTimelineService(self.session).read(999)

    def _call(self, task: Task, tool_name: str, at: datetime) -> ToolCall:
        call = ToolCall(
            task_id=task.id,
            tool_name=tool_name,
            tool_version="1.0.0",
            input_json={},
            output_json={"status": "ok"},
            risk_level="R0",
            status="ok",
            started_at=at,
            ended_at=at,
        )
        self.session.add(call)
        self.session.flush()
        return call


if __name__ == "__main__":
    unittest.main()
