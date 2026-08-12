from __future__ import annotations

import hashlib
import io
import json
import unittest
import zipfile

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.audit.service import AuditService
from backend.app.core.database import get_session
from backend.app.diagnostics.api import build_diagnostic_router
from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    AuditChain,
    EvidenceItem,
    Hypothesis,
    HypothesisEvidence,
    Investigation,
    SafetyReview,
    Task,
    TaskEvent,
    ToolCall,
)


class DiagnosticBundleApiTest(unittest.TestCase):
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
            AuditChain.__table__,
            ToolCall.__table__,
            Investigation.__table__,
            EvidenceItem.__table__,
            Hypothesis.__table__,
            HypothesisEvidence.__table__,
            SafetyReview.__table__,
            ActionProposal.__table__,
            ActionSafetyCase.__table__,
        ):
            table.create(engine)
        self.session = Session(engine, expire_on_commit=False)

        task = Task(
            trace_id="trace-diagnostic-bundle",
            user_input=(
                "检查 /var/log/app.log，api_key=fixture-api-value，"
                "App Secret：feishu-test-secret-value"
            ),
            intent="log_analysis",
            status="SEALED",
            risk_level="R2",
            summary="定位到日志增长，password=hunter2。",
        )
        self.session.add(task)
        self.session.flush()
        AuditService(self.session).append_event(
            task,
            "RECEIVED",
            "task_created",
            "接收请求，Authorization: Bearer hidden-bearer-token。",
            {"raw_event_secret": "event-payload-secret"},
        )

        tool_call = ToolCall(
            task_id=task.id,
            tool_name="journal_query",
            tool_version="1.2.0",
            input_json={"token": "raw-tool-input-secret"},
            output_json={
                "observations": [{"line": "raw-tool-output-secret"}],
                "warnings": ["password=hunter2"],
                "evidence_refs": ["file:/var/log/app.log"],
            },
            risk_level="R0",
            status="ok",
            duration_ms=18,
        )
        self.session.add(tool_call)
        self.session.flush()

        investigation = Investigation(
            task_id=task.id,
            status="CONCLUDED",
            current_iteration=2,
            max_iterations=4,
            max_tool_calls=12,
            max_elapsed_ms=120000,
            stop_reason="证据满足结论要求。",
        )
        self.session.add(investigation)
        self.session.flush()
        evidence = EvidenceItem(
            investigation_id=investigation.id,
            source_ref="journal_query:observation:1:/var/log/app.log",
            source_type="MCP",
            source_key="journal_query",
            tool_call_id=tool_call.id,
            title="应用日志摘要",
            summary="path=/var/log/app.log，password=hunter2",
            payload_json={"line": "raw-evidence-payload-secret"},
            trust_level="local_tool",
        )
        self.session.add(evidence)
        self.session.flush()
        hypothesis = Hypothesis(
            investigation_id=investigation.id,
            key="log-growth",
            title="应用日志持续增长",
            rationale="日志增长与磁盘占用一致，token=hypothesis-secret。",
            evidence_gap="无",
            status="SUPPORTED",
            confidence_level="HIGH",
            confidence_score=92,
            first_seen_iteration=1,
            last_updated_iteration=2,
        )
        self.session.add(hypothesis)
        self.session.flush()
        self.session.add(
            HypothesisEvidence(
                hypothesis_id=hypothesis.id,
                evidence_item_id=evidence.id,
                relation="SUPPORTS",
                rationale="路径和增长趋势一致。",
            )
        )
        self.session.add(
            SafetyReview(
                task_id=task.id,
                review_type="intent",
                risk_level="R2",
                decision="APPROVAL_REQUIRED",
                matched_rules_json=[
                    {
                        "rule_id": "action-log-rotate",
                        "category": "side_effect",
                        "pattern": "raw-rule-pattern-secret",
                    }
                ],
                reason="需要审批，password=review-secret。",
            )
        )
        proposal = ActionProposal(
            task_id=task.id,
            tool_name="safe_log_rotate",
            input_json={"path": "/var/log/app.log", "secret": "proposal-input-secret"},
            risk_level="R2",
            reason="备份后轮转日志。",
            status="PENDING_APPROVAL",
            dry_run_result_json={"raw": "dry-run-secret"},
        )
        self.session.add(proposal)
        self.session.flush()
        self.session.add(
            ActionSafetyCase(
                task_id=task.id,
                proposal_id=proposal.id,
                tool_name="safe_log_rotate",
                risk_level="R2",
                policy_version="action-safety-case-v1",
                status="READY",
                action_fingerprint="a" * 64,
                scope_json={
                    "resource_type": "file",
                    "paths": ["/var/log/app.log"],
                    "operation": "backup_compress_then_truncate",
                    "side_effects": ["create_backup", "truncate_source"],
                    "secret": "safety-scope-secret",
                },
                preconditions_json=[
                    {"code": "source_hash_complete", "statement": "执行前记录哈希。"}
                ],
                postconditions_json=[
                    {"code": "backup_hash_matches", "statement": "备份哈希一致。"}
                ],
                verifier_tool="file_integrity_state",
                rollback_strategy_json={
                    "mode": "APPROVAL_REQUIRED",
                    "tool_name": "restore_log_backup",
                    "summary": "使用备份恢复。",
                    "secret": "rollback-secret",
                },
                evidence_refs_json=["tool_call:1", "file:/var/log/app.log"],
                result_json={"execution": {"artifacts": ["result-secret"]}},
                case_hash="b" * 64,
            )
        )
        self.session.commit()
        self.task = task

        app = FastAPI()
        api_router = APIRouter(prefix="/api")
        api_router.include_router(build_diagnostic_router())
        app.include_router(api_router)

        def override_session():
            yield self.session

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.session.close()

    def test_export_is_redacted_hashed_and_audited(self) -> None:
        response = self.client.post(
            f"/api/tasks/{self.task.id}/diagnostic-bundle"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/zip")
        self.assertIn(
            f"opscouncil-task-{self.task.id}-diagnostic.zip",
            response.headers["content-disposition"],
        )
        self.assertEqual(
            response.headers["x-opscouncil-bundle-sha256"],
            hashlib.sha256(response.content).hexdigest(),
        )

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            self.assertEqual(
                set(archive.namelist()),
                {
                    "task.json",
                    "evidence.json",
                    "hypotheses.json",
                    "safety.json",
                    "tool-calls.json",
                    "audit.json",
                    "manifest.json",
                },
            )
            contents = {
                name: archive.read(name)
                for name in archive.namelist()
            }

        all_text = b"\n".join(contents.values()).decode("utf-8")
        for secret in (
            "fixture-api-value",
            "feishu-test-secret-value",
            "hidden-bearer-token",
            "hunter2",
            "event-payload-secret",
            "raw-tool-input-secret",
            "raw-tool-output-secret",
            "raw-evidence-payload-secret",
            "hypothesis-secret",
            "review-secret",
            "raw-rule-pattern-secret",
            "proposal-input-secret",
            "dry-run-secret",
            "safety-scope-secret",
            "rollback-secret",
            "result-secret",
        ):
            self.assertNotIn(secret, all_text)
        self.assertIn("/var/log/app.log", all_text)
        self.assertIn("journal_query", all_text)
        self.assertIn("[REDACTED]", all_text)

        manifest = json.loads(contents["manifest.json"])
        self.assertEqual(manifest["privacy"]["scope"], "single_task")
        for descriptor in manifest["files"]:
            file_content = contents[descriptor["name"]]
            self.assertEqual(descriptor["bytes"], len(file_content))
            self.assertEqual(
                descriptor["sha256"],
                hashlib.sha256(file_content).hexdigest(),
            )

        audit_snapshot = json.loads(contents["audit.json"])
        self.assertTrue(audit_snapshot["verification"]["valid"])
        self.assertEqual(audit_snapshot["verification"]["entry_count"], 1)

        export_event = self.session.scalar(
            select(TaskEvent).where(
                TaskEvent.task_id == self.task.id,
                TaskEvent.event_type == "diagnostic_bundle_exported",
            )
        )
        self.assertIsNotNone(export_event)
        self.assertEqual(
            export_event.payload_json["sha256"],
            response.headers["x-opscouncil-bundle-sha256"],
        )
        self.assertTrue(AuditService(self.session).verify_trace(self.task.trace_id)["valid"])

    def test_missing_task_returns_404_without_audit_side_effect(self) -> None:
        before = self.session.query(TaskEvent).count()

        response = self.client.post("/api/tasks/999/diagnostic-bundle")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.session.query(TaskEvent).count(), before)


if __name__ == "__main__":
    unittest.main()
