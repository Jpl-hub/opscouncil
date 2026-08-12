from __future__ import annotations

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.api.routes import build_router
from backend.app.core.database import get_session
from backend.app.models.entities import ActionProposal, ActionSafetyCase, Task
from backend.app.safety.safety_case import ActionSafetyCaseService


class EmptyRegistry:
    def list_tools(self) -> list[dict]:
        return []


class ApprovalQueueApiTest(unittest.TestCase):
    def setUp(self) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        Task.__table__.create(engine)
        ActionProposal.__table__.create(engine)
        ActionSafetyCase.__table__.create(engine)
        self.session = Session(engine, expire_on_commit=False)
        older = Task(
            trace_id="trace-approval-older",
            user_input="清理受控测试日志",
            intent="disk_pressure_analysis",
            status="SEALED",
            risk_level="R2",
            summary="已形成安全轮转建议。",
        )
        newer = Task(
            trace_id="trace-approval-newer",
            user_input="恢复配置权限",
            intent="config_integrity_analysis",
            status="SEALED",
            risk_level="R3",
            summary="已形成配置权限恢复建议。",
        )
        self.session.add_all([older, newer])
        self.session.flush()
        older_proposal = ActionProposal(
            task_id=older.id,
            tool_name="safe_log_rotate",
            input_json={"path": "/tmp/opscouncil-lab/test.log"},
            risk_level="R2",
            reason="目标位于受控靶场并支持备份。",
            status="PENDING_APPROVAL",
            dry_run_result_json={"status": "ok", "evidence_refs": ["tool_call:1"]},
        )
        newer_proposal = ActionProposal(
            task_id=newer.id,
            tool_name="restore_config_mode",
            input_json={
                "path": "/tmp/opscouncil-lab/sshd_config",
                "target_mode": "0644",
                "expected_sha256": "a" * 64,
            },
            risk_level="R3",
            reason="内容哈希与确认基线一致。",
            status="PENDING_APPROVAL",
            dry_run_result_json={"status": "ok", "evidence_refs": ["tool_call:2"]},
        )
        self.session.add_all(
            [
                older_proposal,
                newer_proposal,
                ActionProposal(
                    task_id=older.id,
                    tool_name="safe_log_rotate",
                    input_json={"path": "/tmp/opscouncil-lab/stale.log"},
                    risk_level="R2",
                    reason="旧版本处置建议，缺少执行依据。",
                    status="PENDING_APPROVAL",
                    dry_run_result_json={"status": "ok"},
                ),
                ActionProposal(
                    task_id=older.id,
                    tool_name="safe_log_rotate",
                    input_json={"path": "/tmp/opscouncil-lab/old.log"},
                    risk_level="R2",
                    reason="操作员已拒绝。",
                    status="REJECTED",
                ),
            ]
        )
        self.session.flush()
        safety_cases = ActionSafetyCaseService(self.session)
        safety_cases.create_for_proposal(older_proposal)
        safety_cases.create_for_proposal(newer_proposal)
        self.session.commit()

        app = FastAPI()
        app.include_router(build_router(EmptyRegistry()))  # type: ignore[arg-type]

        def override_session():
            yield self.session

        app.dependency_overrides[get_session] = override_session
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        self.session.close()

    def test_pending_queue_is_global_and_includes_task_context(self) -> None:
        response = self.client.get(
            "/api/proposals",
            params={"status_filter": "PENDING_APPROVAL"},
        )

        self.assertEqual(response.status_code, 200)
        rows = response.json()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["tool_name"], "restore_config_mode")
        self.assertEqual(rows[0]["task_id"], 2)
        self.assertEqual(rows[0]["user_input"], "恢复配置权限")
        self.assertEqual(rows[1]["task_id"], 1)
        self.assertNotIn("input", rows[0])
        self.assertNotIn("旧版本处置建议", [row["reason"] for row in rows])

    def test_unknown_queue_status_is_rejected(self) -> None:
        response = self.client.get(
            "/api/proposals",
            params={"status_filter": "UNKNOWN"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"], "unsupported proposal status")


if __name__ == "__main__":
    unittest.main()
