from __future__ import annotations

import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.agent.runner import AgentRunner
from backend.app.config_baseline.service import ConfigBaselineService, LAB_SCOPE
from backend.app.executor import policy
from backend.app.executor.config_policy import validate_repairable_config_path
from backend.app.executor.tools import (
    RestoreConfigModeInput,
    register_executor_tools,
    restore_config_mode,
)
from backend.app.executor.verification import (
    post_action_verification_input,
    pre_action_verification_input,
    validate_post_action_evidence,
    validate_pre_action_evidence,
    verification_tool_name,
)
from backend.app.mcp.types import ToolResult
from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    Approval,
    AuditChain,
    ConfigBaseline,
    ConfigBaselineCheck,
    ExecutionRecord,
    NotificationOutbox,
    Operator,
    OperatorExternalIdentity,
    SafetyReview,
    Task,
    TaskChannelBinding,
    TaskEvent,
    ToolCall,
)
from backend.app.perception.tools import build_perception_registry
from backend.app.safety.engine import SafetyEngine


TABLES = [
    Operator.__table__,
    OperatorExternalIdentity.__table__,
    Task.__table__,
    TaskEvent.__table__,
    ToolCall.__table__,
    SafetyReview.__table__,
    Approval.__table__,
    ActionProposal.__table__,
    ActionSafetyCase.__table__,
    ExecutionRecord.__table__,
    AuditChain.__table__,
    TaskChannelBinding.__table__,
    NotificationOutbox.__table__,
    ConfigBaseline.__table__,
    ConfigBaselineCheck.__table__,
]


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def config_state(path: Path, mode: str) -> dict[str, object]:
    stat_result = path.stat()
    return {
        "path": str(path),
        "resolved_path": str(path),
        "exists": True,
        "file_type": "file",
        "size_bytes": stat_result.st_size,
        "mtime": stat_result.st_mtime,
        "mode": mode,
        "uid": stat_result.st_uid,
        "gid": stat_result.st_gid,
        "sha256": file_sha256(path),
        "hash_truncated": False,
    }


class ConfigModePolicyTest(unittest.TestCase):
    def test_explicit_permission_restore_request_enters_approval_risk(self) -> None:
        review = SafetyEngine.classify_user_text("请将 agent.conf 的权限恢复到确认基线")

        self.assertEqual(review.risk_level.value, "R3")
        self.assertEqual(review.decision.value, "APPROVAL_REQUIRED")

    def test_exact_allowlist_accepts_normal_config_and_denies_protected_path(self) -> None:
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            path = Path(temp_dir) / "agent.conf"
            path.write_text("enabled=true\n", encoding="utf-8")

            self.assertEqual(
                validate_repairable_config_path(str(path), (str(path),)),
                str(path.resolve()),
            )
            with self.assertRaisesRegex(ValueError, "永久保护"):
                validate_repairable_config_path("/etc/ssh/sshd_config", ("/etc/ssh/sshd_config",))

    def test_dynamic_and_execution_policy_reject_unlisted_config(self) -> None:
        configured = SimpleNamespace(
            executor_mode="restricted-local",
            executor_user="opscouncil-agent",
            allow_root_executor=False,
            restartable_systemd_units=(),
            repairable_config_paths=("/tmp/allowed.conf",),
        )
        payload = {
            "path": "/tmp/unlisted.conf",
            "target_mode": "0o640",
            "expected_sha256": "a" * 64,
            "baseline_id": 1,
            "baseline_check_id": 2,
            "dry_run": False,
        }
        with patch("backend.app.safety.engine.settings", configured):
            review = SafetyEngine.classify_tool_action("restore_config_mode", payload)
        with (
            patch.object(policy, "settings", configured),
            patch.object(policy, "current_identity", return_value={"uid": 1001, "user": "opscouncil-agent"}),
        ):
            with self.assertRaises(policy.ExecutionDeniedError):
                policy.authorize_execution("restore_config_mode", "R3", payload)

        self.assertEqual(review.decision.value, "REJECT")
        self.assertEqual(review.risk_level.value, "R4")


class ConfigModeToolTest(unittest.TestCase):
    def test_dry_run_and_execution_preserve_content_and_owner(self) -> None:
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            path = Path(temp_dir) / "agent.conf"
            path.write_text("enabled=true\n", encoding="utf-8")
            os.chmod(path, 0o666)
            before = path.stat()
            expected_hash = file_sha256(path)
            configured = SimpleNamespace(repairable_config_paths=(str(path),))
            payload = {
                "path": str(path),
                "target_mode": "0o640",
                "expected_sha256": expected_hash,
                "baseline_id": 1,
                "baseline_check_id": 2,
            }

            with patch("backend.app.executor.tools.settings", configured):
                dry_run = restore_config_mode(
                    RestoreConfigModeInput(**payload, dry_run=True)
                )
                self.assertEqual(path.stat().st_mode & 0o777, 0o666)
                result = restore_config_mode(
                    RestoreConfigModeInput(**payload, dry_run=False)
                )

            after = path.stat()
            self.assertEqual(after.st_mode & 0o777, 0o640)
            self.assertEqual(after.st_uid, before.st_uid)
            self.assertEqual(after.st_gid, before.st_gid)
            self.assertEqual(file_sha256(path), expected_hash)
            self.assertTrue(result.observations[0]["mode_change_requested"])
            self.assertNotIn("verified", result.observations[0])
            self.assertEqual(dry_run.actions_proposed[0]["operation"], "restore_config_mode")

    def test_content_change_blocks_permission_restore(self) -> None:
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            path = Path(temp_dir) / "agent.conf"
            path.write_text("changed=true\n", encoding="utf-8")
            configured = SimpleNamespace(repairable_config_paths=(str(path),))
            with patch("backend.app.executor.tools.settings", configured):
                with self.assertRaisesRegex(ValueError, "内容哈希"):
                    restore_config_mode(
                        RestoreConfigModeInput(
                            path=str(path),
                            target_mode="0o640",
                            expected_sha256="a" * 64,
                            baseline_id=1,
                            baseline_check_id=2,
                            dry_run=False,
                        )
                    )


class ConfigModeVerificationTest(unittest.TestCase):
    def test_config_mode_uses_config_scan_and_requires_unchanged_hash(self) -> None:
        with TemporaryDirectory(dir="/tmp") as temp_dir:
            path = Path(temp_dir) / "agent.conf"
            path.write_text("enabled=true\n", encoding="utf-8")
            payload = {
                "path": str(path),
                "target_mode": "0o640",
                "expected_sha256": file_sha256(path),
                "baseline_id": 1,
                "baseline_check_id": 2,
                "dry_run": False,
            }
            before = config_state(path, "0o666")
            after = config_state(path, "0o640")
            action_output = {
                "observations": [
                    {
                        "path": str(path),
                        "target_mode": "0o640",
                        "mode_change_requested": True,
                    }
                ]
            }

            self.assertEqual(verification_tool_name("restore_config_mode"), "config_integrity_scan")
            self.assertEqual(
                pre_action_verification_input("restore_config_mode", payload),
                {"paths": [str(path)]},
            )
            self.assertEqual(
                post_action_verification_input("restore_config_mode", payload, action_output),
                {"paths": [str(path)]},
            )
            pre = validate_pre_action_evidence(
                "restore_config_mode",
                payload,
                {"observations": [before]},
            )
            post = validate_post_action_evidence(
                "restore_config_mode",
                payload,
                {"observations": [before]},
                action_output,
                {"observations": [after]},
            )

            self.assertTrue(pre.valid)
            self.assertTrue(post.valid)
            self.assertEqual(post.details["mode_after"], "0o640")


class ConfigModeFlowTest(unittest.TestCase):
    def test_baseline_mode_drift_creates_bound_proposal_and_restores_after_approval(self) -> None:
        lab_root = Path("/tmp/opscouncil-lab")
        lab_root.mkdir(exist_ok=True)
        with TemporaryDirectory(dir=lab_root) as temp_dir:
            path = Path(temp_dir) / "agent.conf"
            path.write_text("enabled=true\n", encoding="utf-8")
            os.chmod(path, 0o640)
            engine = create_engine(
                "sqlite+pysqlite:///:memory:",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                future=True,
            )
            for table in TABLES:
                table.create(engine)
            session = Session(engine, expire_on_commit=False)
            registry = build_perception_registry()
            register_executor_tools(registry)
            baseline = ConfigBaselineService(session, registry).create(
                name="Agent 配置",
                paths=[str(path)],
                created_by="admin",
                scope=LAB_SCOPE,
            )
            os.chmod(path, 0o666)
            task = Task(
                trace_id="trace-config-mode",
                user_input=f"请将 {path} 的权限恢复到已确认基线",
                intent="config_integrity_analysis",
                status="SEALED",
                risk_level="R3",
                summary="等待处置。",
            )
            session.add(task)
            session.flush()
            runner = AgentRunner(session, registry)
            current = registry.call("config_integrity_scan", {"paths": [str(path)]})
            observations = [
                {
                    "tool_name": "config_integrity_scan",
                    "result": current.model_dump(mode="json"),
                }
            ]
            configured = SimpleNamespace(
                executor_mode="restricted-local",
                executor_user="opscouncil-agent",
                allow_root_executor=os.geteuid() == 0,
                restartable_systemd_units=(),
                repairable_config_paths=(str(path),),
                feishu_default_chat_id="",
            )

            with (
                patch("backend.app.agent.runner.settings", configured),
                patch("backend.app.executor.tools.settings", configured),
                patch("backend.app.executor.policy.settings", configured),
                patch("backend.app.safety.engine.settings", configured),
                patch(
                    "backend.app.executor.policy.current_identity",
                    return_value={"uid": path.stat().st_uid, "user": "opscouncil-agent"},
                ),
            ):
                context = runner._create_action_proposals(task, observations)
                proposal = session.scalar(
                    select(ActionProposal).where(ActionProposal.task_id == task.id)
                )
                assert proposal is not None
                runner.approve_and_execute_proposal(proposal.id)

            self.assertEqual(context["path"], str(path))
            self.assertEqual(proposal.input_json["baseline_id"], baseline.id)
            self.assertIsInstance(proposal.input_json["baseline_check_id"], int)
            self.assertEqual(proposal.status, "EXECUTED")
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            calls = list(
                session.scalars(
                    select(ToolCall).where(ToolCall.task_id == task.id).order_by(ToolCall.id)
                )
            )
            self.assertEqual(
                [call.tool_name for call in calls],
                ["config_integrity_scan", "restore_config_mode", "config_integrity_scan"],
            )
            session.close()


if __name__ == "__main__":
    unittest.main()
