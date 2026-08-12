from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch
import unittest

from backend.app.executor import policy


class ExecutionPolicyTest(unittest.TestCase):
    def test_root_runtime_is_denied_by_default(self) -> None:
        with (
            patch.object(policy, "settings", SimpleNamespace(executor_mode="restricted-local", executor_user="opscouncil-agent", allow_root_executor=False)),
            patch.object(policy, "current_identity", return_value={"uid": 0, "user": "root"}),
        ):
            with self.assertRaises(policy.ExecutionDeniedError) as raised:
                policy.authorize_execution("safe_log_rotate", "R2", {"path": "/tmp/opscouncil-lab/logs/app.log"})

        self.assertEqual(raised.exception.context["allowed"], "false")
        self.assertIn("禁止以 root 身份运行", raised.exception.context["reason"])

    def test_restricted_runtime_can_execute_whitelisted_tool(self) -> None:
        with (
            patch.object(policy, "settings", SimpleNamespace(executor_mode="restricted-local", executor_user="opscouncil-agent", allow_root_executor=False)),
            patch.object(policy, "current_identity", return_value={"uid": 1000, "user": "vmuser"}),
        ):
            context = policy.authorize_execution("safe_log_rotate", "R2", {"path": "/tmp/opscouncil-lab/logs/app.log"})

        self.assertEqual(context["allowed"], "true")
        self.assertEqual(context["runtime_user"], "vmuser")

    def test_restricted_runtime_can_restore_approved_backup(self) -> None:
        with (
            patch.object(policy, "settings", SimpleNamespace(executor_mode="restricted-local", executor_user="opscouncil-agent", allow_root_executor=False)),
            patch.object(policy, "current_identity", return_value={"uid": 1000, "user": "vmuser"}),
        ):
            context = policy.authorize_execution(
                "restore_log_backup",
                "R2",
                {
                    "artifact_path": "/tmp/opscouncil-lab/logs/app.log.opscouncil.1234abcd.bak.gz",
                    "restore_target": "/tmp/opscouncil-lab/logs/app.log",
                },
            )

        self.assertEqual(context["allowed"], "true")
        self.assertEqual(context["scope"]["target_path"], "/tmp/opscouncil-lab/logs/app.log")
        self.assertEqual(
            context["scope"]["artifact_path"],
            "/tmp/opscouncil-lab/logs/app.log.opscouncil.1234abcd.bak.gz",
        )


if __name__ == "__main__":
    unittest.main()
