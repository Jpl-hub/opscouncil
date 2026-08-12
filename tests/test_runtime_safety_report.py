from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch
import unittest

from backend.app.executor import runtime


class RuntimeSafetyReportTest(unittest.TestCase):
    def test_report_blocks_side_effects_when_service_runs_as_root(self) -> None:
        with (
            patch.object(
                runtime,
                "settings",
                SimpleNamespace(
                    executor_mode="restricted-local",
                    executor_user="opscouncil-agent",
                    allow_root_executor=False,
                ),
            ),
            patch.object(runtime, "current_identity", return_value={"uid": 0, "user": "root"}),
        ):
            report = runtime.runtime_safety_report()

        self.assertEqual(report["overall_status"], "blocked")
        self.assertFalse(report["executor"]["action_execution_enabled"])
        self.assertEqual(report["guards"][0]["status"], "blocked")
        self.assertIn("/var/log/journal/", report["boundary"]["protected_path_prefixes"])

    def test_report_marks_restricted_identity_as_ready(self) -> None:
        with (
            patch.object(
                runtime,
                "settings",
                SimpleNamespace(
                    executor_mode="restricted-local",
                    executor_user="opscouncil-agent",
                    allow_root_executor=False,
                ),
            ),
            patch.object(runtime, "current_identity", return_value={"uid": 1001, "user": "opscouncil-agent"}),
        ):
            report = runtime.runtime_safety_report()

        self.assertEqual(report["overall_status"], "ok")
        self.assertTrue(report["executor"]["action_execution_enabled"])
        self.assertEqual(report["executor"]["runtime_user"], "opscouncil-agent")
        self.assertEqual(
            report["boundary"]["allowed_tools"],
            ["restore_log_backup", "safe_log_rotate"],
        )

    def test_report_exposes_service_restart_only_when_an_exact_unit_is_configured(self) -> None:
        with (
            patch.object(
                runtime,
                "settings",
                SimpleNamespace(
                    executor_mode="restricted-local",
                    executor_user="opscouncil-agent",
                    allow_root_executor=False,
                    restartable_systemd_units=("demo-worker.service",),
                ),
            ),
            patch.object(runtime, "current_identity", return_value={"uid": 1001, "user": "opscouncil-agent"}),
        ):
            report = runtime.runtime_safety_report()

        self.assertIn("restart_managed_service", report["boundary"]["allowed_tools"])
        self.assertEqual(report["boundary"]["restartable_units"], ["demo-worker.service"])

    def test_report_disables_service_restart_when_config_contains_a_protected_unit(self) -> None:
        with (
            patch.object(
                runtime,
                "settings",
                SimpleNamespace(
                    executor_mode="restricted-local",
                    executor_user="opscouncil-agent",
                    allow_root_executor=False,
                    restartable_systemd_units=("sshd.service",),
                ),
            ),
            patch.object(runtime, "current_identity", return_value={"uid": 1001, "user": "opscouncil-agent"}),
        ):
            report = runtime.runtime_safety_report()

        self.assertEqual(report["overall_status"], "warn")
        self.assertNotIn("restart_managed_service", report["boundary"]["allowed_tools"])
        self.assertEqual(report["boundary"]["restartable_units"], [])

    def test_report_exposes_config_restore_only_for_an_exact_safe_path(self) -> None:
        with (
            patch.object(
                runtime,
                "settings",
                SimpleNamespace(
                    executor_mode="restricted-local",
                    executor_user="opscouncil-agent",
                    allow_root_executor=False,
                    repairable_config_paths=("/opt/opscouncil/config/agent.conf",),
                ),
            ),
            patch.object(runtime, "current_identity", return_value={"uid": 1001, "user": "opscouncil-agent"}),
        ):
            report = runtime.runtime_safety_report()

        self.assertIn("restore_config_mode", report["boundary"]["allowed_tools"])
        self.assertEqual(
            report["boundary"]["repairable_config_paths"],
            ["/opt/opscouncil/config/agent.conf"],
        )

    def test_report_disables_config_restore_for_a_protected_path(self) -> None:
        with (
            patch.object(
                runtime,
                "settings",
                SimpleNamespace(
                    executor_mode="restricted-local",
                    executor_user="opscouncil-agent",
                    allow_root_executor=False,
                    repairable_config_paths=("/etc/ssh/sshd_config",),
                ),
            ),
            patch.object(runtime, "current_identity", return_value={"uid": 1001, "user": "opscouncil-agent"}),
        ):
            report = runtime.runtime_safety_report()

        self.assertEqual(report["overall_status"], "warn")
        self.assertNotIn("restore_config_mode", report["boundary"]["allowed_tools"])
        self.assertEqual(report["boundary"]["repairable_config_paths"], [])


if __name__ == "__main__":
    unittest.main()
