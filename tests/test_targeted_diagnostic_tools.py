from __future__ import annotations

import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from backend.app.perception.diagnostic_tools import (
    JournalStorageStatusInput,
    ProcessRuntimeDetailInput,
    _parse_journal_disk_usage,
    _parse_journald_settings,
    _read_process_runtime,
    _scan_journal_directory,
    build_diagnostic_tool_definitions,
    journal_storage_status,
)
from backend.app.schemas.enums import RiskLevel


class ProcessRuntimeDetailTest(unittest.TestCase):
    def test_proc_reader_returns_bounded_runtime_facts_without_fd_targets(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            proc_root = Path(directory)
            process = proc_root / "321"
            fd_dir = process / "fd"
            fd_dir.mkdir(parents=True)
            (process / "status").write_text(
                "\n".join(
                    [
                        "Name:\tdemo-api",
                        "State:\tS (sleeping)",
                        "PPid:\t12",
                        "Uid:\t1000\t1000\t1000\t1000",
                        "Gid:\t1000\t1000\t1000\t1000",
                        "Threads:\t7",
                        "VmRSS:\t2048 kB",
                        "VmSize:\t8192 kB",
                        "voluntary_ctxt_switches:\t33",
                        "nonvoluntary_ctxt_switches:\t4",
                    ]
                ),
                encoding="utf-8",
            )
            (process / "limits").write_text(
                "Limit                     Soft Limit           Hard Limit           Units\n"
                "Max open files            1024                 4096                 files\n"
                "Max processes             2048                 4096                 processes\n",
                encoding="utf-8",
            )
            (process / "cgroup").write_text(
                "0::/system.slice/demo-api.service\n",
                encoding="utf-8",
            )
            (process / "stat").write_text(
                "321 (demo-api) S 12 1 1 0 -1 0 0 0 0 0 1 2 0 0 20 0 7 0 987654 0 0\n",
                encoding="utf-8",
            )
            executable = proc_root / "demo-api-bin"
            executable.write_bytes(b"binary")
            os.symlink(executable, process / "exe")
            regular = proc_root / "app.log"
            regular.write_text("log", encoding="utf-8")
            os.symlink(regular, fd_dir / "1")
            os.symlink("socket:[100]", fd_dir / "2")
            os.symlink("pipe:[200]", fd_dir / "3")
            os.symlink("anon_inode:[eventpoll]", fd_dir / "4")

            observation, warnings = _read_process_runtime(321, proc_root=proc_root, max_fd_scan=50)

            self.assertEqual(warnings, [])
            self.assertTrue(observation["exists"])
            self.assertEqual(observation["pid"], 321)
            self.assertEqual(observation["name"], "demo-api")
            self.assertEqual(observation["systemd_unit"], "demo-api.service")
            self.assertEqual(observation["max_open_files_soft"], 1024)
            self.assertEqual(observation["open_fd_count"], 4)
            self.assertEqual(observation["fd_type_counts"]["socket"], 1)
            self.assertEqual(observation["fd_type_counts"]["pipe"], 1)
            self.assertEqual(observation["fd_type_counts"]["anon_inode"], 1)
            self.assertNotIn("fd_targets", observation)
            self.assertNotIn("cmdline", observation)
            self.assertNotIn("environment", observation)

    def test_missing_process_is_explicit_observation(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            observation, warnings = _read_process_runtime(
                999999,
                proc_root=Path(directory),
                max_fd_scan=10,
            )

            self.assertFalse(observation["exists"])
            self.assertTrue(warnings)

    def test_process_input_bounds_pid_and_fd_scan(self) -> None:
        with self.assertRaises(ValueError):
            ProcessRuntimeDetailInput(pid=0)
        with self.assertRaises(ValueError):
            ProcessRuntimeDetailInput(pid=1, max_fd_scan=50001)


class JournalStorageStatusTest(unittest.TestCase):
    def test_disk_usage_parser_uses_binary_units(self) -> None:
        self.assertEqual(
            _parse_journal_disk_usage(
                "Archived and active journals take up 24.0M in the file system."
            ),
            24 * 1024 * 1024,
        )
        self.assertIsNone(_parse_journal_disk_usage("unrecognized output"))

    def test_journald_parser_returns_only_whitelisted_effective_settings(self) -> None:
        settings = _parse_journald_settings(
            """
            # /usr/lib/systemd/journald.conf
            [Journal]
            Storage=auto
            SystemMaxUse=1G
            ForwardToSyslog=yes
            # /etc/systemd/journald.conf.d/override.conf
            [Journal]
            Storage=persistent
            SystemMaxUse=512M
            """
        )

        self.assertEqual(settings["Storage"], "persistent")
        self.assertEqual(settings["SystemMaxUse"], "512M")
        self.assertNotIn("ForwardToSyslog", settings)

    def test_directory_scan_separates_active_and_archived_files(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            (root / "system.journal").write_bytes(b"a" * 10)
            (root / "system@old.journal~").write_bytes(b"b" * 20)

            result, warnings = _scan_journal_directory(root, max_files=100)

            self.assertEqual(warnings, [])
            self.assertEqual(result["total_bytes"], 30)
            self.assertEqual(result["active_file_count"], 1)
            self.assertEqual(result["archived_file_count"], 1)
            self.assertFalse(result["scan_truncated"])

    @patch("backend.app.perception.diagnostic_tools.shutil.which", return_value="/usr/bin/tool")
    @patch("backend.app.perception.diagnostic_tools.subprocess.run")
    def test_journal_tool_combines_command_and_filesystem_facts(
        self,
        run_mock,
        _which_mock,
    ) -> None:  # type: ignore[no-untyped-def]
        run_mock.side_effect = [
            SimpleNamespace(
                stdout="Archived and active journals take up 8.0M in the file system.\n",
                stderr="",
                returncode=0,
            ),
            SimpleNamespace(
                stdout="[Journal]\nStorage=persistent\nSystemMaxUse=512M\n",
                stderr="",
                returncode=0,
            ),
        ]
        with tempfile.TemporaryDirectory(dir="/tmp") as persistent:
            root = Path(persistent)
            (root / "system.journal").write_bytes(b"x" * 32)
            with patch(
                "backend.app.perception.diagnostic_tools.JOURNAL_PATHS",
                (("persistent", root),),
            ):
                result = journal_storage_status(JournalStorageStatusInput(max_files=100))

        self.assertEqual(result.status, "ok")
        observation = result.observations[0]
        self.assertEqual(observation["reported_disk_usage_bytes"], 8 * 1024 * 1024)
        self.assertEqual(observation["settings"]["Storage"], "persistent")
        self.assertEqual(observation["settings_status"], "explicit_settings_found")
        self.assertEqual(observation["storage"][0]["total_bytes"], 32)
        self.assertNotIn("config_text", observation)

    @patch("backend.app.perception.diagnostic_tools.shutil.which", return_value="/usr/bin/tool")
    @patch("backend.app.perception.diagnostic_tools.subprocess.run")
    def test_journal_tool_applies_one_file_limit_across_all_storage_roots(
        self,
        run_mock,
        _which_mock,
    ) -> None:  # type: ignore[no-untyped-def]
        run_mock.side_effect = [
            SimpleNamespace(stdout="Journals take up 2.0M.\n", stderr="", returncode=0),
            SimpleNamespace(stdout="[Journal]\nStorage=auto\n", stderr="", returncode=0),
        ]
        with (
            tempfile.TemporaryDirectory(dir="/tmp") as persistent,
            tempfile.TemporaryDirectory(dir="/tmp") as runtime,
        ):
            persistent_root = Path(persistent)
            runtime_root = Path(runtime)
            (persistent_root / "system.journal").write_bytes(b"x")
            (runtime_root / "system.journal").write_bytes(b"y")
            with patch(
                "backend.app.perception.diagnostic_tools.JOURNAL_PATHS",
                (("persistent", persistent_root), ("runtime", runtime_root)),
            ):
                result = journal_storage_status(JournalStorageStatusInput(max_files=1))

        storage = result.observations[0]["storage"]
        self.assertEqual(sum(item["scanned_file_count"] for item in storage), 1)
        self.assertTrue(storage[1]["scan_truncated"])

    def test_tool_definitions_are_read_only_and_bounded(self) -> None:
        definitions = {tool.name: tool for tool in build_diagnostic_tool_definitions()}

        self.assertEqual(definitions["process_runtime_detail"].risk_level, RiskLevel.R0)
        self.assertEqual(definitions["journal_storage_status"].risk_level, RiskLevel.R0)
        self.assertEqual(definitions["process_runtime_detail"].version, "1.0.0")


if __name__ == "__main__":
    unittest.main()
