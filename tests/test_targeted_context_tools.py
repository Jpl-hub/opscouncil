from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from backend.app.perception.context_tools import (
    FilesystemMountContextInput,
    SocketProcessContextInput,
    _collect_socket_process_context,
    _read_filesystem_mount_context,
    build_context_tool_definitions,
)
from backend.app.perception.socket_inventory import parse_network_listener_line
from backend.app.schemas.enums import RiskLevel


class SocketProcessContextTest(unittest.TestCase):
    def test_listener_parser_keeps_service_attribution_without_cgroup_path(self) -> None:
        observation = parse_network_listener_line(
            'tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* '
            'users:(("gateway",pid=42,fd=7)) uid:1001 ino:777 '
            "cgroup:/system.slice/gateway.service"
        )

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual(observation["pid"], 42)
        self.assertEqual(observation["systemd_unit"], "gateway.service")
        self.assertEqual(observation["exposure_scope"], "wildcard")
        self.assertNotIn("cgroup_path", observation)

    @patch("backend.app.perception.context_tools.shutil.which", return_value="/usr/sbin/ss")
    @patch("backend.app.perception.context_tools.subprocess.run")
    def test_targeted_socket_context_resolves_unattributed_inode_from_procfs(
        self,
        run_mock,
        _which_mock,
    ) -> None:  # type: ignore[no-untyped-def]
        run_mock.return_value = SimpleNamespace(
            stdout=(
                "tcp LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* "
                "uid:1000 ino:777 cgroup:/\n"
            ),
            stderr="",
            returncode=0,
        )
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            proc_root = Path(directory)
            process = proc_root / "42"
            fd_dir = process / "fd"
            fd_dir.mkdir(parents=True)
            (process / "status").write_text(
                "Name:\tuvicorn\nUid:\t1000\t1000\t1000\t1000\n",
                encoding="utf-8",
            )
            (process / "comm").write_text("uvicorn\n", encoding="utf-8")
            (process / "cgroup").write_text(
                "0::/system.slice/opscouncil.service\n",
                encoding="utf-8",
            )
            os.symlink("socket:[777]", fd_dir / "7")

            result = _collect_socket_process_context(
                SocketProcessContextInput(protocol="TCP", port=8000),
                proc_root=proc_root,
            )

        self.assertEqual(result.status, "ok")
        observation = result.observations[0]
        self.assertEqual(observation["listener_count"], 1)
        self.assertEqual(observation["unattributed_count"], 0)
        listener = observation["listeners"][0]
        self.assertEqual(listener["pid"], 42)
        self.assertEqual(listener["process_name"], "uvicorn")
        self.assertEqual(listener["systemd_unit"], "opscouncil.service")
        self.assertEqual(listener["attribution_source"], "procfs")
        self.assertNotIn("cmdline", listener)

    @patch("backend.app.perception.context_tools.shutil.which", return_value="/usr/sbin/ss")
    @patch("backend.app.perception.context_tools.subprocess.run")
    def test_targeted_socket_context_filters_protocol(
        self,
        run_mock,
        _which_mock,
    ) -> None:  # type: ignore[no-untyped-def]
        run_mock.return_value = SimpleNamespace(
            stdout="udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* ino:9 cgroup:/\n",
            stderr="",
            returncode=0,
        )

        result = _collect_socket_process_context(
            SocketProcessContextInput(protocol="tcp", port=53),
            proc_root=Path("/proc"),
        )

        self.assertEqual(result.observations[0]["listener_count"], 0)

    @patch("backend.app.perception.context_tools.shutil.which", return_value="/usr/sbin/ss")
    @patch("backend.app.perception.context_tools.subprocess.run")
    def test_known_pid_metadata_does_not_claim_proc_fd_scan(
        self,
        run_mock,
        _which_mock,
    ) -> None:  # type: ignore[no-untyped-def]
        run_mock.return_value = SimpleNamespace(
            stdout=(
                'tcp LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* '
                'users:(("uvicorn",pid=42,fd=7)) ino:777 cgroup:/\n'
            ),
            stderr="",
            returncode=0,
        )
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            proc_root = Path(directory)
            process = proc_root / "42"
            process.mkdir()
            (process / "status").write_text(
                "Name:\tuvicorn\nUid:\t12345\t12345\t12345\t12345\n",
                encoding="utf-8",
            )
            (process / "comm").write_text("uvicorn\n", encoding="utf-8")
            (process / "cgroup").write_text("0::/\n", encoding="utf-8")

            result = _collect_socket_process_context(
                SocketProcessContextInput(protocol="tcp", port=8000),
                proc_root=proc_root,
            )

        listener = result.observations[0]["listeners"][0]
        self.assertEqual(listener["user"], "12345")
        self.assertIn("/proc/<pid>/status", result.evidence_refs)
        self.assertNotIn("/proc/*/fd", result.evidence_refs)

    def test_socket_input_enforces_protocol_and_port_bounds(self) -> None:
        with self.assertRaises(ValueError):
            SocketProcessContextInput(protocol="sctp", port=80)
        with self.assertRaises(ValueError):
            SocketProcessContextInput(protocol="tcp", port=0)


class FilesystemMountContextTest(unittest.TestCase):
    @patch("backend.app.perception.context_tools.shutil.disk_usage")
    @patch("backend.app.perception.context_tools.subprocess.run")
    @patch("backend.app.perception.context_tools.shutil.which", return_value="/usr/bin/findmnt")
    def test_mount_context_uses_json_and_removes_sensitive_options(
        self,
        _which_mock,
        run_mock,
        disk_usage_mock,
    ) -> None:  # type: ignore[no-untyped-def]
        run_mock.return_value = SimpleNamespace(
            stdout=json.dumps(
                {
                    "filesystems": [
                        {
                            "target": "/srv",
                            "source": "//ops:secret@fileserver/logs",
                            "fstype": "cifs",
                            "options": (
                                "rw,nosuid,nodev,noexec,credentials=/root/share,username=ops,"
                                "password=secret,relatime"
                            ),
                            "fsroot": "/",
                        }
                    ]
                }
            ),
            stderr="",
            returncode=0,
        )
        disk_usage_mock.return_value = SimpleNamespace(total=1000, used=900, free=100)
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            result = _read_filesystem_mount_context(directory)

        self.assertEqual(result.status, "ok")
        observation = result.observations[0]
        self.assertEqual(observation["source"], "//<redacted>@fileserver/logs")
        self.assertEqual(
            observation["mount_options"],
            ["rw", "nosuid", "nodev", "noexec", "relatime"],
        )
        self.assertTrue(observation["is_network_filesystem"])
        self.assertTrue(observation["nosuid"])
        self.assertTrue(observation["nodev"])
        self.assertTrue(observation["noexec"])
        self.assertEqual(observation["used_percent"], 90.0)
        serialized = json.dumps(observation)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("credentials", serialized)

    def test_mount_input_rejects_relative_paths(self) -> None:
        with self.assertRaises(ValueError):
            FilesystemMountContextInput(path="var/log")

    def test_context_tool_definitions_are_read_only(self) -> None:
        definitions = {tool.name: tool for tool in build_context_tool_definitions()}

        self.assertEqual(definitions["socket_process_context"].risk_level, RiskLevel.R0)
        self.assertEqual(definitions["filesystem_mount_context"].risk_level, RiskLevel.R0)
        self.assertEqual(definitions["filesystem_mount_context"].version, "1.0.0")


if __name__ == "__main__":
    unittest.main()
