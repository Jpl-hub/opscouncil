from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from backend.app.perception.tools import _parse_psi_text, _read_io_activity, build_perception_registry


class PatrolPerceptionToolsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = build_perception_registry()

    def test_disk_usage_returns_capacity_and_inode_pressure(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            result = self.registry.call("disk_usage", {"paths": [directory]})

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        observation = result.observations[0]
        self.assertGreater(observation["inode_total"], 0)
        self.assertGreaterEqual(observation["inode_used"], 0)
        self.assertGreaterEqual(observation["inode_free"], 0)
        self.assertGreaterEqual(observation["inode_used_percent"], 0.0)
        self.assertLessEqual(observation["inode_used_percent"], 100.0)
        self.assertTrue(any(ref.startswith("statvfs:") for ref in result.evidence_refs))

    def test_parses_linux_psi_without_returning_raw_content(self) -> None:
        parsed = _parse_psi_text(
            "some avg10=1.25 avg60=2.50 avg300=3.75 total=12345\n"
            "full avg10=0.10 avg60=0.20 avg300=0.30 total=456\n"
        )

        self.assertEqual(parsed["some"]["avg10"], 1.25)
        self.assertEqual(parsed["some"]["total_us"], 12345)
        self.assertEqual(parsed["full"]["avg300"], 0.30)
        self.assertNotIn("raw", parsed)

    def test_reads_bounded_procfs_io_activity_without_raw_device_rows(self) -> None:
        values = _read_io_activity()

        self.assertTrue("iowait_ticks" in values or "device_count" in values)
        self.assertNotIn("raw", values)
        if "device_count" in values:
            self.assertGreater(values["device_count"], 0)
            self.assertGreaterEqual(values["read_ios"], 0)
            self.assertGreaterEqual(values["write_ios"], 0)

    def test_time_sync_status_returns_bounded_structured_state(self) -> None:
        completed = SimpleNamespace(
            stdout=(
                "NTPSynchronized=yes\n"
                "NTP=yes\n"
                "Timezone=Asia/Shanghai\n"
                "LocalRTC=no\n"
            ),
            stderr="",
            returncode=0,
        )
        with (
            patch("backend.app.perception.tools.shutil.which", return_value="/usr/bin/timedatectl"),
            patch("backend.app.perception.tools.subprocess.run", return_value=completed) as run,
        ):
            result = self.registry.call("time_sync_status", {})

        self.assertEqual(result.status, "ok")
        self.assertEqual(
            result.observations,
            [
                {
                    "ntp_synchronized": True,
                    "ntp_enabled": True,
                    "timezone": "Asia/Shanghai",
                    "local_rtc": False,
                }
            ],
        )
        command = run.call_args.args[0]
        self.assertEqual(command[0], "timedatectl")
        self.assertIn("NTPSynchronized", " ".join(command))
        self.assertNotIn(completed.stdout, str(result.model_dump()))

    def test_time_sync_status_is_explicitly_unavailable_without_timedatectl(self) -> None:
        with patch("backend.app.perception.tools.shutil.which", return_value=None):
            result = self.registry.call("time_sync_status", {})

        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.observations, [])
        self.assertIn("timedatectl not found", result.warnings)

    def test_large_file_scan_does_not_accept_a_parent_of_allowed_roots(self) -> None:
        result = self.registry.call(
            "find_large_files",
            {"roots": ["/"], "limit": 20, "min_size_mb": 10},
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.observations, [])
        self.assertTrue(any("outside allowed read-only scan scope" in warning for warning in result.warnings))

    def test_large_file_scan_binds_each_observation_to_its_real_path(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            candidate = Path(directory) / "application.log"
            with candidate.open("wb") as handle:
                handle.truncate(1024 * 1024)
            result = self.registry.call(
                "find_large_files",
                {"roots": [directory], "limit": 20, "min_size_mb": 1},
            )

        self.assertEqual([item["path"] for item in result.observations], [str(candidate)])
        self.assertEqual(result.evidence_refs, [str(candidate)])
        self.assertEqual(result.summary_fields["scan_roots"], [directory])


if __name__ == "__main__":
    unittest.main()
