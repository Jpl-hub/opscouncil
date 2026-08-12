from __future__ import annotations

from pathlib import Path
import re
import unittest

from backend.app.lab.service import LabService
from backend.app.perception.tools import build_perception_registry


class ConfigIntegrityToolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = build_perception_registry()

    def test_scans_allowlisted_config_without_returning_file_content(self) -> None:
        result = self.registry.call("config_integrity_scan", {"paths": ["/etc/hosts"]})

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        observation = result.observations[0]

        self.assertEqual(observation["path"], "/etc/hosts")
        self.assertIn("size_bytes", observation)
        self.assertIn("mode", observation)
        self.assertIn("mtime", observation)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", observation["sha256"]))
        self.assertNotIn("content", observation)
        self.assertNotIn("lines", observation)

    def test_records_allowlisted_symlink_metadata_without_following_out_of_scope_target(self) -> None:
        resolv_conf = Path("/etc/resolv.conf")
        if not resolv_conf.is_symlink():
            self.skipTest("/etc/resolv.conf is not a symlink on this host")

        result = self.registry.call("config_integrity_scan", {"paths": ["/etc/resolv.conf"]})

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.observations), 1)
        observation = result.observations[0]

        self.assertEqual(observation["path"], "/etc/resolv.conf")
        self.assertEqual(observation["file_type"], "symlink")
        self.assertIn("link_target_sha256", observation)
        self.assertNotIn("content", observation)
        self.assertNotIn("lines", observation)

    def test_skips_sensitive_and_out_of_scope_paths(self) -> None:
        result = self.registry.call(
            "config_integrity_scan",
            {"paths": ["/etc/shadow", "/root/.ssh/id_rsa"]},
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.observations, [])
        warnings = "\n".join(result.warnings)
        self.assertIn("protected config path skipped", warnings)
        self.assertIn("outside allowed config scan scope", warnings)

    def test_scans_controlled_lab_config_without_returning_content(self) -> None:
        service = LabService()
        service.reset("config-drift-sample")
        try:
            ready = service.activate("config-drift-sample")

            result = self.registry.call("config_integrity_scan", {"paths": [ready["artifact_path"]]})

            self.assertEqual(result.status, "ok")
            self.assertEqual(len(result.observations), 1)
            observation = result.observations[0]
            self.assertEqual(observation["path"], ready["artifact_path"])
            self.assertTrue(observation["exists"])
            self.assertEqual(observation["file_type"], "file")
            self.assertEqual(observation["mode"], "0o666")
            self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", observation["sha256"]))
            self.assertNotIn("content", observation)
            self.assertNotIn("lines", observation)
        finally:
            service.reset("config-drift-sample")


if __name__ == "__main__":
    unittest.main()
