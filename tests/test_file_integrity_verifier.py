from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
import tempfile
import unittest

from backend.app.executor.verification import (
    FileIntegrityStateInput,
    file_integrity_state,
    register_file_integrity_verifier,
)
from backend.app.mcp.registry import ToolRegistry
from backend.app.schemas.enums import RiskLevel


class FileIntegrityVerifierTest(unittest.TestCase):
    def test_raw_file_returns_metadata_and_hash_without_content(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "app.log"
            content = b"first line\nsecond line\n"
            path.write_bytes(content)

            result = file_integrity_state(
                FileIntegrityStateInput(paths=[str(path)], max_bytes=4096)
            )

            self.assertEqual(result.status, "ok")
            self.assertEqual(len(result.observations), 1)
            observation = result.observations[0]
            self.assertEqual(observation["path"], str(path.resolve()))
            self.assertEqual(observation["size_bytes"], len(content))
            self.assertEqual(observation["sha256"], hashlib.sha256(content).hexdigest())
            self.assertFalse(observation["hash_truncated"])
            self.assertNotIn("content", observation)

    def test_gzip_artifact_returns_bounded_uncompressed_hash(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "app.log.backup.gz"
            content = b"verified backup content\n" * 100
            with gzip.open(path, "wb") as stream:
                stream.write(content)

            result = file_integrity_state(
                FileIntegrityStateInput(paths=[str(path)], max_bytes=1024 * 1024)
            )

            observation = result.observations[0]
            self.assertTrue(observation["gzip_valid"])
            self.assertEqual(
                observation["content_sha256"],
                hashlib.sha256(content).hexdigest(),
            )
            self.assertEqual(observation["content_size_bytes"], len(content))
            self.assertFalse(observation["content_hash_truncated"])

    def test_hashing_stops_at_bound_and_marks_truncation(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "large.log"
            content = b"x" * 8192
            path.write_bytes(content)

            result = file_integrity_state(
                FileIntegrityStateInput(paths=[str(path)], max_bytes=4096)
            )

            observation = result.observations[0]
            self.assertTrue(observation["hash_truncated"])
            self.assertEqual(observation["hashed_bytes"], 4096)
            self.assertEqual(
                observation["sha256"],
                hashlib.sha256(content[:4096]).hexdigest(),
            )

    def test_protected_or_out_of_scope_paths_are_rejected(self) -> None:
        for path in ("/etc/hosts", "/var/log/journal/system.journal"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    FileIntegrityStateInput(paths=[path])

    def test_malformed_gzip_is_explicit_partial_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "broken.gz"
            path.write_bytes(b"not a gzip stream")

            result = file_integrity_state(FileIntegrityStateInput(paths=[str(path)]))

            self.assertEqual(result.status, "partial")
            self.assertFalse(result.observations[0]["gzip_valid"])
            self.assertTrue(any("gzip" in warning.lower() for warning in result.warnings))

    def test_registry_exposes_one_read_only_verifier(self) -> None:
        registry = ToolRegistry()

        register_file_integrity_verifier(registry)

        tool = registry.get("file_integrity_state")
        self.assertEqual(tool.risk_level, RiskLevel.R0)
        self.assertEqual(tool.version, "1.0.0")


if __name__ == "__main__":
    unittest.main()
