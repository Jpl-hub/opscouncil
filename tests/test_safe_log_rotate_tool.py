from __future__ import annotations

import gzip
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from backend.app.agent.runner import _is_safe_rotation_candidate
from backend.app.executor.tools import (
    RestoreLogBackupInput,
    SafeLogRotateInput,
    _is_protected_path,
    restore_log_backup,
    safe_log_rotate,
)


class SafeLogRotateToolTest(unittest.TestCase):
    def test_dry_run_does_not_modify_source_file(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            path = Path(tmp) / "app.log"
            path.write_text("important log\n" * 16, encoding="utf-8")
            original_size = path.stat().st_size

            result = safe_log_rotate(SafeLogRotateInput(path=str(path), dry_run=True))

            self.assertEqual(path.stat().st_size, original_size)
            self.assertEqual(result.status, "ok")
            self.assertEqual(result.observations[0]["estimated_reclaim_bytes"], original_size)
            self.assertTrue(result.observations[0]["source_will_be_truncated"])
            self.assertEqual(result.actions_proposed[0]["rollback_strategy"], "restore_backup")

    def test_execute_backs_up_and_truncates_source_file(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            path = Path(tmp) / "app.log"
            content = "large log line\n" * 128
            path.write_text(content, encoding="utf-8")
            original_size = path.stat().st_size

            result = safe_log_rotate(SafeLogRotateInput(path=str(path), dry_run=False, compress=True))

            artifact = Path(result.artifacts[0]["path"])
            self.assertEqual(path.stat().st_size, 0)
            self.assertTrue(artifact.exists())
            self.assertEqual(result.observations[0]["reclaimed_bytes"], original_size)
            self.assertTrue(result.observations[0]["source_truncated"])
            self.assertEqual(result.artifacts[0]["restore_target"], str(path))
            with gzip.open(artifact, "rt", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), content)

    def test_protected_journal_paths_are_never_rotation_candidates(self) -> None:
        journal_path = Path("/var/log/journal/machine/system.journal")

        self.assertTrue(_is_protected_path(journal_path))
        self.assertFalse(_is_safe_rotation_candidate(str(journal_path)))
        self.assertFalse(_is_safe_rotation_candidate("/var/log/postgresql/postgresql-16-main.log"))
        self.assertTrue(_is_safe_rotation_candidate("/tmp/opscouncil-lab/logs/app-large.log"))
        self.assertTrue(_is_safe_rotation_candidate("/var/log/nginx/access.log"))

    def test_restore_dry_run_does_not_modify_target(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            target = Path(tmp) / "app.log"
            target.write_text("", encoding="utf-8")
            artifact = Path(tmp) / "app.log.opscouncil.1234abcd.bak.gz"
            with gzip.open(artifact, "wt", encoding="utf-8") as handle:
                handle.write("original log\n")

            result = restore_log_backup(
                RestoreLogBackupInput(
                    artifact_path=str(artifact),
                    restore_target=str(target),
                    dry_run=True,
                )
            )

            self.assertEqual(target.read_text(encoding="utf-8"), "")
            self.assertEqual(result.observations[0]["restore_bytes"], len("original log\n".encode()))
            self.assertEqual(result.actions_proposed[0]["operation"], "restore_log_backup")
            self.assertIn("dry-run", result.warnings[0])

    def test_restore_recovers_backup_and_preserves_current_target(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            target = Path(tmp) / "app.log"
            target.write_text("new log after rotation\n", encoding="utf-8")
            artifact = Path(tmp) / "app.log.opscouncil.1234abcd.bak.gz"
            with gzip.open(artifact, "wt", encoding="utf-8") as handle:
                handle.write("original log before rotation\n")

            result = restore_log_backup(
                RestoreLogBackupInput(
                    artifact_path=str(artifact),
                    restore_target=str(target),
                    dry_run=False,
                )
            )

            self.assertEqual(target.read_text(encoding="utf-8"), "original log before rotation\n")
            snapshot = Path(result.artifacts[0]["path"])
            self.assertTrue(snapshot.exists())
            with gzip.open(snapshot, "rt", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "new log after rotation\n")
            self.assertTrue(result.observations[0]["restored"])

    def test_restore_rejects_artifact_that_does_not_match_target(self) -> None:
        with TemporaryDirectory(dir="/tmp") as tmp:
            target = Path(tmp) / "app.log"
            target.write_text("current\n", encoding="utf-8")
            artifact = Path(tmp) / "other.log.opscouncil.1234abcd.bak.gz"
            with gzip.open(artifact, "wt", encoding="utf-8") as handle:
                handle.write("untrusted\n")

            with self.assertRaises(ValueError):
                restore_log_backup(
                    RestoreLogBackupInput(
                        artifact_path=str(artifact),
                        restore_target=str(target),
                        dry_run=False,
                    )
                )

            self.assertEqual(target.read_text(encoding="utf-8"), "current\n")


if __name__ == "__main__":
    unittest.main()
