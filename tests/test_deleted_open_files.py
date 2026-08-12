from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from backend.app.perception.diagnostic_tools import _scan_deleted_open_files


class DeletedOpenFilesToolTest(unittest.TestCase):
    def test_finds_unlinked_file_still_held_by_current_process(self) -> None:
        file_descriptor, raw_path = tempfile.mkstemp(
            prefix="opscouncil-deleted-open-",
        )
        path = Path(raw_path)
        try:
            os.write(file_descriptor, b"x" * 8192)
            os.fsync(file_descriptor)
            path.unlink()

            rows, scan = _scan_deleted_open_files(
                Path("/proc"),
                limit=10,
                min_size_bytes=1,
                max_processes=1,
                max_fd_scan=1024,
                candidate_pids=[os.getpid()],
            )

            matching = [
                row
                for row in rows
                if row["path"] == raw_path
                and row["pid"] == os.getpid()
            ]
            self.assertEqual(len(matching), 1)
            self.assertGreaterEqual(matching[0]["size_bytes"], 8192)
            self.assertGreaterEqual(matching[0]["open_handle_count"], 1)
            self.assertFalse(scan["scan_truncated"])
        finally:
            os.close(file_descriptor)
            path.unlink(missing_ok=True)

    def test_summary_totals_are_not_limited_by_returned_rows(self) -> None:
        descriptors: list[int] = []
        paths: list[Path] = []
        try:
            for size in (4096, 8192):
                file_descriptor, raw_path = tempfile.mkstemp(
                    prefix="opscouncil-deleted-open-total-",
                )
                descriptors.append(file_descriptor)
                path = Path(raw_path)
                paths.append(path)
                os.write(file_descriptor, b"x" * size)
                os.fsync(file_descriptor)
                path.unlink()

            rows, scan = _scan_deleted_open_files(
                Path("/proc"),
                limit=1,
                min_size_bytes=1,
                max_processes=1,
                max_fd_scan=1024,
                candidate_pids=[os.getpid()],
            )

            self.assertEqual(len(rows), 1)
            self.assertEqual(scan["matched_file_count"], 2)
            self.assertGreaterEqual(scan["retained_bytes_total"], 12288)
            self.assertEqual(scan["open_handle_count_total"], 2)
        finally:
            for file_descriptor in descriptors:
                os.close(file_descriptor)
            for path in paths:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
