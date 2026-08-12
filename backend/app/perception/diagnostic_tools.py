from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Any

from backend.app.core.pydantic_compat import BaseModel, Field
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.schemas.enums import RiskLevel


JOURNAL_PATHS = (
    ("persistent", Path("/var/log/journal")),
    ("runtime", Path("/run/log/journal")),
)

_JOURNAL_SETTING_KEYS = {
    "Storage",
    "Compress",
    "Seal",
    "SystemMaxUse",
    "SystemKeepFree",
    "SystemMaxFileSize",
    "SystemMaxFiles",
    "RuntimeMaxUse",
    "RuntimeKeepFree",
    "RuntimeMaxFileSize",
    "RuntimeMaxFiles",
    "MaxRetentionSec",
    "MaxFileSec",
    "RateLimitIntervalSec",
    "RateLimitBurst",
}


class ProcessRuntimeDetailInput(BaseModel):
    pid: int = Field(ge=1, le=4194304)
    max_fd_scan: int = Field(default=20000, ge=1, le=50000)


class JournalStorageStatusInput(BaseModel):
    max_files: int = Field(default=10000, ge=1, le=20000)


class DeletedOpenFilesInput(BaseModel):
    limit: int = Field(default=30, ge=1, le=100)
    min_size_mb: int = Field(default=1, ge=0, le=10240)
    max_processes: int = Field(default=8192, ge=1, le=65536)
    max_fd_scan: int = Field(default=50000, ge=1, le=200000)


def process_runtime_detail(payload: BaseModel) -> ToolResult:
    args = ProcessRuntimeDetailInput.model_validate(payload)
    observation, warnings = _read_process_runtime(
        args.pid,
        proc_root=Path("/proc"),
        max_fd_scan=args.max_fd_scan,
    )
    evidence_refs = [
        f"/proc/{args.pid}/status",
        f"/proc/{args.pid}/limits",
        f"/proc/{args.pid}/fd",
        f"/proc/{args.pid}/cgroup",
        f"/proc/{args.pid}/stat",
    ]
    return ToolResult(
        status="unavailable" if not observation.get("exists") else "partial" if warnings else "ok",
        observations=[observation],
        warnings=warnings[:10],
        evidence_refs=evidence_refs,
    )


def _read_process_runtime(
    pid: int,
    *,
    proc_root: Path,
    max_fd_scan: int,
) -> tuple[dict[str, Any], list[str]]:
    process = proc_root / str(pid)
    if not process.exists():
        return {"pid": pid, "exists": False}, [f"process not found: {pid}"]

    warnings: list[str] = []
    status_values = _read_key_value_file(process / "status", warnings)
    limits = read_process_limits(process / "limits", warnings)
    fd_counts, scanned_fds, fd_scan_truncated = _read_fd_types(
        process / "fd",
        max_fd_scan,
        warnings,
    )
    systemd_unit, container_hint = _read_cgroup_identity(process / "cgroup", warnings)
    executable_path, executable_inode = _read_executable_identity(process / "exe", warnings)
    start_time_ticks = _read_process_start_time(process / "stat", warnings)

    max_open_soft = limits.get("max_open_files_soft")
    fd_utilization = (
        round(scanned_fds / max_open_soft * 100, 2)
        if isinstance(max_open_soft, int) and max_open_soft > 0 and not fd_scan_truncated
        else None
    )
    observation = {
        "pid": pid,
        "exists": True,
        "name": status_values.get("Name"),
        "state": status_values.get("State"),
        "ppid": _first_int(status_values.get("PPid")),
        "uid": _first_int(status_values.get("Uid")),
        "gid": _first_int(status_values.get("Gid")),
        "threads": _first_int(status_values.get("Threads")),
        "vm_rss_kb": _first_int(status_values.get("VmRSS")),
        "vm_size_kb": _first_int(status_values.get("VmSize")),
        "voluntary_context_switches": _first_int(
            status_values.get("voluntary_ctxt_switches")
        ),
        "nonvoluntary_context_switches": _first_int(
            status_values.get("nonvoluntary_ctxt_switches")
        ),
        "start_time_ticks": start_time_ticks,
        "open_fd_count": scanned_fds,
        "fd_scan_truncated": fd_scan_truncated,
        "fd_type_counts": fd_counts,
        "max_open_files_soft": limits.get("max_open_files_soft"),
        "max_open_files_hard": limits.get("max_open_files_hard"),
        "max_processes_soft": limits.get("max_processes_soft"),
        "max_processes_hard": limits.get("max_processes_hard"),
        "fd_utilization_percent": fd_utilization,
        "systemd_unit": systemd_unit,
        "container_hint": container_hint,
        "executable_path": executable_path,
        "executable_inode": executable_inode,
    }
    return observation, warnings


def journal_storage_status(payload: BaseModel) -> ToolResult:
    args = JournalStorageStatusInput.model_validate(payload)
    warnings: list[str] = []
    evidence_refs: list[str] = []
    reported_bytes: int | None = None
    settings: dict[str, str] = {}
    settings_status = "unavailable"

    if shutil.which("journalctl") is None:
        warnings.append("journalctl not found")
    else:
        completed = _run_readonly_command(["journalctl", "--disk-usage", "--quiet"], 8)
        evidence_refs.append("journalctl --disk-usage --quiet")
        if completed is None:
            warnings.append("journalctl disk-usage command failed")
        else:
            if completed.stderr.strip():
                warnings.append(completed.stderr.strip())
            if completed.returncode != 0:
                warnings.append(f"journalctl exited with code {completed.returncode}")
            reported_bytes = _parse_journal_disk_usage(completed.stdout)
            if reported_bytes is None:
                warnings.append("journalctl disk usage output could not be parsed")

    if shutil.which("systemd-analyze") is None:
        warnings.append("systemd-analyze not found")
    else:
        completed = _run_readonly_command(
            ["systemd-analyze", "cat-config", "systemd/journald.conf"],
            8,
        )
        evidence_refs.append("systemd-analyze cat-config systemd/journald.conf")
        if completed is None:
            warnings.append("systemd-analyze cat-config command failed")
        else:
            if completed.stderr.strip():
                warnings.append(completed.stderr.strip())
            if completed.returncode != 0:
                warnings.append(f"systemd-analyze exited with code {completed.returncode}")
            else:
                settings = _parse_journald_settings(completed.stdout)
                settings_status = (
                    "explicit_settings_found"
                    if settings
                    else "no_explicit_settings_found"
                )

    storage: list[dict[str, Any]] = []
    remaining_files = args.max_files
    for storage_type, path in JOURNAL_PATHS:
        result, scan_warnings = _scan_journal_directory(path, max_files=remaining_files)
        result["storage_type"] = storage_type
        storage.append(result)
        warnings.extend(scan_warnings)
        remaining_files = max(0, remaining_files - int(result.get("scanned_file_count", 0)))
        evidence_refs.append(str(path))

    observation = {
        "reported_disk_usage_bytes": reported_bytes,
        "storage": storage,
        "settings": settings,
        "settings_available": bool(settings),
        "settings_status": settings_status,
    }
    return ToolResult(
        status="partial" if warnings else "ok",
        observations=[observation],
        warnings=warnings[:10],
        evidence_refs=evidence_refs,
    )


def deleted_open_files(payload: BaseModel) -> ToolResult:
    args = DeletedOpenFilesInput.model_validate(payload)
    rows, scan = _scan_deleted_open_files(
        Path("/proc"),
        limit=args.limit,
        min_size_bytes=args.min_size_mb * 1024 * 1024,
        max_processes=args.max_processes,
        max_fd_scan=args.max_fd_scan,
    )
    observations = rows or [
        {
            "retained_file_count": 0,
            "retained_bytes": 0,
            "open_handle_count": 0,
            "scan_complete": not scan["scan_truncated"],
        }
    ]
    warnings: list[str] = []
    if scan["permission_denied_count"]:
        warnings.append(
            f"{scan['permission_denied_count']} 个进程的 fd 目录不可读"
        )
    if scan["scan_truncated"]:
        warnings.append("deleted-open-file scan reached configured budget")
    retained_bytes = int(scan["retained_bytes_total"])
    retained_file_count = int(scan["matched_file_count"])
    open_handle_count = int(scan["open_handle_count_total"])
    return ToolResult(
        status="partial" if warnings else "ok",
        observations=observations,
        warnings=warnings,
        evidence_refs=["/proc/*/fd/* -> * (deleted)"],
        summary_fields={
            "retained_file_count": retained_file_count,
            "retained_bytes": retained_bytes,
            "open_handle_count": open_handle_count,
            "returned_file_count": len(rows),
            "scanned_process_count": scan["scanned_process_count"],
            "scanned_fd_count": scan["scanned_fd_count"],
            "permission_denied_count": scan["permission_denied_count"],
            "scan_truncated": scan["scan_truncated"],
        },
        risk_hints=(
            [
                f"发现 {retained_file_count} 个已删除但仍由进程持有的文件，"
                f"共保留约 {retained_bytes} 字节磁盘空间。"
            ]
            if rows
            else []
        ),
    )


def _scan_deleted_open_files(
    proc_root: Path,
    *,
    limit: int,
    min_size_bytes: int,
    max_processes: int,
    max_fd_scan: int,
    candidate_pids: list[int] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int | bool]]:
    if candidate_pids is None:
        try:
            candidate_pids = sorted(
                int(item.name)
                for item in proc_root.iterdir()
                if item.name.isdigit() and item.is_dir()
            )
        except OSError:
            candidate_pids = []
    aggregate: dict[tuple[int, int], dict[str, Any]] = {}
    scanned_processes = 0
    scanned_fds = 0
    permission_denied = 0
    truncated = False

    for pid in candidate_pids:
        if scanned_processes >= max_processes or scanned_fds >= max_fd_scan:
            truncated = True
            break
        process_root = proc_root / str(pid)
        fd_root = process_root / "fd"
        scanned_processes += 1
        status = _read_process_identity(process_root / "status")
        unit = _read_process_unit(process_root / "cgroup")
        try:
            for fd_entry in fd_root.iterdir():
                if scanned_fds >= max_fd_scan:
                    truncated = True
                    break
                scanned_fds += 1
                try:
                    target = os.readlink(fd_entry)
                    target_stat = fd_entry.stat()
                except (OSError, ValueError):
                    continue
                if not target.endswith(" (deleted)") or not stat.S_ISREG(
                    target_stat.st_mode
                ):
                    continue
                if target_stat.st_size < min_size_bytes:
                    continue

                key = (int(target_stat.st_dev), int(target_stat.st_ino))
                owner = {
                    "pid": pid,
                    "process": status.get("name"),
                    "uid": status.get("uid"),
                    "systemd_unit": unit,
                    "fd": fd_entry.name,
                }
                row = aggregate.get(key)
                if row is None:
                    clean_path = target[: -len(" (deleted)")]
                    row = {
                        "path": clean_path,
                        "size_bytes": int(target_stat.st_size),
                        "device": int(target_stat.st_dev),
                        "inode": int(target_stat.st_ino),
                        "open_handle_count": 0,
                        "owners": [],
                    }
                    aggregate[key] = row
                row["open_handle_count"] += 1
                if owner not in row["owners"]:
                    row["owners"].append(owner)
        except PermissionError:
            permission_denied += 1
            continue
        except OSError:
            continue

    all_rows = sorted(
        aggregate.values(),
        key=lambda item: (-int(item["size_bytes"]), str(item["path"])),
    )
    matched_file_count = len(all_rows)
    retained_bytes_total = sum(int(item["size_bytes"]) for item in all_rows)
    open_handle_count_total = sum(
        int(item["open_handle_count"]) for item in all_rows
    )
    rows = all_rows[:limit]
    for row in rows:
        owners = row["owners"]
        primary = owners[0] if owners else {}
        row.update(
            {
                "owner_count": len(owners),
                "pid": primary.get("pid"),
                "process": primary.get("process"),
                "uid": primary.get("uid"),
                "systemd_unit": primary.get("systemd_unit"),
            }
        )
    return rows, {
        "scanned_process_count": scanned_processes,
        "scanned_fd_count": scanned_fds,
        "permission_denied_count": permission_denied,
        "scan_truncated": truncated,
        "matched_file_count": matched_file_count,
        "retained_bytes_total": retained_bytes_total,
        "open_handle_count_total": open_handle_count_total,
    }


def _read_process_identity(path: Path) -> dict[str, int | str | None]:
    try:
        values = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"name": None, "uid": None}
    parsed: dict[str, int | str | None] = {"name": None, "uid": None}
    for line in values:
        if line.startswith("Name:"):
            parsed["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("Uid:"):
            parsed["uid"] = _first_int(line.split(":", 1)[1])
    return parsed


def _read_process_unit(path: Path) -> str | None:
    unit, _ = _read_cgroup_identity(path, [])
    return unit


def _parse_journal_disk_usage(value: str) -> int | None:
    match = re.search(
        r"take\s+up\s+(\d+(?:\.\d+)?)\s*([KMGTPE]?)",
        value,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    amount = float(match.group(1))
    unit = match.group(2).upper()
    exponent = "KMGTPE".find(unit) + 1 if unit else 0
    return int(amount * (1024**exponent))


def _parse_journald_settings(value: str) -> dict[str, str]:
    section = ""
    settings: dict[str, str] = {}
    for raw_line in value.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section != "Journal" or "=" not in line:
            continue
        key, setting = line.split("=", 1)
        key = key.strip()
        if key in _JOURNAL_SETTING_KEYS:
            settings[key] = setting.strip()
    return settings


def _scan_journal_directory(
    root: Path,
    *,
    max_files: int,
) -> tuple[dict[str, Any], list[str]]:
    result: dict[str, Any] = {
        "path": str(root),
        "exists": root.exists(),
        "total_bytes": 0,
        "active_file_count": 0,
        "archived_file_count": 0,
        "scanned_file_count": 0,
        "scan_truncated": False,
    }
    if not root.exists():
        return result, []
    warnings: list[str] = []
    try:
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                if not (filename.endswith(".journal") or filename.endswith(".journal~")):
                    continue
                if result["scanned_file_count"] >= max_files:
                    result["scan_truncated"] = True
                    warnings.append(f"journal scan stopped at file limit: {root}")
                    return result, warnings
                path = Path(dirpath) / filename
                try:
                    file_stat = path.stat()
                except OSError as exc:
                    warnings.append(f"unable to stat journal file {path}: {exc}")
                    continue
                if not stat.S_ISREG(file_stat.st_mode):
                    continue
                result["total_bytes"] += file_stat.st_size
                result["scanned_file_count"] += 1
                if "@" in filename or filename.endswith(".journal~"):
                    result["archived_file_count"] += 1
                else:
                    result["active_file_count"] += 1
    except OSError as exc:
        warnings.append(f"unable to scan journal directory {root}: {exc}")
    return result, warnings


def build_diagnostic_tool_definitions() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="process_runtime_detail",
            version="1.0.0",
            description=(
                "Read bounded process status, resource limits, descriptor classes, cgroup "
                "identity, and executable metadata without cmdline or environment content."
            ),
            risk_level=RiskLevel.R0,
            input_model=ProcessRuntimeDetailInput,
            output_model=ToolResult,
            handler=process_runtime_detail,
            capability_requirements=("kernel.procfs",),
        ),
        ToolDefinition(
            name="journal_storage_status",
            version="1.0.0",
            description=(
                "Read journal disk usage, bounded journal file structure, and whitelisted "
                "journald retention settings without returning log content."
            ),
            risk_level=RiskLevel.R0,
            input_model=JournalStorageStatusInput,
            output_model=ToolResult,
            handler=journal_storage_status,
            capability_requirements=(
                "command.journalctl",
                "filesystem.read",
            ),
        ),
        ToolDefinition(
            name="deleted_open_files",
            version="1.0.0",
            description=(
                "Scan bounded /proc file descriptors for deleted regular files that "
                "still retain disk blocks, with process and systemd ownership."
            ),
            risk_level=RiskLevel.R0,
            input_model=DeletedOpenFilesInput,
            output_model=ToolResult,
            handler=deleted_open_files,
            capability_requirements=("kernel.procfs",),
        ),
    ]


def _read_key_value_file(path: Path, warnings: list[str]) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        warnings.append(f"unable to read {path}: {exc}")
        return {}
    values: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def read_process_limits(path: Path, warnings: list[str]) -> dict[str, int | None]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        warnings.append(f"unable to read {path}: {exc}")
        return {}
    limits: dict[str, int | None] = {}
    for label, prefix in (
        ("max_open_files", "Max open files"),
        ("max_processes", "Max processes"),
    ):
        line = next((item for item in lines if item.startswith(prefix)), None)
        if line is None:
            continue
        values = line[len(prefix) :].split()
        if len(values) >= 2:
            limits[f"{label}_soft"] = _limit_value(values[0])
            limits[f"{label}_hard"] = _limit_value(values[1])
    return limits


def _read_fd_types(
    fd_dir: Path,
    max_fd_scan: int,
    warnings: list[str],
) -> tuple[dict[str, int], int, bool]:
    counts = {
        "regular": 0,
        "directory": 0,
        "socket": 0,
        "pipe": 0,
        "anon_inode": 0,
        "other": 0,
        "unreadable": 0,
    }
    scanned = 0
    truncated = False
    try:
        entries = sorted(fd_dir.iterdir(), key=lambda path: int(path.name))
    except (OSError, ValueError) as exc:
        warnings.append(f"unable to scan {fd_dir}: {exc}")
        return counts, scanned, truncated
    for entry in entries:
        if scanned >= max_fd_scan:
            truncated = True
            break
        scanned += 1
        try:
            target = os.readlink(entry)
        except OSError:
            counts["unreadable"] += 1
            continue
        if target.startswith("socket:["):
            counts["socket"] += 1
        elif target.startswith("pipe:["):
            counts["pipe"] += 1
        elif target.startswith("anon_inode:"):
            counts["anon_inode"] += 1
        else:
            try:
                target_stat = entry.stat()
            except OSError:
                counts["other"] += 1
                continue
            if stat.S_ISREG(target_stat.st_mode):
                counts["regular"] += 1
            elif stat.S_ISDIR(target_stat.st_mode):
                counts["directory"] += 1
            else:
                counts["other"] += 1
    return counts, scanned, truncated


def _read_cgroup_identity(path: Path, warnings: list[str]) -> tuple[str | None, str | None]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        warnings.append(f"unable to read {path}: {exc}")
        return None, None
    systemd_unit: str | None = None
    container_hint: str | None = None
    for line in lines:
        cgroup_path = line.rsplit(":", 1)[-1]
        for segment in reversed(cgroup_path.split("/")):
            if segment.endswith(".service"):
                systemd_unit = segment
                break
        lowered = cgroup_path.lower()
        if "kubepods" in lowered:
            container_hint = "kubernetes"
        elif "docker" in lowered:
            container_hint = "docker"
        elif "libpod" in lowered:
            container_hint = "podman"
    return systemd_unit, container_hint


def _read_executable_identity(path: Path, warnings: list[str]) -> tuple[str | None, int | None]:
    try:
        target = path.resolve(strict=True)
        target_stat = target.stat()
        return str(target), target_stat.st_ino
    except OSError as exc:
        warnings.append(f"unable to inspect {path}: {exc}")
        return None, None


def _read_process_start_time(path: Path, warnings: list[str]) -> int | None:
    try:
        value = path.read_text(encoding="utf-8", errors="replace").strip()
        close_paren = value.rfind(")")
        fields = value[close_paren + 1 :].split()
        return int(fields[19]) if close_paren >= 0 and len(fields) > 19 else None
    except (OSError, ValueError) as exc:
        warnings.append(f"unable to parse {path}: {exc}")
        return None


def _first_int(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.search(r"-?\d+", value)
    return int(match.group(0)) if match else None


def _limit_value(value: str) -> int | None:
    return None if value.lower() == "unlimited" else int(value)


def _run_readonly_command(command: list[str], timeout: int):
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return None
