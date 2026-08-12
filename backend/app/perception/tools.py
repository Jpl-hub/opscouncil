from __future__ import annotations

from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import time
from typing import Any

from backend.app.core.pydantic_compat import BaseModel, Field, field_validator

from backend.app.deployment.capabilities import (
    PlatformCapabilityProbe,
    build_platform_capability_tool,
)
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.perception.context_tools import build_context_tool_definitions
from backend.app.perception.diagnostic_tools import (
    build_diagnostic_tool_definitions,
    read_process_limits,
)
from backend.app.perception.service_tools import build_service_tool_definitions
from backend.app.perception.topology_tools import build_topology_tool_definitions
from backend.app.perception.socket_inventory import (
    collect_proc_socket_owners as _collect_proc_socket_owners,
    parse_network_listener_line as _parse_network_listener_line,
)
from backend.app.schemas.enums import RiskLevel


class EmptyInput(BaseModel):
    pass


class DiskUsageInput(BaseModel):
    paths: list[str] = Field(default_factory=lambda: ["/", "/tmp", "/var"])


class ProcessListInput(BaseModel):
    limit: int = Field(default=20, ge=1, le=200)


class JournalQueryInput(BaseModel):
    unit: str | None = None
    lines: int = Field(default=80, ge=1, le=500)


class NetworkListenersInput(BaseModel):
    limit: int = Field(default=80, ge=1, le=500)


class ProcessFileHandlesInput(BaseModel):
    limit: int = Field(default=20, ge=1, le=200)
    sample_per_process: int = Field(default=5, ge=0, le=20)


class ServiceStatusInput(BaseModel):
    unit: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_.@:-]+(\.service)?$")


class FindLargeFilesInput(BaseModel):
    roots: list[str] = Field(default_factory=lambda: ["/var/log", "/tmp"])
    limit: int = Field(default=20, ge=1, le=100)
    min_size_mb: int = Field(default=10, ge=1, le=10240)

    @field_validator("roots")
    @classmethod
    def validate_roots(cls, value: list[str]) -> list[str]:
        if not 1 <= len(value) <= 8:
            raise ValueError("roots must contain between 1 and 8 paths")
        if any(not root.strip() or len(root) > 512 for root in value):
            raise ValueError("each scan root must contain between 1 and 512 characters")
        return value


class ConfigIntegrityInput(BaseModel):
    paths: list[str] = Field(
        default_factory=lambda: ["/etc/hosts", "/etc/resolv.conf", "/etc/fstab"],
    )
    max_bytes: int = Field(default=1024 * 1024, ge=4096, le=5 * 1024 * 1024)

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, value: list[str]) -> list[str]:
        if len(value) > 20:
            raise ValueError("paths must contain at most 20 items")
        return value


def _read_meminfo() -> dict[str, int]:
    meminfo: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, rest = line.split(":", 1)
            value = int(rest.strip().split()[0])
            meminfo[key] = value
    except Exception:
        return {}
    return meminfo


def _parse_psi_text(content: str) -> dict[str, dict[str, float | int]]:
    pressure: dict[str, dict[str, float | int]] = {}
    for line in content.splitlines()[:2]:
        parts = line.strip().split()
        if not parts or parts[0] not in {"some", "full"}:
            continue
        values: dict[str, float | int] = {}
        for item in parts[1:]:
            if "=" not in item:
                continue
            key, raw_value = item.split("=", 1)
            try:
                if key == "total":
                    values["total_us"] = int(raw_value)
                elif key in {"avg10", "avg60", "avg300"}:
                    values[key] = float(raw_value)
            except ValueError:
                continue
        if values:
            pressure[parts[0]] = values
    return pressure


def _read_pressure() -> dict[str, dict[str, dict[str, float | int]]]:
    pressure: dict[str, dict[str, dict[str, float | int]]] = {}
    for resource in ("cpu", "memory", "io"):
        path = Path("/proc/pressure") / resource
        try:
            parsed = _parse_psi_text(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if parsed:
            pressure[resource] = parsed
    return pressure


def _read_io_activity() -> dict[str, int]:
    activity: dict[str, int] = {}
    try:
        cpu_line = next(
            line
            for line in Path("/proc/stat").read_text(encoding="utf-8", errors="replace").splitlines()
            if line.startswith("cpu ")
        )
        cpu_fields = [int(value) for value in cpu_line.split()[1:]]
        if len(cpu_fields) >= 5:
            activity["iowait_ticks"] = cpu_fields[4]
    except (OSError, StopIteration, ValueError):
        pass

    device_count = 0
    read_ios = 0
    write_ios = 0
    io_time_ms = 0
    try:
        for line in Path("/proc/diskstats").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            fields = line.split()
            if len(fields) < 14 or fields[2].startswith(("loop", "ram")):
                continue
            try:
                read_ios += int(fields[3])
                write_ios += int(fields[7])
                io_time_ms += int(fields[12])
            except ValueError:
                continue
            device_count += 1
    except OSError:
        pass
    if device_count:
        activity.update(
            {
                "device_count": device_count,
                "read_ios": read_ios,
                "write_ios": write_ios,
                "io_time_ms": io_time_ms,
            }
        )
    return activity


def _read_os_release() -> dict[str, Any]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key.lower()] = value.strip().strip('"').strip("'")
    except OSError:
        return {}

    return {
        "id": values.get("id"),
        "id_like": values.get("id_like"),
        "name": values.get("name"),
        "pretty_name": values.get("pretty_name"),
        "version": values.get("version"),
        "version_id": values.get("version_id"),
    }


def system_snapshot(_: BaseModel) -> ToolResult:
    uname = os.uname() if hasattr(os, "uname") else None
    machine = uname.machine if uname else "unknown"
    loadavg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    uptime_seconds = None
    try:
        uptime_seconds = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
    except Exception:
        pass
    meminfo = _read_meminfo()
    total = meminfo.get("MemTotal")
    available = meminfo.get("MemAvailable")
    observations = [
        {
            "hostname": uname.nodename if uname else "unknown",
            "kernel": uname.release if uname else "unknown",
            "machine": machine,
            "os_family": "linux",
            "is_loongarch": machine.lower().startswith("loongarch"),
            "os_release": _read_os_release(),
            "loadavg": loadavg,
            "uptime_seconds": uptime_seconds,
            "memory": {
                "total_kb": total,
                "available_kb": available,
                "used_percent": round((1 - available / total) * 100, 2)
                if total and available
                else None,
            },
            "pressure": _read_pressure(),
            "io_activity": _read_io_activity(),
        }
    ]
    return ToolResult(
        observations=observations,
        evidence_refs=[
            "/etc/os-release",
            "/proc/meminfo",
            "/proc/uptime",
            "/proc/pressure/cpu",
            "/proc/pressure/memory",
            "/proc/pressure/io",
            "/proc/stat",
            "/proc/diskstats",
        ],
    )


def disk_usage(payload: BaseModel) -> ToolResult:
    args = DiskUsageInput.model_validate(payload)
    observations: list[dict[str, Any]] = []
    warnings: list[str] = []
    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.exists():
            warnings.append(f"path not found: {raw_path}")
            continue
        usage = shutil.disk_usage(path)
        try:
            inode_stats = os.statvfs(path)
            inode_total = int(inode_stats.f_files)
            inode_free = int(inode_stats.f_ffree)
            inode_used = max(inode_total - inode_free, 0)
            inode_used_percent = (
                round(inode_used / inode_total * 100, 2) if inode_total else None
            )
        except OSError as exc:
            inode_total = inode_free = inode_used = 0
            inode_used_percent = None
            warnings.append(f"unable to collect inode usage for {raw_path}: {exc}")
        observations.append(
            {
                "path": str(path),
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "used_percent": round(usage.used / usage.total * 100, 2) if usage.total else None,
                "inode_total": inode_total,
                "inode_used": inode_used,
                "inode_free": inode_free,
                "inode_used_percent": inode_used_percent,
            }
        )
    return ToolResult(
        observations=observations,
        warnings=warnings,
        evidence_refs=[*args.paths, *[f"statvfs:{path}" for path in args.paths]],
    )


def time_sync_status(_: BaseModel) -> ToolResult:
    if shutil.which("timedatectl") is None:
        return ToolResult(status="unavailable", warnings=["timedatectl not found"])
    command = [
        "timedatectl",
        "show",
        "--no-pager",
        "--property=NTPSynchronized",
        "--property=NTP",
        "--property=Timezone",
        "--property=LocalRTC",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=6,
        )
    except Exception as exc:
        return ToolResult(status="error", warnings=[str(exc)])
    warnings = [completed.stderr.strip()] if completed.stderr.strip() else []
    if completed.returncode != 0:
        warnings.append(f"timedatectl exited with code {completed.returncode}")
        return ToolResult(
            status="error",
            warnings=warnings[:10],
            evidence_refs=["timedatectl show"],
        )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines()[:16]:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    observation = {
        "ntp_synchronized": _yes_no(values.get("NTPSynchronized")),
        "ntp_enabled": _yes_no(values.get("NTP")),
        "timezone": values.get("Timezone", "")[:128] or None,
        "local_rtc": _yes_no(values.get("LocalRTC")),
    }
    missing = [
        key
        for key, value in observation.items()
        if value is None and key in {"ntp_synchronized", "ntp_enabled"}
    ]
    if missing:
        warnings.append(f"timedatectl omitted fields: {', '.join(missing)}")
    return ToolResult(
        status="partial" if warnings else "ok",
        observations=[observation],
        warnings=warnings[:10],
        evidence_refs=["timedatectl show"],
    )


def _yes_no(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"yes", "true", "1"}:
        return True
    if normalized in {"no", "false", "0"}:
        return False
    return None


def process_list(payload: BaseModel) -> ToolResult:
    args = ProcessListInput.model_validate(payload)
    cmd = ["ps", "-eo", "pid=,ppid=,stat=,%cpu=,%mem=,comm=", "--sort=-%cpu"]
    try:
        completed = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=5)
    except Exception as exc:
        return ToolResult(status="error", warnings=[str(exc)])

    rows = []
    warnings = [completed.stderr.strip()] if completed.stderr.strip() else []
    for line in completed.stdout.splitlines()[:4000]:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        try:
            rows.append(
                {
                    "pid": int(parts[0]),
                    "ppid": int(parts[1]),
                    "stat": parts[2],
                    "cpu_percent": float(parts[3]),
                    "mem_percent": float(parts[4]),
                    "command": parts[5],
                    "is_zombie": "Z" in parts[2],
                }
            )
        except ValueError as exc:
            warnings.append(f"process row skipped: {exc}")
            continue
    if completed.returncode != 0:
        warnings.append(f"ps exited with code {completed.returncode}")
    rows.sort(
        key=lambda item: (
            not bool(item["is_zombie"]),
            -float(item["cpu_percent"]),
            int(item["pid"]),
        )
    )
    return ToolResult(
        observations=rows[: args.limit],
        warnings=warnings,
        evidence_refs=["ps -eo pid=,ppid=,stat=,%cpu=,%mem=,comm="],
    )


def journal_query(payload: BaseModel) -> ToolResult:
    args = JournalQueryInput.model_validate(payload)
    if shutil.which("journalctl") is None:
        return ToolResult(status="unavailable", warnings=["journalctl not found"])
    cmd = ["journalctl", "--no-pager", "-n", str(args.lines)]
    if args.unit:
        cmd.extend(["-u", args.unit])
    try:
        completed = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=8)
    except Exception as exc:
        return ToolResult(status="error", warnings=[str(exc)])
    lines = completed.stdout.splitlines()[-args.lines :]
    return ToolResult(
        observations=[{"line": line} for line in lines],
        warnings=[completed.stderr.strip()] if completed.stderr.strip() else [],
        evidence_refs=["journalctl"],
    )


def network_listeners(payload: BaseModel) -> ToolResult:
    args = NetworkListenersInput.model_validate(payload)
    if shutil.which("ss") is None:
        return ToolResult(status="unavailable", warnings=["ss not found"])

    cmd = ["ss", "-H", "-lntupe"]
    try:
        completed = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=5)
    except Exception as exc:
        return ToolResult(status="error", warnings=[str(exc)])

    observations: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines()[: args.limit]:
        observation = _parse_network_listener_line(line)
        if observation is not None:
            observations.append(observation)

    unresolved_inodes = {
        int(item["socket_inode"])
        for item in observations
        if item.get("pid") is None and isinstance(item.get("socket_inode"), int)
    }
    proc_owners = _collect_proc_socket_owners(unresolved_inodes)
    for item in observations:
        inode = item.get("socket_inode")
        if item.get("pid") is not None or not isinstance(inode, int):
            continue
        owner = proc_owners.get(inode)
        if owner is None:
            continue
        item.update(owner)
        item["process"] = owner["process_name"]
        item["attribution_source"] = "procfs"

    warnings = [completed.stderr.strip()] if completed.stderr.strip() else []
    if completed.returncode != 0:
        warnings.append(f"ss exited with code {completed.returncode}")
    evidence_refs = ["ss -H -lntupe"]
    if unresolved_inodes:
        evidence_refs.extend(["/proc/*/fd", "/proc/*/comm", "/proc/*/status"])
    return ToolResult(observations=observations, warnings=warnings, evidence_refs=evidence_refs)


def process_file_handles(payload: BaseModel) -> ToolResult:
    args = ProcessFileHandlesInput.model_validate(payload)
    observations, warnings = _collect_process_file_handles(Path("/proc"), args)
    return ToolResult(
        observations=observations,
        warnings=warnings,
        evidence_refs=["/proc/*/fd", "/proc/*/comm", "/proc/*/limits"],
    )


def _collect_process_file_handles(
    proc_root: Path,
    args: ProcessFileHandlesInput,
) -> tuple[list[dict[str, Any]], list[str]]:
    observations: list[dict[str, Any]] = []
    warnings: list[str] = []

    for proc_path in proc_root.iterdir():
        if not proc_path.name.isdigit():
            continue
        pid = int(proc_path.name)
        fd_dir = proc_path / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except PermissionError:
            warnings.append(f"permission denied: /proc/{pid}/fd")
            continue
        except OSError:
            continue

        samples: list[str] = []
        for fd in fds[: args.sample_per_process]:
            try:
                samples.append(str(fd.resolve()))
            except OSError:
                continue
        try:
            command = (proc_path / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            command = "unknown"
        limit_warnings: list[str] = []
        limits = read_process_limits(proc_path / "limits", limit_warnings)
        max_open_files_soft = limits.get("max_open_files_soft")
        fd_utilization_percent = (
            round(len(fds) / max_open_files_soft * 100, 2)
            if isinstance(max_open_files_soft, int) and max_open_files_soft > 0
            else None
        )
        observations.append(
            {
                "pid": pid,
                "command": command,
                "open_fd_count": len(fds),
                "max_open_files_soft": max_open_files_soft,
                "fd_utilization_percent": fd_utilization_percent,
                "samples": samples,
            }
        )

    observations.sort(
        key=lambda item: (
            isinstance(item.get("fd_utilization_percent"), (int, float)),
            float(item.get("fd_utilization_percent") or -1),
            int(item["open_fd_count"]),
        ),
        reverse=True,
    )
    return observations[: args.limit], warnings[:20]


def service_status(payload: BaseModel) -> ToolResult:
    args = ServiceStatusInput.model_validate(payload)
    if shutil.which("systemctl") is None:
        return ToolResult(status="unavailable", warnings=["systemctl not found"])

    if args.unit:
        unit = args.unit if args.unit.endswith(".service") else f"{args.unit}.service"
        cmd = [
            "systemctl",
            "show",
            unit,
            "--no-pager",
            (
                "--property=Id,LoadState,ActiveState,SubState,UnitFileState,"
                "FragmentPath,ExecStart,ExecMainPID,ExecMainCode,ExecMainStatus,"
                "Result,NRestarts"
            ),
        ]
    else:
        cmd = ["systemctl", "--no-pager", "--plain", "--failed", "--type=service"]

    try:
        completed = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=8)
    except Exception as exc:
        return ToolResult(status="error", warnings=[str(exc)])

    observations: list[dict[str, Any]] = []
    if args.unit:
        values: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value
        if values:
            observations.append(
                {
                    "unit": values.get("Id") or unit,
                    "load_state": values.get("LoadState"),
                    "active_state": values.get("ActiveState"),
                    "sub_state": values.get("SubState"),
                    "result": values.get("Result"),
                    "main_pid": _optional_int(values.get("ExecMainPID")),
                    "exec_main_code": _optional_int(values.get("ExecMainCode")),
                    "exec_main_status": _optional_int(values.get("ExecMainStatus")),
                    "exec_start_path": _systemd_exec_start_path(values.get("ExecStart")),
                    "fragment_path": values.get("FragmentPath") or None,
                    "unit_file_state": values.get("UnitFileState") or None,
                    "restart_count": _optional_int(values.get("NRestarts")),
                }
            )
    else:
        for line in completed.stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("UNIT ") or stripped.startswith("LOAD "):
                continue
            parts = stripped.split(None, 4)
            if len(parts) >= 4 and parts[0].endswith(".service"):
                observations.append(
                    {
                        "unit": parts[0],
                        "load": parts[1],
                        "active": parts[2],
                        "sub": parts[3],
                        "description": parts[4] if len(parts) > 4 else "",
                    }
                )
        if completed.returncode == 0 and not observations:
            observations.append(
                {
                    "scope": "failed_services",
                    "failed_count": 0,
                }
            )

    warnings = [completed.stderr.strip()] if completed.stderr.strip() else []
    if completed.returncode != 0:
        warnings.append(f"systemctl exited with code {completed.returncode}")
    return ToolResult(observations=observations, warnings=warnings, evidence_refs=["systemctl"])


def _optional_int(value: str | None) -> int | None:
    try:
        return int(value) if value not in {None, ""} else None
    except ValueError:
        return None


def _systemd_exec_start_path(value: str | None) -> str | None:
    if not value:
        return None
    marker = "path="
    start = value.find(marker)
    if start < 0:
        return None
    path = value[start + len(marker) :].split(";", 1)[0].strip().rstrip("}").strip()
    return path or None


def find_large_files(payload: BaseModel) -> ToolResult:
    args = FindLargeFilesInput.model_validate(payload)
    allowed_roots = [Path("/var/log"), Path("/tmp"), Path.home()]
    min_size = args.min_size_mb * 1024 * 1024
    found: list[dict[str, Any]] = []
    warnings: list[str] = []
    started = time.monotonic()

    for raw_root in args.roots:
        root = Path(raw_root).resolve()
        if not any(root == allowed or allowed in root.parents for allowed in allowed_roots):
            warnings.append(f"root outside allowed read-only scan scope: {root}")
            continue
        if not root.exists():
            warnings.append(f"root not found: {root}")
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            if time.monotonic() - started > 8:
                warnings.append("scan stopped after 8 seconds")
                break
            for filename in filenames:
                path = Path(dirpath) / filename
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_size >= min_size:
                    found.append(
                        {
                            "path": str(path),
                            "size_bytes": stat.st_size,
                            "mtime": stat.st_mtime,
                            "extension": path.suffix,
                        }
                    )
        found.sort(key=lambda item: item["size_bytes"], reverse=True)
        found = found[: args.limit]
    return ToolResult(
        observations=found,
        warnings=warnings,
        evidence_refs=[str(item["path"]) for item in found],
        summary_fields={"scan_roots": [str(Path(root)) for root in args.roots]},
    )


def _is_within(path: Path, roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _sha256_file(path: Path, max_bytes: int) -> tuple[str, bool]:
    digest = hashlib.sha256()
    consumed = 0
    truncated = False
    with path.open("rb") as file:
        while True:
            chunk_limit = min(1024 * 1024, max_bytes - consumed)
            if chunk_limit <= 0:
                truncated = file.read(1) != b""
                break
            chunk = file.read(chunk_limit)
            if not chunk:
                break
            digest.update(chunk)
            consumed += len(chunk)
    return digest.hexdigest(), truncated


def config_integrity_scan(payload: BaseModel) -> ToolResult:
    args = ConfigIntegrityInput.model_validate(payload)
    allowed_roots = [
        Path("/etc"),
        Path("/usr/lib/systemd/system"),
        Path("/lib/systemd/system"),
        Path("/run/systemd/resolve"),
        Path("/run/resolvconf"),
        Path("/tmp/opscouncil-lab"),
    ]
    denied_roots = [
        Path("/etc/shadow"),
        Path("/etc/gshadow"),
        Path("/etc/security"),
        Path("/etc/ssl/private"),
    ]
    observations: list[dict[str, Any]] = []
    warnings: list[str] = []
    evidence_refs: list[str] = []

    for raw_path in args.paths:
        requested = Path(raw_path).expanduser()
        if not requested.is_absolute():
            warnings.append(f"relative config path skipped: {raw_path}")
            continue

        resolved = requested.resolve(strict=False)
        if _is_within(requested, denied_roots) or _is_within(resolved, denied_roots):
            warnings.append(f"protected config path skipped: {raw_path}")
            continue
        if not _is_within(resolved, allowed_roots):
            if _is_within(requested, allowed_roots) and requested.is_symlink():
                try:
                    link_stat = requested.lstat()
                    link_target = os.readlink(requested)
                except OSError as exc:
                    warnings.append(f"unable to read config symlink {raw_path}: {exc}")
                    continue
                observations.append(
                    {
                        "path": str(requested),
                        "resolved_path": str(resolved),
                        "exists": resolved.exists(),
                        "file_type": "symlink",
                        "size_bytes": link_stat.st_size,
                        "mtime": link_stat.st_mtime,
                        "mode": oct(link_stat.st_mode & 0o777),
                        "uid": link_stat.st_uid,
                        "gid": link_stat.st_gid,
                        "link_target_sha256": hashlib.sha256(
                            link_target.encode("utf-8", errors="replace")
                        ).hexdigest(),
                    }
                )
                evidence_refs.append(str(requested))
                continue
            warnings.append(f"outside allowed config scan scope: {raw_path}")
            continue
        if not resolved.exists():
            observations.append(
                {
                    "path": str(requested),
                    "resolved_path": str(resolved),
                    "exists": False,
                }
            )
            evidence_refs.append(str(requested))
            continue

        try:
            stat_result = resolved.stat()
        except OSError as exc:
            warnings.append(f"unable to stat config path {raw_path}: {exc}")
            continue
        if not resolved.is_file():
            warnings.append(f"non-regular config path skipped: {raw_path}")
            continue

        try:
            file_hash, truncated = _sha256_file(resolved, args.max_bytes)
        except OSError as exc:
            warnings.append(f"unable to hash config path {raw_path}: {exc}")
            continue

        observations.append(
            {
                "path": str(requested),
                "resolved_path": str(resolved),
                "exists": True,
                "file_type": "file",
                "size_bytes": stat_result.st_size,
                "mtime": stat_result.st_mtime,
                "mode": oct(stat_result.st_mode & 0o777),
                "uid": stat_result.st_uid,
                "gid": stat_result.st_gid,
                "sha256": file_hash,
                "hash_truncated": truncated,
            }
        )
        evidence_refs.append(str(requested))

    return ToolResult(observations=observations, warnings=warnings, evidence_refs=evidence_refs)


def build_perception_registry(
    capability_probe: PlatformCapabilityProbe | None = None,
) -> ToolRegistry:
    probe = capability_probe or PlatformCapabilityProbe()
    registry = ToolRegistry(capability_provider=probe.probe)
    registry.register(build_platform_capability_tool(probe))
    for tool in build_diagnostic_tool_definitions():
        registry.register(tool)
    for tool in build_context_tool_definitions():
        registry.register(tool)
    for tool in build_service_tool_definitions():
        registry.register(tool)
    for tool in build_topology_tool_definitions():
        registry.register(tool)
    registry.register(
        ToolDefinition(
            name="system_snapshot",
            version="1.1.0",
            description="Collect host identity, kernel, uptime, load, memory, and Linux PSI pressure summary.",
            risk_level=RiskLevel.R0,
            input_model=EmptyInput,
            output_model=ToolResult,
            handler=system_snapshot,
            capability_requirements=(
                "kernel.procfs",
                "platform.os_release",
            ),
        )
    )
    registry.register(
        ToolDefinition(
            name="disk_usage",
            version="1.1.0",
            description="Collect filesystem capacity and inode usage for selected paths.",
            risk_level=RiskLevel.R0,
            input_model=DiskUsageInput,
            output_model=ToolResult,
            handler=disk_usage,
            capability_requirements=("filesystem.read",),
        )
    )
    registry.register(
        ToolDefinition(
            name="time_sync_status",
            version="1.0.0",
            description="Read bounded system time synchronization state from timedatectl.",
            risk_level=RiskLevel.R0,
            input_model=EmptyInput,
            output_model=ToolResult,
            handler=time_sync_status,
            capability_requirements=(
                "command.timedatectl",
                "runtime.systemd",
            ),
        )
    )
    registry.register(
        ToolDefinition(
            name="process_list",
            version="1.0.0",
            description="Collect top processes and identify zombie process states.",
            risk_level=RiskLevel.R0,
            input_model=ProcessListInput,
            output_model=ToolResult,
            handler=process_list,
            capability_requirements=("command.ps",),
        )
    )
    registry.register(
        ToolDefinition(
            name="journal_query",
            version="1.0.0",
            description="Read recent systemd journal lines without modifying system state.",
            risk_level=RiskLevel.R0,
            input_model=JournalQueryInput,
            output_model=ToolResult,
            handler=journal_query,
            capability_requirements=("command.journalctl",),
        )
    )
    registry.register(
        ToolDefinition(
            name="network_listeners",
            version="1.1.0",
            description="Collect listening TCP/UDP sockets with process attribution when available.",
            risk_level=RiskLevel.R0,
            input_model=NetworkListenersInput,
            output_model=ToolResult,
            handler=network_listeners,
            capability_requirements=("command.ss",),
        )
    )
    registry.register(
        ToolDefinition(
            name="process_file_handles",
            version="1.0.0",
            description="Collect top processes by open file descriptor count using /proc.",
            risk_level=RiskLevel.R0,
            input_model=ProcessFileHandlesInput,
            output_model=ToolResult,
            handler=process_file_handles,
            capability_requirements=("kernel.procfs",),
        )
    )
    registry.register(
        ToolDefinition(
            name="service_status",
            version="1.1.0",
            description="Read systemd service state, failed summary, and bounded startup context.",
            risk_level=RiskLevel.R0,
            input_model=ServiceStatusInput,
            output_model=ToolResult,
            handler=service_status,
            capability_requirements=(
                "command.systemctl",
                "runtime.systemd",
            ),
        )
    )
    registry.register(
        ToolDefinition(
            name="find_large_files",
            version="1.0.0",
            description="Scan allowed directories for large files to support disk pressure analysis.",
            risk_level=RiskLevel.R1,
            input_model=FindLargeFilesInput,
            output_model=ToolResult,
            handler=find_large_files,
            capability_requirements=("filesystem.read",),
        )
    )
    registry.register(
        ToolDefinition(
            name="config_integrity_scan",
            version="1.0.0",
            description="Collect metadata and content hashes for allowlisted configuration files without returning file contents.",
            risk_level=RiskLevel.R0,
            input_model=ConfigIntegrityInput,
            output_model=ToolResult,
            handler=config_integrity_scan,
            capability_requirements=("filesystem.read",),
        )
    )
    return registry
