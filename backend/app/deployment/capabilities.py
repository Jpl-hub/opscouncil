from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

from backend.app.core.pydantic_compat import BaseModel
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.schemas.enums import RiskLevel


CAPABILITY_SUPPORTED = "SUPPORTED"
CAPABILITY_DEGRADED = "DEGRADED"
CAPABILITY_UNAVAILABLE = "UNAVAILABLE"

CORE_CAPABILITIES = (
    "kernel.procfs",
    "filesystem.read",
    "platform.os_release",
)

COMMAND_VERSION_ARGUMENTS: dict[str, tuple[str, ...]] = {
    "ps": ("--version",),
    "ss": ("-V",),
    "journalctl": ("--version",),
    "systemctl": ("--version",),
    "timedatectl": ("--version",),
    "findmnt": ("--version",),
    "systemd-analyze": ("--version",),
    "lsof": ("-v",),
    "iostat": ("-V",),
    "perf": ("--version",),
    "bpftool": ("version",),
}


class EmptyCapabilityInput(BaseModel):
    pass


class PlatformCapabilityProbe:
    """Build one evidence-bearing description of the current Linux runtime."""

    def __init__(
        self,
        *,
        which: Callable[[str], str | None] | None = None,
        path_exists: Callable[[Path], bool] | None = None,
        path_readable: Callable[[Path], bool] | None = None,
        command_runner: Callable[[list[str]], tuple[int, str]] | None = None,
        uname_provider: Callable[[], Any] | None = None,
        os_release_reader: Callable[[], dict[str, Any]] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.which = which or shutil.which
        self.path_exists = path_exists or (lambda path: path.exists())
        self.path_readable = path_readable or (
            lambda path: path.exists() and os.access(path, os.R_OK)
        )
        self.command_runner = command_runner or _run_version_command
        self.uname_provider = uname_provider or _read_uname
        self.os_release_reader = os_release_reader or _read_os_release
        self.now = now or (lambda: datetime.now(timezone.utc))

    def probe(self) -> dict[str, Any]:
        uname = self.uname_provider()
        machine = str(getattr(uname, "machine", "unknown") or "unknown")
        os_release = self.os_release_reader()
        capabilities = {
            "kernel.procfs": self._path_capability(
                "kernel.procfs",
                "Linux procfs",
                (Path("/proc/self/status"), Path("/proc/meminfo")),
            ),
            "filesystem.read": self._path_capability(
                "filesystem.read",
                "文件系统只读访问",
                (Path("/"),),
            ),
            "platform.os_release": self._path_capability(
                "platform.os_release",
                "操作系统发行版标识",
                (Path("/etc/os-release"),),
            ),
            "kernel.psi": self._path_capability(
                "kernel.psi",
                "Linux PSI 压力指标",
                (
                    Path("/proc/pressure/cpu"),
                    Path("/proc/pressure/memory"),
                    Path("/proc/pressure/io"),
                ),
                partial_status=CAPABILITY_DEGRADED,
            ),
            "kernel.cgroup_v2": self._path_capability(
                "kernel.cgroup_v2",
                "cgroup v2",
                (Path("/sys/fs/cgroup/cgroup.controllers"),),
            ),
            "runtime.systemd": self._path_capability(
                "runtime.systemd",
                "systemd 运行时",
                (Path("/run/systemd/system"),),
            ),
        }
        for command in COMMAND_VERSION_ARGUMENTS:
            capabilities[f"command.{command}"] = self._command_capability(command)

        core_unavailable = [
            key
            for key in CORE_CAPABILITIES
            if capabilities[key]["status"] == CAPABILITY_UNAVAILABLE
        ]
        status_counts = {
            status: sum(
                1 for item in capabilities.values() if item.get("status") == status
            )
            for status in (
                CAPABILITY_SUPPORTED,
                CAPABILITY_DEGRADED,
                CAPABILITY_UNAVAILABLE,
            )
        }
        return {
            "profile_version": "1.0.0",
            "probed_at": self.now().isoformat(),
            "status": (
                CAPABILITY_DEGRADED if core_unavailable else CAPABILITY_SUPPORTED
            ),
            "platform": {
                "hostname": str(getattr(uname, "nodename", "unknown") or "unknown"),
                "kernel": str(getattr(uname, "release", "unknown") or "unknown"),
                "machine": machine,
                "os_family": "linux",
                "is_loongarch": machine.lower().startswith("loongarch"),
                "os_release": os_release,
            },
            "capabilities": capabilities,
            "summary": {
                "supported": status_counts[CAPABILITY_SUPPORTED],
                "degraded": status_counts[CAPABILITY_DEGRADED],
                "unavailable": status_counts[CAPABILITY_UNAVAILABLE],
                "core_unavailable": core_unavailable,
            },
        }

    def _path_capability(
        self,
        key: str,
        name: str,
        paths: tuple[Path, ...],
        *,
        partial_status: str = CAPABILITY_UNAVAILABLE,
    ) -> dict[str, Any]:
        readable = [str(path) for path in paths if self.path_readable(path)]
        missing = [str(path) for path in paths if not self.path_exists(path)]
        unreadable = [
            str(path)
            for path in paths
            if self.path_exists(path) and not self.path_readable(path)
        ]
        if len(readable) == len(paths):
            status = CAPABILITY_SUPPORTED
            reason = "所需路径可读。"
        elif readable:
            status = partial_status
            reason = "部分所需路径不可读或不存在。"
        else:
            status = CAPABILITY_UNAVAILABLE
            reason = "所需路径不可读或不存在。"
        return {
            "key": key,
            "name": name,
            "kind": "runtime",
            "status": status,
            "reason": reason,
            "evidence": {
                "readable": readable,
                "missing": missing,
                "unreadable": unreadable,
            },
        }

    def _command_capability(self, command: str) -> dict[str, Any]:
        executable = self.which(command)
        if not executable:
            return {
                "key": f"command.{command}",
                "name": command,
                "kind": "command",
                "status": CAPABILITY_UNAVAILABLE,
                "reason": "未在 PATH 中发现命令。",
                "evidence": {"executable": None, "version": None},
            }
        return_code, version = self.command_runner(
            [executable, *COMMAND_VERSION_ARGUMENTS[command]]
        )
        return {
            "key": f"command.{command}",
            "name": command,
            "kind": "command",
            "status": CAPABILITY_SUPPORTED,
            "reason": "命令可执行。",
            "evidence": {
                "executable": executable,
                "version": version or None,
                "version_probe_return_code": return_code,
            },
        }


def build_platform_capability_tool(
    probe: PlatformCapabilityProbe,
) -> ToolDefinition:
    def platform_capability_profile(_: BaseModel) -> ToolResult:
        profile = probe.probe()
        capabilities = profile["capabilities"]
        evidence_refs: list[str] = []
        for item in capabilities.values():
            evidence = item.get("evidence", {})
            if isinstance(evidence, dict):
                evidence_refs.extend(
                    str(path)
                    for path in evidence.get("readable", [])
                    if isinstance(path, str)
                )
                executable = evidence.get("executable")
                if isinstance(executable, str):
                    evidence_refs.append(executable)
        return ToolResult(
            status="ok" if profile["status"] == CAPABILITY_SUPPORTED else "degraded",
            observations=[profile],
            evidence_refs=list(dict.fromkeys(evidence_refs)),
            summary_fields=profile["summary"],
            warnings=(
                ["主机核心能力不完整，Agent 将禁用不满足前置条件的工具。"]
                if profile["summary"]["core_unavailable"]
                else []
            ),
        )

    return ToolDefinition(
        name="platform_capability_profile",
        version="1.0.0",
        description=(
            "Probe the current Linux runtime, architecture, kernel interfaces, "
            "systemd state, and command availability before selecting OS tools."
        ),
        risk_level=RiskLevel.R0,
        input_model=EmptyCapabilityInput,
        output_model=ToolResult,
        handler=platform_capability_profile,
    )


def _read_uname() -> Any:
    if hasattr(os, "uname"):
        return os.uname()
    return type(
        "Uname",
        (),
        {
            "nodename": "unknown",
            "release": "unknown",
            "machine": "unknown",
        },
    )()


def _read_os_release() -> dict[str, Any]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
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


def _run_version_command(command: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)[:200]
    output = (completed.stdout or completed.stderr or "").strip().splitlines()
    return completed.returncode, output[0][:200] if output else ""
