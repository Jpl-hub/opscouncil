from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

from backend.app.core.pydantic_compat import BaseModel, Field, field_validator
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.perception.socket_inventory import (
    collect_proc_socket_owners,
    parse_network_listener_line,
    read_process_cgroup_identity,
    read_process_uid,
    username,
)
from backend.app.schemas.enums import RiskLevel


_NETWORK_FILESYSTEMS = {
    "9p",
    "afs",
    "ceph",
    "cifs",
    "fuse.sshfs",
    "glusterfs",
    "nfs",
    "nfs4",
    "smb3",
}
_PSEUDO_FILESYSTEMS = {
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "proc",
    "securityfs",
    "sysfs",
    "tracefs",
}
_SAFE_MOUNT_OPTION_KEYS = {
    "async",
    "bind",
    "data",
    "dev",
    "dirsync",
    "discard",
    "errors",
    "exec",
    "lazytime",
    "noatime",
    "nodev",
    "noexec",
    "nosuid",
    "relatime",
    "remount",
    "rbind",
    "ro",
    "rw",
    "strictatime",
    "suid",
    "sync",
}


class SocketProcessContextInput(BaseModel):
    protocol: str = Field(pattern=r"^(tcp|udp)$")
    port: int = Field(ge=1, le=65535)
    max_matches: int = Field(default=20, ge=1, le=50)

    @field_validator("protocol", mode="before")
    @classmethod
    def normalize_protocol(cls, value: Any) -> str:
        return str(value).strip().lower()


class FilesystemMountContextInput(BaseModel):
    path: str = Field(min_length=1, max_length=4096)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if "\x00" in value or not value.startswith("/"):
            raise ValueError("path must be an absolute path without NUL bytes")
        return value


def socket_process_context(payload: BaseModel) -> ToolResult:
    args = SocketProcessContextInput.model_validate(payload)
    return _collect_socket_process_context(args, proc_root=Path("/proc"))


def _collect_socket_process_context(
    args: SocketProcessContextInput,
    *,
    proc_root: Path,
) -> ToolResult:
    if shutil.which("ss") is None:
        return ToolResult(status="unavailable", warnings=["ss not found"])
    command = ["ss", "-H", "-lntupe", f"sport = :{args.port}"]
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

    matches: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        listener = parse_network_listener_line(line)
        if listener is None:
            continue
        if listener.get("protocol") != args.protocol:
            continue
        if _endpoint_port(str(listener.get("local_address") or "")) != args.port:
            continue
        matches.append(listener)

    unresolved_inodes = {
        int(item["socket_inode"])
        for item in matches
        if item.get("pid") is None and isinstance(item.get("socket_inode"), int)
    }
    proc_owners = collect_proc_socket_owners(unresolved_inodes, proc_root=proc_root)
    proc_owner_scan_used = bool(unresolved_inodes)
    proc_metadata_used = False
    for item in matches:
        inode = item.get("socket_inode")
        if item.get("pid") is None and isinstance(inode, int):
            owner = proc_owners.get(inode)
            if owner is not None:
                item.update(owner)
                item["process"] = owner["process_name"]
                item["attribution_source"] = "procfs"
        pid = item.get("pid")
        if isinstance(pid, int):
            proc_metadata_used = True
            if not isinstance(item.get("uid"), int):
                uid = read_process_uid(proc_root / str(pid) / "status")
                item["uid"] = uid
                item["user"] = username(uid)
            if not item.get("process_name"):
                try:
                    process_name = (proc_root / str(pid) / "comm").read_text(
                        encoding="utf-8",
                        errors="replace",
                    ).strip()
                except OSError:
                    process_name = ""
                item["process_name"] = process_name or None
                item["process"] = process_name
            if not item.get("systemd_unit"):
                unit, container_hint = read_process_cgroup_identity(
                    pid,
                    proc_root=proc_root,
                )
                item["systemd_unit"] = unit
                item["container_hint"] = container_hint

    scan_truncated = len(matches) > args.max_matches
    selected = [_bounded_listener(item) for item in matches[: args.max_matches]]
    unattributed_count = sum(
        not isinstance(item.get("pid"), int) for item in matches
    )
    warnings = [completed.stderr.strip()] if completed.stderr.strip() else []
    if completed.returncode != 0:
        warnings.append(f"ss exited with code {completed.returncode}")
    if scan_truncated:
        warnings.append(f"listener matches truncated at {args.max_matches}")
    evidence_refs = [f"ss -H -lntupe sport = :{args.port}"]
    if proc_owner_scan_used:
        evidence_refs.extend(
            ["/proc/*/fd", "/proc/*/comm", "/proc/*/status", "/proc/*/cgroup"]
        )
    elif proc_metadata_used:
        evidence_refs.extend(
            ["/proc/<pid>/comm", "/proc/<pid>/status", "/proc/<pid>/cgroup"]
        )

    observation = {
        "protocol": args.protocol,
        "port": args.port,
        "listener_count": len(matches),
        "unattributed_count": unattributed_count,
        "scan_truncated": scan_truncated,
        "listeners": selected,
    }
    return ToolResult(
        status="partial" if warnings else "ok",
        observations=[observation],
        warnings=warnings[:10],
        evidence_refs=evidence_refs,
    )


def filesystem_mount_context(payload: BaseModel) -> ToolResult:
    args = FilesystemMountContextInput.model_validate(payload)
    return _read_filesystem_mount_context(args.path)


def _read_filesystem_mount_context(raw_path: str) -> ToolResult:
    if shutil.which("findmnt") is None:
        return ToolResult(status="unavailable", warnings=["findmnt not found"])
    try:
        resolved_path = Path(raw_path).resolve(strict=True)
    except OSError as exc:
        return ToolResult(
            status="unavailable",
            warnings=[f"path unavailable: {exc}"],
            evidence_refs=[raw_path],
        )

    command = [
        "findmnt",
        "--json",
        "--target",
        str(resolved_path),
        "--output",
        "TARGET,SOURCE,FSTYPE,OPTIONS,FSROOT",
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
        warnings.append(f"findmnt exited with code {completed.returncode}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return ToolResult(
            status="error",
            warnings=[*warnings, f"findmnt JSON could not be parsed: {exc}"][:10],
            evidence_refs=[f"findmnt --json --target {resolved_path}"],
        )
    filesystems = payload.get("filesystems") if isinstance(payload, dict) else None
    filesystem = filesystems[0] if isinstance(filesystems, list) and filesystems else None
    if not isinstance(filesystem, dict):
        return ToolResult(
            status="unavailable",
            warnings=[*warnings, "findmnt returned no filesystem mapping"][:10],
            evidence_refs=[f"findmnt --json --target {resolved_path}"],
        )

    mount_target = str(filesystem.get("target") or "")
    source = _sanitize_mount_source(str(filesystem.get("source") or ""))[:512]
    filesystem_type = str(filesystem.get("fstype") or "")
    options = _safe_mount_options(str(filesystem.get("options") or ""))
    option_keys = {item.split("=", 1)[0] for item in options}
    try:
        usage = shutil.disk_usage(resolved_path)
    except OSError as exc:
        return ToolResult(
            status="error",
            warnings=[*warnings, f"capacity lookup failed: {exc}"][:10],
            evidence_refs=[f"findmnt --json --target {resolved_path}"],
        )

    relative_path: str | None
    try:
        relative = resolved_path.relative_to(Path(mount_target))
        relative_path = "." if str(relative) == "." else str(relative)
    except (ValueError, OSError):
        relative_path = None
    observation = {
        "requested_path": raw_path,
        "resolved_path": str(resolved_path),
        "mount_target": mount_target,
        "path_on_mount": relative_path,
        "source": source,
        "filesystem_type": filesystem_type,
        "filesystem_root": filesystem.get("fsroot"),
        "mount_options": options,
        "read_only": "ro" in option_keys and "rw" not in option_keys,
        "noexec": "noexec" in option_keys,
        "nosuid": "nosuid" in option_keys,
        "nodev": "nodev" in option_keys,
        "is_network_filesystem": filesystem_type.lower() in _NETWORK_FILESYSTEMS,
        "is_overlay_filesystem": filesystem_type.lower() == "overlay",
        "is_pseudo_filesystem": filesystem_type.lower() in _PSEUDO_FILESYSTEMS,
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "used_percent": round(usage.used / usage.total * 100, 2) if usage.total else None,
    }
    return ToolResult(
        status="partial" if warnings else "ok",
        observations=[observation],
        warnings=warnings[:10],
        evidence_refs=[
            f"findmnt --json --target {resolved_path}",
            f"statvfs:{resolved_path}",
        ],
    )


def _endpoint_port(value: str) -> int | None:
    if ":" not in value:
        return None
    raw_port = value.rsplit(":", 1)[-1]
    try:
        return int(raw_port)
    except ValueError:
        return None


def _bounded_listener(item: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "protocol",
        "state",
        "local_address",
        "peer_address",
        "exposure_scope",
        "process_name",
        "pid",
        "uid",
        "user",
        "socket_inode",
        "systemd_unit",
        "container_hint",
        "attribution_source",
    )
    return {key: item.get(key) for key in keys}


def _safe_mount_options(value: str) -> list[str]:
    options: list[str] = []
    for raw_option in value.split(","):
        option = raw_option.strip()
        key = option.split("=", 1)[0].lower()
        if option and key in _SAFE_MOUNT_OPTION_KEYS:
            options.append(option)
    return options


def _sanitize_mount_source(value: str) -> str:
    return re.sub(r"(?<=//)[^/@:]+(?::[^/@]*)?@", "<redacted>@", value)


def build_context_tool_definitions() -> list[ToolDefinition]:
    return [
        ToolDefinition(
            name="socket_process_context",
            version="1.0.0",
            description=(
                "Read ownership, exposure scope, process, user, and service attribution for "
                "one listening port and protocol without returning process command lines."
            ),
            risk_level=RiskLevel.R0,
            input_model=SocketProcessContextInput,
            output_model=ToolResult,
            handler=socket_process_context,
            capability_requirements=(
                "command.ss",
                "kernel.procfs",
            ),
        ),
        ToolDefinition(
            name="filesystem_mount_context",
            version="1.0.0",
            description=(
                "Map one existing absolute path to its mount, filesystem, safe mount options, "
                "security flags, and capacity using findmnt JSON and statvfs."
            ),
            risk_level=RiskLevel.R0,
            input_model=FilesystemMountContextInput,
            output_model=ToolResult,
            handler=filesystem_mount_context,
            capability_requirements=(
                "command.findmnt",
                "filesystem.read",
            ),
        ),
    ]
