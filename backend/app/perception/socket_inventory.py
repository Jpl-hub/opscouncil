from __future__ import annotations

import os
from pathlib import Path
import pwd
import re
from typing import Any

from backend.app.perception.network_scope import classify_listener_scope


def parse_network_listener_line(line: str) -> dict[str, Any] | None:
    parts = line.split()
    if len(parts) < 6:
        return None
    metadata = " ".join(parts[6:])
    pid_match = re.search(r"\bpid=(\d+)", metadata)
    process_match = re.search(r'users:\(\("([^"]+)"', metadata)
    uid_match = re.search(r"\buid:(\d+)", metadata)
    inode_match = re.search(r"\bino:(\d+)", metadata)
    cgroup_match = re.search(r"\bcgroup:([^\s]+)", metadata)
    pid = int(pid_match.group(1)) if pid_match else None
    uid = int(uid_match.group(1)) if uid_match else None
    process_name = process_match.group(1) if process_match else None
    systemd_unit, container_hint = cgroup_identity(
        cgroup_match.group(1) if cgroup_match else ""
    )
    return {
        "protocol": parts[0],
        "state": parts[1],
        "recv_q": parts[2],
        "send_q": parts[3],
        "local_address": parts[4],
        "peer_address": parts[5],
        "exposure_scope": classify_listener_scope(parts[4]),
        "process": process_name or "",
        "pid": pid,
        "process_name": process_name,
        "uid": uid,
        "user": username(uid),
        "socket_inode": int(inode_match.group(1)) if inode_match else None,
        "systemd_unit": systemd_unit,
        "container_hint": container_hint,
        "attribution_source": "ss" if pid is not None else "unresolved",
    }


def collect_proc_socket_owners(
    socket_inodes: set[int],
    *,
    proc_root: Path = Path("/proc"),
) -> dict[int, dict[str, Any]]:
    if not socket_inodes:
        return {}
    owners: dict[int, dict[str, Any]] = {}
    try:
        proc_paths = sorted(
            (path for path in proc_root.iterdir() if path.name.isdigit()),
            key=lambda path: int(path.name),
        )
    except OSError:
        return {}

    for proc_path in proc_paths:
        pid = int(proc_path.name)
        try:
            uid = read_process_uid(proc_path / "status")
            process_name = (proc_path / "comm").read_text(encoding="utf-8").strip()
            fd_paths = list((proc_path / "fd").iterdir())
        except OSError:
            continue
        process_cgroup: tuple[str | None, str | None] | None = None
        for fd_path in fd_paths:
            try:
                target = os.readlink(fd_path)
            except OSError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)]", target)
            if match is None:
                continue
            inode = int(match.group(1))
            if inode not in socket_inodes or inode in owners:
                continue
            if process_cgroup is None:
                process_cgroup = read_process_cgroup_identity(
                    pid,
                    proc_root=proc_root,
                )
            systemd_unit, container_hint = process_cgroup
            owner = {
                "pid": pid,
                "process_name": process_name or "unknown",
                "uid": uid,
                "user": username(uid),
            }
            if systemd_unit is not None:
                owner["systemd_unit"] = systemd_unit
            if container_hint is not None:
                owner["container_hint"] = container_hint
            owners[inode] = owner
        if socket_inodes.issubset(owners):
            break
    return owners


def read_process_cgroup_identity(
    pid: int,
    *,
    proc_root: Path = Path("/proc"),
) -> tuple[str | None, str | None]:
    try:
        lines = (proc_root / str(pid) / "cgroup").read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
    except OSError:
        return None, None
    systemd_unit: str | None = None
    container_hint: str | None = None
    for line in lines:
        unit, container = cgroup_identity(line.rsplit(":", 1)[-1])
        systemd_unit = unit or systemd_unit
        container_hint = container or container_hint
    return systemd_unit, container_hint


def cgroup_identity(value: str) -> tuple[str | None, str | None]:
    systemd_unit = next(
        (
            segment
            for segment in reversed(value.split("/"))
            if segment.endswith((".service", ".scope"))
        ),
        None,
    )
    lowered = value.lower()
    if "kubepods" in lowered:
        container_hint = "kubernetes"
    elif "docker" in lowered:
        container_hint = "docker"
    elif "libpod" in lowered:
        container_hint = "podman"
    else:
        container_hint = None
    return systemd_unit, container_hint


def read_process_uid(status_path: Path) -> int | None:
    try:
        for line in status_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def username(uid: int | None) -> str | None:
    if uid is None:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)
