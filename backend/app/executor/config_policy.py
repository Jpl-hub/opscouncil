from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path


ALLOWED_CONFIG_MODES = {"0o600", "0o640", "0o644"}


PERMANENTLY_PROTECTED_CONFIG_PATHS = {
    "/etc/crypttab",
    "/etc/fstab",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
}

PERMANENTLY_PROTECTED_CONFIG_PREFIXES = (
    "/boot/",
    "/etc/audit/",
    "/etc/NetworkManager/",
    "/etc/pam.d/",
    "/etc/polkit-1/",
    "/etc/security/",
    "/etc/selinux/",
    "/etc/ssh/",
    "/etc/ssl/private/",
    "/etc/sudoers.d/",
    "/etc/systemd/",
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
)


def normalize_config_path(value: str) -> str:
    raw = value.strip()
    if not raw or not Path(raw).is_absolute():
        raise ValueError("配置路径必须是绝对路径")
    return os.path.normpath(raw)


def normalized_repairable_config_paths(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        path = normalize_config_path(value)
        if path not in normalized:
            normalized.append(path)
    return tuple(normalized)


def is_permanently_protected_config_path(value: str) -> bool:
    path = normalize_config_path(value)
    return path in PERMANENTLY_PROTECTED_CONFIG_PATHS or any(
        path.startswith(prefix) for prefix in PERMANENTLY_PROTECTED_CONFIG_PREFIXES
    )


def validate_repairable_config_path(value: str, configured_paths: Iterable[str]) -> str:
    path = normalize_config_path(value)
    if is_permanently_protected_config_path(path):
        raise ValueError("目标配置属于永久保护范围")
    allowed = normalized_repairable_config_paths(configured_paths)
    if path not in allowed:
        raise ValueError("目标配置未进入权限恢复白名单")
    return path
