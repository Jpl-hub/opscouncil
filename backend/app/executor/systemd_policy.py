from __future__ import annotations

import re
from collections.abc import Iterable


SYSTEMD_UNIT_PATTERN = re.compile(r"^[A-Za-z0-9_.@:-]+(?:\.service)?$")

PERMANENTLY_PROTECTED_UNITS = {
    "auditd.service",
    "dbus.service",
    "firewalld.service",
    "network.service",
    "NetworkManager.service",
    "nftables.service",
    "polkit.service",
    "ssh.service",
    "sshd.service",
}

PERMANENTLY_PROTECTED_PREFIXES = (
    "opscouncil",
    "mariadb",
    "mysql",
    "postgresql",
    "systemd-",
)


def normalize_service_unit(value: str) -> str:
    unit = value.strip()
    if not SYSTEMD_UNIT_PATTERN.fullmatch(unit):
        raise ValueError("systemd 服务名称格式不合法")
    return unit if unit.endswith(".service") else f"{unit}.service"


def normalized_restartable_units(values: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        unit = normalize_service_unit(value)
        if unit not in normalized:
            normalized.append(unit)
    return tuple(normalized)


def is_permanently_protected_unit(unit: str) -> bool:
    normalized = normalize_service_unit(unit)
    lowered = normalized.lower()
    return normalized in PERMANENTLY_PROTECTED_UNITS or any(
        lowered.startswith(prefix.lower()) for prefix in PERMANENTLY_PROTECTED_PREFIXES
    )


def validate_restartable_unit(unit: str, configured_units: Iterable[str]) -> str:
    normalized = normalize_service_unit(unit)
    if is_permanently_protected_unit(normalized):
        raise ValueError("目标服务属于永久保护范围")
    allowed = normalized_restartable_units(configured_units)
    if normalized not in allowed:
        raise ValueError("目标服务未进入受控重启白名单")
    return normalized
