from __future__ import annotations

import getpass
import os
from pathlib import Path
from typing import Any

from backend.app.core.config import settings
from backend.app.executor.config_policy import (
    ALLOWED_CONFIG_MODES,
    validate_repairable_config_path,
)
from backend.app.executor.systemd_policy import validate_restartable_unit


ALLOWED_ACTION_TOOLS = {
    "restart_managed_service",
    "restore_config_mode",
    "restore_log_backup",
    "safe_log_rotate",
}
ALLOWED_PATH_PREFIXES = ("/var/log/", "/tmp/")
PROTECTED_PATH_PREFIXES = (
    "/etc/",
    "/boot/",
    "/usr/",
    "/var/lib/mysql/",
    "/var/lib/postgresql/",
    "/var/log/audit/",
    "/var/log/journal/",
    "/var/log/mysql/",
    "/var/log/mariadb/",
    "/var/log/postgresql/",
)


class ExecutionDeniedError(PermissionError):
    def __init__(self, context: dict[str, Any]):
        super().__init__(context["reason"])
        self.context = context


def authorize_execution(tool_name: str, risk_level: str, payload: dict[str, Any]) -> dict[str, Any]:
    identity = current_identity()
    target_path = payload.get("restore_target") if tool_name == "restore_log_backup" else payload.get("path")
    artifact_path = payload.get("artifact_path") if tool_name == "restore_log_backup" else None
    requested_unit = payload.get("unit") if tool_name == "restart_managed_service" else None
    scope = {
        "allowed_tools": sorted(ALLOWED_ACTION_TOOLS),
        "allowed_path_prefixes": list(ALLOWED_PATH_PREFIXES),
        "protected_path_prefixes": list(PROTECTED_PATH_PREFIXES),
        "target_path": target_path if isinstance(target_path, str) else None,
        "artifact_path": artifact_path if isinstance(artifact_path, str) else None,
        "unit": requested_unit if isinstance(requested_unit, str) else None,
        "restartable_units": list(getattr(settings, "restartable_systemd_units", ())),
        "repairable_config_paths": list(getattr(settings, "repairable_config_paths", ())),
    }
    context = {
        "executor_mode": settings.executor_mode,
        "runtime_user": identity["user"],
        "runtime_uid": identity["uid"],
        "target_user": settings.executor_user,
        "tool_name": tool_name,
        "risk_level": risk_level,
        "allowed": "true",
        "reason": "工具和目标路径通过最小权限执行策略。",
        "scope": scope,
    }

    if identity["uid"] == 0 and not settings.allow_root_executor:
        context["allowed"] = "false"
        context["reason"] = "副作用工具禁止以 root 身份运行，请使用受限账号启动 Agent 服务。"
        raise ExecutionDeniedError(context)

    if tool_name not in ALLOWED_ACTION_TOOLS:
        context["allowed"] = "false"
        context["reason"] = "工具未进入副作用执行白名单。"
        raise ExecutionDeniedError(context)

    accepted_risks = (
        {"R3"}
        if tool_name in {"restart_managed_service", "restore_config_mode"}
        else {"R1", "R2"}
    )
    if risk_level not in accepted_risks:
        context["allowed"] = "false"
        context["reason"] = "当前风险等级不允许直接进入受限执行代理。"
        raise ExecutionDeniedError(context)

    if tool_name == "restart_managed_service":
        if not isinstance(requested_unit, str):
            context["allowed"] = "false"
            context["reason"] = "服务恢复动作缺少结构化 unit 参数。"
            raise ExecutionDeniedError(context)
        try:
            scope["unit"] = validate_restartable_unit(
                requested_unit,
                getattr(settings, "restartable_systemd_units", ()),
            )
        except ValueError as exc:
            context["allowed"] = "false"
            context["reason"] = str(exc)
            raise ExecutionDeniedError(context) from exc
        context["reason"] = "服务单元、风险等级和精确白名单通过最小权限执行策略。"
        return context

    if tool_name == "restore_config_mode":
        if not isinstance(target_path, str):
            context["allowed"] = "false"
            context["reason"] = "配置权限恢复缺少结构化 path 参数。"
            raise ExecutionDeniedError(context)
        try:
            scope["target_path"] = validate_repairable_config_path(
                target_path,
                getattr(settings, "repairable_config_paths", ()),
            )
        except ValueError as exc:
            context["allowed"] = "false"
            context["reason"] = str(exc)
            raise ExecutionDeniedError(context) from exc
        if payload.get("target_mode") not in ALLOWED_CONFIG_MODES:
            context["allowed"] = "false"
            context["reason"] = "目标权限位超出配置恢复策略。"
            raise ExecutionDeniedError(context)
        expected_hash = payload.get("expected_sha256")
        baseline_ids = (payload.get("baseline_id"), payload.get("baseline_check_id"))
        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(character not in "0123456789abcdef" for character in expected_hash)
            or any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in baseline_ids)
        ):
            context["allowed"] = "false"
            context["reason"] = "配置权限恢复缺少有效的基线证据绑定。"
            raise ExecutionDeniedError(context)
        context["reason"] = "配置路径、基线绑定和目标权限位通过最小权限执行策略。"
        return context

    for scope_key, path_value in (("target_path", target_path), ("artifact_path", artifact_path)):
        if path_value is None:
            if scope_key == "artifact_path" and tool_name != "restore_log_backup":
                continue
            context["allowed"] = "false"
            context["reason"] = "副作用工具缺少受控路径参数。"
            raise ExecutionDeniedError(context)
        if not isinstance(path_value, str):
            context["allowed"] = "false"
            context["reason"] = "副作用工具路径参数类型不合法。"
            raise ExecutionDeniedError(context)
        normalized = str(Path(path_value).resolve())
        scope[scope_key] = normalized
        if not any(normalized.startswith(prefix) for prefix in ALLOWED_PATH_PREFIXES):
            context["allowed"] = "false"
            context["reason"] = "目标路径超出受限执行范围。"
            raise ExecutionDeniedError(context)
        if any(normalized.startswith(prefix) for prefix in PROTECTED_PATH_PREFIXES):
            context["allowed"] = "false"
            context["reason"] = "目标路径属于受保护系统目录。"
            raise ExecutionDeniedError(context)

    return context


def current_identity() -> dict[str, Any]:
    uid = os.geteuid() if hasattr(os, "geteuid") else -1
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    return {"uid": uid, "user": user}
