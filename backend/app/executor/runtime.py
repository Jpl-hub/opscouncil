from __future__ import annotations

from typing import Any

from backend.app.core.config import settings
from backend.app.executor.config_policy import validate_repairable_config_path
from backend.app.executor.policy import (
    ALLOWED_ACTION_TOOLS,
    ALLOWED_PATH_PREFIXES,
    PROTECTED_PATH_PREFIXES,
    current_identity,
)
from backend.app.executor.systemd_policy import validate_restartable_unit


def runtime_safety_report() -> dict[str, Any]:
    identity = current_identity()
    running_as_root = identity["uid"] == 0
    root_bypass_enabled = settings.allow_root_executor
    action_execution_enabled = not running_as_root or root_bypass_enabled
    configured_restart_units = tuple(getattr(settings, "restartable_systemd_units", ()))
    restartable_units: list[str] = []
    restart_configuration_errors: list[str] = []
    for configured_unit in configured_restart_units:
        try:
            restartable_units.append(
                validate_restartable_unit(configured_unit, configured_restart_units)
            )
        except ValueError as exc:
            restart_configuration_errors.append(f"{configured_unit}: {exc}")
    restartable_units = list(dict.fromkeys(restartable_units))
    configured_config_paths = tuple(getattr(settings, "repairable_config_paths", ()))
    repairable_config_paths: list[str] = []
    config_path_errors: list[str] = []
    for configured_path in configured_config_paths:
        try:
            repairable_config_paths.append(
                validate_repairable_config_path(configured_path, configured_config_paths)
            )
        except ValueError as exc:
            config_path_errors.append(f"{configured_path}: {exc}")
    repairable_config_paths = list(dict.fromkeys(repairable_config_paths))
    boundary_configuration_errors = [*restart_configuration_errors, *config_path_errors]
    enabled_action_tools = sorted(
        tool
        for tool in ALLOWED_ACTION_TOOLS
        if (tool != "restart_managed_service" or restartable_units)
        and (tool != "restore_config_mode" or repairable_config_paths)
    )
    if boundary_configuration_errors:
        whitelist_detail = "处置白名单配置无效，对应动作已关闭。"
    else:
        enabled_extensions: list[str] = []
        if restartable_units:
            enabled_extensions.append("服务重启")
        if repairable_config_paths:
            enabled_extensions.append("配置权限恢复")
        suffix = "、" + "、".join(enabled_extensions) if enabled_extensions else ""
        whitelist_detail = f"副作用执行仅开放日志轮转、备份恢复{suffix}。"

    if running_as_root and not root_bypass_enabled:
        overall_status = "blocked"
        summary = "当前服务以 root 身份运行，副作用工具已被策略锁定。"
    elif running_as_root and root_bypass_enabled:
        overall_status = "warn"
        summary = "当前服务允许 root 执行副作用工具，仅适合临时调试。"
    elif boundary_configuration_errors:
        overall_status = "warn"
        summary = "处置白名单配置未通过安全校验，其余受控动作保持可用。"
    else:
        overall_status = "ok"
        summary = "当前服务使用受限身份运行，副作用工具受白名单、路径边界和审批约束。"

    return {
        "overall_status": overall_status,
        "summary": summary,
        "executor": {
            "mode": settings.executor_mode,
            "runtime_user": identity["user"],
            "runtime_uid": identity["uid"],
            "target_user": settings.executor_user,
            "allow_root_executor": root_bypass_enabled,
            "action_execution_enabled": action_execution_enabled,
        },
        "boundary": {
            "allowed_tools": enabled_action_tools,
            "allowed_path_prefixes": list(ALLOWED_PATH_PREFIXES),
            "protected_path_prefixes": list(PROTECTED_PATH_PREFIXES),
            "restartable_units": restartable_units,
            "repairable_config_paths": repairable_config_paths,
        },
        "guards": [
            {
                "key": "runtime_identity",
                "name": "运行身份",
                "status": _identity_guard_status(running_as_root, root_bypass_enabled),
                "detail": _identity_guard_detail(identity["user"], identity["uid"], root_bypass_enabled),
            },
            {
                "key": "tool_whitelist",
                "name": "工具白名单",
                "status": "warn" if boundary_configuration_errors else "ok",
                "detail": whitelist_detail,
            },
            {
                "key": "path_boundary",
                "name": "路径边界",
                "status": "ok",
                "detail": "允许 /var/log 与 /tmp，数据库日志、审计日志和系统目录保持保护。",
            },
            {
                "key": "approval_gate",
                "name": "审批闸门",
                "status": "ok",
                "detail": "R2/R3 处置需先生成方案，再由人工审批触发执行。",
            },
        ],
    }


def _identity_guard_status(running_as_root: bool, root_bypass_enabled: bool) -> str:
    if running_as_root and not root_bypass_enabled:
        return "blocked"
    if running_as_root:
        return "warn"
    return "ok"


def _identity_guard_detail(user: str, uid: int, root_bypass_enabled: bool) -> str:
    if uid == 0 and not root_bypass_enabled:
        return f"当前身份 {user}/0，系统已拒绝副作用工具执行。"
    if uid == 0:
        return f"当前身份 {user}/0，已显式允许 root 调试执行。"
    return f"当前身份 {user}/{uid}，符合最小权限运行要求。"
