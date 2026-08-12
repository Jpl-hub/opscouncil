from __future__ import annotations

import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import uuid
from typing import Any

from backend.app.core.config import settings
from backend.app.core.pydantic_compat import BaseModel, Field, field_validator
from backend.app.executor.config_policy import (
    ALLOWED_CONFIG_MODES,
    validate_repairable_config_path,
)
from backend.app.executor.systemd_policy import normalize_service_unit, validate_restartable_unit
from backend.app.executor.verification import register_file_integrity_verifier
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.schemas.enums import RiskLevel


PROTECTED_PREFIXES = [
    Path("/etc"),
    Path("/boot"),
    Path("/usr"),
    Path("/var/lib/mysql"),
    Path("/var/lib/postgresql"),
    Path("/var/log/audit"),
    Path("/var/log/journal"),
    Path("/var/log/mysql"),
    Path("/var/log/mariadb"),
    Path("/var/log/postgresql"),
]

MAX_CONFIG_MODE_BYTES = 1024 * 1024


class SafeLogRotateInput(BaseModel):
    path: str
    backup: bool = True
    compress: bool = True
    keep_days: int = Field(default=30, ge=1, le=365)
    dry_run: bool = True

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        path = Path(value).resolve()
        if not path.exists():
            raise ValueError("target path does not exist")
        if not path.is_file():
            raise ValueError("target path must be a regular file")
        if not (str(path).startswith("/var/log/") or str(path).startswith("/tmp/")):
            raise ValueError("safe_log_rotate only accepts /var/log or /tmp files")
        if _is_protected_path(path):
            raise ValueError("target path is protected")
        return str(path)


class RestoreLogBackupInput(BaseModel):
    artifact_path: str
    restore_target: str
    dry_run: bool = True

    @field_validator("artifact_path")
    @classmethod
    def validate_artifact_path(cls, value: str) -> str:
        path = Path(value).resolve()
        if not path.exists():
            raise ValueError("backup artifact does not exist")
        if not path.is_file():
            raise ValueError("backup artifact must be a regular file")
        if not _is_allowed_action_path(path) or _is_protected_path(path):
            raise ValueError("backup artifact is outside the allowed restore scope")
        if not (path.name.endswith(".bak") or path.name.endswith(".bak.gz")):
            raise ValueError("backup artifact format is not supported")
        return str(path)

    @field_validator("restore_target")
    @classmethod
    def validate_restore_target(cls, value: str) -> str:
        path = Path(value).resolve()
        if not path.exists():
            raise ValueError("restore target does not exist")
        if not path.is_file():
            raise ValueError("restore target must be a regular file")
        if not _is_allowed_action_path(path) or _is_protected_path(path):
            raise ValueError("restore target is outside the allowed restore scope")
        return str(path)


class RestartManagedServiceInput(BaseModel):
    unit: str = Field(min_length=1, max_length=128)
    dry_run: bool = True

    @field_validator("unit")
    @classmethod
    def validate_unit(cls, value: str) -> str:
        return normalize_service_unit(value)


class RestoreConfigModeInput(BaseModel):
    path: str
    target_mode: str
    expected_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_id: int = Field(ge=1)
    baseline_check_id: int = Field(ge=1)
    dry_run: bool = True

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return validate_repairable_config_path(value, settings.repairable_config_paths)

    @field_validator("target_mode")
    @classmethod
    def validate_mode(cls, value: str) -> str:
        if value not in ALLOWED_CONFIG_MODES:
            raise ValueError("配置权限仅允许恢复为 0o600、0o640 或 0o644")
        return value


def safe_log_rotate(payload: BaseModel) -> ToolResult:
    args = SafeLogRotateInput.model_validate(payload)
    path = Path(args.path)
    stat = path.stat()
    plan: dict[str, Any] = {
        "target": str(path),
        "size_bytes": stat.st_size,
        "backup": args.backup,
        "compress": args.compress,
        "keep_days": args.keep_days,
        "dry_run": args.dry_run,
    }

    if args.dry_run:
        return ToolResult(
            observations=[
                {
                    **plan,
                    "estimated_reclaim_bytes": stat.st_size,
                    "source_will_be_truncated": True,
                    "rollback_strategy": "restore_backup",
                }
            ],
            evidence_refs=[str(path)],
            warnings=["dry-run only: no file was modified"],
            actions_proposed=[
                {
                    "operation": "safe_log_rotate",
                    "target": str(path),
                    "estimated_reclaim_bytes": stat.st_size,
                    "rollback_strategy": "restore_backup",
                }
            ],
        )

    rotated_path = path.with_name(f"{path.name}.opscouncil.{uuid.uuid4().hex[:8]}.bak")
    shutil.copy2(path, rotated_path)
    artifact_path = str(rotated_path)
    if args.compress:
        gz_path = Path(str(rotated_path) + ".gz")
        with rotated_path.open("rb") as source, gzip.open(gz_path, "wb") as target:
            shutil.copyfileobj(source, target)
        rotated_path.unlink()
        artifact_path = str(gz_path)

    with path.open("r+b") as target:
        target.truncate(0)

    return ToolResult(
        observations=[
            {
                **plan,
                "artifact_path": artifact_path,
                "reclaimed_bytes": stat.st_size,
                "source_truncated": True,
                "rollback_strategy": "restore_backup",
            }
        ],
        evidence_refs=[str(path), artifact_path],
        warnings=["source log was truncated after backup; restore from artifact if rollback is required"],
        artifacts=[
            {
                "type": "backup",
                "path": artifact_path,
                "restore_target": str(path),
                "compressed": args.compress,
            }
        ],
    )


def restore_log_backup(payload: BaseModel) -> ToolResult:
    args = RestoreLogBackupInput.model_validate(payload)
    artifact = Path(args.artifact_path)
    target = Path(args.restore_target)
    _validate_restore_pair(artifact, target)

    restored_temp = target.with_name(f".{target.name}.opscouncil-restore-{uuid.uuid4().hex[:8]}.tmp")
    try:
        restore_bytes = _materialize_backup(artifact, restored_temp)
        plan = {
            "artifact_path": str(artifact),
            "restore_target": str(target),
            "restore_bytes": restore_bytes,
            "dry_run": args.dry_run,
        }
        if args.dry_run:
            return ToolResult(
                observations=[{**plan, "target_will_be_replaced": True, "pre_restore_snapshot": True}],
                evidence_refs=[str(artifact), str(target)],
                warnings=["dry-run only: no file was modified"],
                actions_proposed=[
                    {
                        "operation": "restore_log_backup",
                        "artifact_path": str(artifact),
                        "restore_target": str(target),
                        "rollback_strategy": "restore_pre_restore_snapshot",
                    }
                ],
            )

        snapshot = target.with_name(
            f"{target.name}.opscouncil.pre-restore.{uuid.uuid4().hex[:8]}.bak.gz"
        )
        with target.open("rb") as source, gzip.open(snapshot, "wb") as destination:
            shutil.copyfileobj(source, destination)

        with restored_temp.open("rb") as source, target.open("r+b") as destination:
            destination.truncate(0)
            shutil.copyfileobj(source, destination)
            destination.flush()
            os.fsync(destination.fileno())

        return ToolResult(
            observations=[
                {
                    **plan,
                    "restored": True,
                    "pre_restore_snapshot_path": str(snapshot),
                }
            ],
            evidence_refs=[str(artifact), str(target), str(snapshot)],
            warnings=["target content was restored from the approved backup artifact"],
            artifacts=[
                {
                    "type": "pre_restore_backup",
                    "path": str(snapshot),
                    "restore_target": str(target),
                    "compressed": True,
                }
            ],
        )
    finally:
        restored_temp.unlink(missing_ok=True)


def restart_managed_service(payload: BaseModel) -> ToolResult:
    args = RestartManagedServiceInput.model_validate(payload)
    unit = validate_restartable_unit(args.unit, settings.restartable_systemd_units)
    state = _read_systemd_state(unit)
    if state.get("Id") != unit or state.get("LoadState") != "loaded":
        raise ValueError("目标服务未加载，不能进入受控重启流程")

    observation = {
        "unit": unit,
        "load_state": state.get("LoadState"),
        "active_state": state.get("ActiveState"),
        "sub_state": state.get("SubState"),
        "main_pid": _optional_int(state.get("ExecMainPID")),
        "result": state.get("Result"),
        "restart_count": _optional_int(state.get("NRestarts")),
        "dry_run": args.dry_run,
    }
    if args.dry_run:
        return ToolResult(
            observations=[{**observation, "restart_will_be_requested": True}],
            evidence_refs=[f"systemctl:show:{unit}"],
            warnings=["dry-run only: 服务状态未修改"],
            actions_proposed=[
                {
                    "operation": "restart_managed_service",
                    "unit": unit,
                    "verification": "service_status",
                    "rollback_strategy": "manual_takeover",
                }
            ],
        )

    completed = _run_systemd_restart(unit)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"systemctl exited with code {completed.returncode}"
        raise RuntimeError(f"受控服务重启请求失败：{detail[:300]}")
    return ToolResult(
        observations=[{**observation, "restart_requested": True}],
        evidence_refs=[f"systemctl:restart:{unit}"],
        warnings=["服务是否恢复由独立 service_status 工具核验，本工具不自行声明恢复成功。"],
    )


def restore_config_mode(payload: BaseModel) -> ToolResult:
    args = RestoreConfigModeInput.model_validate(payload)
    path = Path(
        validate_repairable_config_path(args.path, settings.repairable_config_paths)
    )
    descriptor, state = _open_config_mode_state(path)
    try:
        if state["sha256"] != args.expected_sha256:
            raise ValueError("配置内容哈希已变化，拒绝恢复权限")
        if state["uid"] != os.geteuid():
            raise ValueError("当前受限执行身份不是目标配置属主，拒绝恢复权限")

        observation = {
            "path": str(path),
            "current_mode": state["mode"],
            "target_mode": args.target_mode,
            "uid": state["uid"],
            "gid": state["gid"],
            "sha256": state["sha256"],
            "baseline_id": args.baseline_id,
            "baseline_check_id": args.baseline_check_id,
            "dry_run": args.dry_run,
        }
        evidence_refs = [
            str(path),
            f"config_baseline:{args.baseline_id}",
            f"config_baseline_check:{args.baseline_check_id}",
        ]
        if args.dry_run:
            return ToolResult(
                observations=[
                    {
                        **observation,
                        "mode_will_be_changed": state["mode"] != args.target_mode,
                    }
                ],
                evidence_refs=evidence_refs,
                warnings=["dry-run only: 配置权限未修改"],
                actions_proposed=[
                    {
                        "operation": "restore_config_mode",
                        "path": str(path),
                        "target_mode": args.target_mode,
                        "verification": "config_integrity_scan",
                        "rollback_strategy": "manual_takeover",
                    }
                ],
            )

        os.fchmod(descriptor, int(args.target_mode, 8))
        return ToolResult(
            observations=[{**observation, "mode_change_requested": True}],
            evidence_refs=evidence_refs,
            warnings=["权限恢复结果由独立 config_integrity_scan 工具核验。"],
        )
    finally:
        os.close(descriptor)


def register_executor_tools(registry: ToolRegistry) -> None:
    register_file_integrity_verifier(registry)
    registry.register(
        ToolDefinition(
            name="safe_log_rotate",
            version="1.0.0",
            description="Create a reviewed log rotation plan and optional compressed backup for non-critical logs.",
            risk_level=RiskLevel.R2,
            input_model=SafeLogRotateInput,
            output_model=ToolResult,
            handler=safe_log_rotate,
            dry_run_supported=True,
            rollback_strategy="restore_backup",
            capability_requirements=("filesystem.read",),
        )
    )
    registry.register(
        ToolDefinition(
            name="restore_log_backup",
            version="1.0.0",
            description="Restore a log from a OpsCouncil backup after approval and preserve the current target as a recovery snapshot.",
            risk_level=RiskLevel.R2,
            input_model=RestoreLogBackupInput,
            output_model=ToolResult,
            handler=restore_log_backup,
            dry_run_supported=True,
            rollback_strategy="restore_pre_restore_snapshot",
            capability_requirements=("filesystem.read",),
        )
    )
    registry.register(
        ToolDefinition(
            name="restart_managed_service",
            version="1.0.0",
            description=(
                "Request one restart of an exact preconfigured systemd service after approval; "
                "critical platform services remain permanently denied."
            ),
            risk_level=RiskLevel.R3,
            input_model=RestartManagedServiceInput,
            output_model=ToolResult,
            handler=restart_managed_service,
            dry_run_supported=True,
            rollback_strategy="manual_takeover",
            capability_requirements=(
                "command.systemctl",
                "runtime.systemd",
            ),
        )
    )
    registry.register(
        ToolDefinition(
            name="restore_config_mode",
            version="1.0.0",
            description=(
                "Restore non-executable permission bits for one exact allowlisted regular "
                "configuration file when its content hash still matches a confirmed baseline."
            ),
            risk_level=RiskLevel.R3,
            input_model=RestoreConfigModeInput,
            output_model=ToolResult,
            handler=restore_config_mode,
            dry_run_supported=True,
            rollback_strategy="manual_takeover",
            capability_requirements=("filesystem.read",),
        )
    )


def _is_protected_path(path: Path) -> bool:
    return any(path == prefix or prefix in path.parents for prefix in PROTECTED_PREFIXES)


def _is_allowed_action_path(path: Path) -> bool:
    normalized = str(path)
    return normalized.startswith("/var/log/") or normalized.startswith("/tmp/")


def _validate_restore_pair(artifact: Path, target: Path) -> None:
    expected = re.compile(
        rf"^{re.escape(target.name)}\.opscouncil\.[a-f0-9]{{8}}\.bak(?:\.gz)?$"
    )
    if not expected.fullmatch(artifact.name):
        raise ValueError("backup artifact does not match the restore target")
    if artifact.parent != target.parent:
        raise ValueError("backup artifact and restore target must share the same directory")


def _materialize_backup(artifact: Path, destination: Path) -> int:
    opener = gzip.open if artifact.name.endswith(".gz") else Path.open
    try:
        if opener is gzip.open:
            source_context = gzip.open(artifact, "rb")
        else:
            source_context = artifact.open("rb")
        with source_context as source, destination.open("wb") as target:
            shutil.copyfileobj(source, target)
        return destination.stat().st_size
    except (OSError, EOFError) as exc:
        raise ValueError("backup artifact cannot be read or decompressed") from exc


def _read_systemd_state(unit: str) -> dict[str, str]:
    completed = subprocess.run(
        [
            "systemctl",
            "show",
            unit,
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,ExecMainPID,Result,NRestarts",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=8,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or f"systemctl exited with code {completed.returncode}"
        raise RuntimeError(f"无法读取目标服务状态：{detail[:300]}")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _run_systemd_restart(unit: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "restart", unit],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _read_config_mode_state(path: Path) -> dict[str, Any]:
    descriptor, state = _open_config_mode_state(path)
    os.close(descriptor)
    return state


def _open_config_mode_state(path: Path) -> tuple[int, dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"无法读取目标配置：{exc}") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("目标配置必须是普通文件")
        if file_stat.st_size > MAX_CONFIG_MODE_BYTES:
            raise ValueError("目标配置超过权限恢复哈希上限")
        digest = hashlib.sha256()
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            while chunk := stream.read(64 * 1024):
                digest.update(chunk)
        return descriptor, {
            "mode": oct(file_stat.st_mode & 0o777),
            "uid": file_stat.st_uid,
            "gid": file_stat.st_gid,
            "sha256": digest.hexdigest(),
        }
    except (OSError, ValueError) as exc:
        os.close(descriptor)
        if isinstance(exc, ValueError):
            raise
        raise ValueError(f"无法读取目标配置内容哈希：{exc}") from exc
