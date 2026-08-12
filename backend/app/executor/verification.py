from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
from pathlib import Path
import stat
from typing import Any, BinaryIO

from backend.app.core.pydantic_compat import BaseModel, Field, field_validator
from backend.app.executor.policy import ALLOWED_PATH_PREFIXES, PROTECTED_PATH_PREFIXES
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.schemas.enums import RiskLevel


class FileIntegrityStateInput(BaseModel):
    paths: list[str]
    max_bytes: int = Field(default=64 * 1024 * 1024, ge=4096, le=512 * 1024 * 1024)

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, value: list[str]) -> list[str]:
        if not 1 <= len(value) <= 6:
            raise ValueError("paths must contain between 1 and 6 items")
        normalized: list[str] = []
        for raw_path in value:
            requested = Path(raw_path).expanduser()
            if not requested.is_absolute():
                raise ValueError("verification paths must be absolute")
            path = str(requested.resolve(strict=False))
            if not any(path.startswith(prefix) for prefix in ALLOWED_PATH_PREFIXES):
                raise ValueError("verification path is outside the allowed action scope")
            if any(
                path == prefix.rstrip("/") or path.startswith(prefix)
                for prefix in PROTECTED_PATH_PREFIXES
            ):
                raise ValueError("verification path is protected")
            if path not in normalized:
                normalized.append(path)
        return normalized


@dataclass(frozen=True)
class ActionVerificationDecision:
    valid: bool
    reason: str
    details: dict[str, Any]


def verification_tool_name(tool_name: str) -> str:
    if tool_name == "restart_managed_service":
        return "service_status"
    if tool_name == "restore_config_mode":
        return "config_integrity_scan"
    if tool_name in {"safe_log_rotate", "restore_log_backup"}:
        return "file_integrity_state"
    raise ValueError(f"unsupported action verification tool: {tool_name}")


def pre_action_verification_input(tool_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    if tool_name == "safe_log_rotate":
        paths = [_required_path(payload, "path")]
    elif tool_name == "restore_log_backup":
        paths = [
            _required_path(payload, "artifact_path"),
            _required_path(payload, "restore_target"),
        ]
    elif tool_name == "restart_managed_service":
        return {"unit": _required_text(payload, "unit")}
    elif tool_name == "restore_config_mode":
        return {"paths": [_required_text(payload, "path")]}
    else:
        raise ValueError(f"unsupported action verification tool: {tool_name}")
    return {"paths": paths, "max_bytes": 512 * 1024 * 1024}


def post_action_verification_input(
    tool_name: str,
    payload: dict[str, Any],
    action_output: dict[str, Any],
) -> dict[str, Any]:
    if tool_name == "restart_managed_service":
        return {"unit": _required_text(payload, "unit")}
    if tool_name == "restore_config_mode":
        return {"paths": [_required_text(payload, "path")]}
    action_observation = _first_observation(action_output)
    if tool_name == "safe_log_rotate":
        paths = [
            _required_path(payload, "path"),
            _required_path(action_observation, "artifact_path"),
        ]
    elif tool_name == "restore_log_backup":
        paths = [
            _required_path(payload, "restore_target"),
            _required_path(action_observation, "pre_restore_snapshot_path"),
        ]
    else:
        raise ValueError(f"unsupported action verification tool: {tool_name}")
    return {"paths": paths, "max_bytes": 512 * 1024 * 1024}


def validate_pre_action_evidence(
    tool_name: str,
    payload: dict[str, Any],
    verifier_output: dict[str, Any],
) -> ActionVerificationDecision:
    if tool_name == "restore_config_mode":
        path = _required_text(payload, "path")
        state = _config_state_observation(verifier_output, path)
        expected_hash = _required_text(payload, "expected_sha256")
        if (
            state is None
            or state.get("exists") is not True
            or state.get("file_type") != "file"
            or state.get("hash_truncated") is not False
            or state.get("sha256") != expected_hash
        ):
            return _invalid("目标配置未形成与基线内容一致的执行前证据。")
        mode = state.get("mode")
        if not isinstance(mode, str):
            return _invalid("目标配置执行前权限位证据不完整。")
        return ActionVerificationDecision(
            valid=True,
            reason="目标配置执行前权限、属主和完整内容哈希已独立记录。",
            details={
                "path": path,
                "mode_before": mode,
                "uid_before": state.get("uid"),
                "gid_before": state.get("gid"),
                "sha256": expected_hash,
            },
        )

    if tool_name == "restart_managed_service":
        unit = _required_text(payload, "unit")
        state = _service_state_observation(verifier_output, unit)
        if state is None or state.get("LoadState") != "loaded":
            return _invalid("目标服务未形成完整的执行前状态证据。")
        active_state = str(state.get("ActiveState") or "")
        sub_state = str(state.get("SubState") or "")
        if not active_state or not sub_state:
            return _invalid("目标服务执行前状态字段不完整。")
        return ActionVerificationDecision(
            valid=True,
            reason="目标服务执行前加载状态、活动状态和主进程已独立记录。",
            details={
                "unit": unit,
                "active_state_before": active_state,
                "sub_state_before": sub_state,
                "main_pid_before": _optional_int(state.get("ExecMainPID")),
                "result_before": state.get("Result"),
            },
        )

    observations = _observations_by_path(verifier_output)
    if tool_name == "safe_log_rotate":
        source = _complete_observation(observations, _required_path(payload, "path"))
        if source is None:
            return _invalid("源日志未形成完整的执行前哈希证据。")
        return ActionVerificationDecision(
            valid=True,
            reason="源日志执行前大小和 SHA256 已独立记录。",
            details={
                "source_path": source["path"],
                "source_size_bytes": source["size_bytes"],
                "source_sha256": source["sha256"],
            },
        )

    if tool_name == "restore_log_backup":
        artifact = _complete_observation(
            observations,
            _required_path(payload, "artifact_path"),
            require_logical_content=True,
        )
        target = _complete_observation(
            observations,
            _required_path(payload, "restore_target"),
        )
        if artifact is None or target is None:
            return _invalid("备份或恢复目标未形成完整的执行前哈希证据。")
        return ActionVerificationDecision(
            valid=True,
            reason="备份内容与恢复目标的执行前 SHA256 已独立记录。",
            details={
                "artifact_path": artifact["path"],
                "artifact_content_sha256": _logical_content_hash(artifact),
                "target_path": target["path"],
                "target_sha256": target["sha256"],
            },
        )

    return _invalid("当前副作用工具没有独立验证规则。")


def validate_post_action_evidence(
    tool_name: str,
    payload: dict[str, Any],
    pre_verifier_output: dict[str, Any],
    action_output: dict[str, Any],
    post_verifier_output: dict[str, Any],
) -> ActionVerificationDecision:
    if tool_name == "restore_config_mode":
        path = _required_text(payload, "path")
        expected_hash = _required_text(payload, "expected_sha256")
        target_mode = _required_text(payload, "target_mode")
        before = _config_state_observation(pre_verifier_output, path)
        after = _config_state_observation(post_verifier_output, path)
        action_observation = _first_observation(action_output)
        if (
            before is None
            or after is None
            or action_observation.get("path") != path
            or action_observation.get("mode_change_requested") is not True
        ):
            return _invalid("配置权限恢复请求或独立前后证据不完整。")
        valid = (
            after.get("mode") == target_mode
            and before.get("sha256") == expected_hash
            and after.get("sha256") == expected_hash
            and after.get("hash_truncated") is False
            and after.get("uid") == before.get("uid")
            and after.get("gid") == before.get("gid")
        )
        return ActionVerificationDecision(
            valid=valid,
            reason=(
                "配置权限已恢复到基线值，内容哈希和属主属组保持不变。"
                if valid
                else "配置权限恢复后证据与基线不一致，系统转人工处理。"
            ),
            details={
                "path": path,
                "mode_before": before.get("mode"),
                "mode_after": after.get("mode"),
                "target_mode": target_mode,
                "uid_before": before.get("uid"),
                "uid_after": after.get("uid"),
                "gid_before": before.get("gid"),
                "gid_after": after.get("gid"),
                "sha256": expected_hash,
            },
        )

    if tool_name == "restart_managed_service":
        unit = _required_text(payload, "unit")
        before = _service_state_observation(pre_verifier_output, unit)
        after = _service_state_observation(post_verifier_output, unit)
        action_observation = _first_observation(action_output)
        if (
            before is None
            or after is None
            or action_observation.get("unit") != unit
            or action_observation.get("restart_requested") is not True
        ):
            return _invalid("服务重启请求或独立前后状态证据不完整。")
        valid = (
            after.get("LoadState") == "loaded"
            and after.get("ActiveState") == "active"
            and after.get("SubState") not in {"failed", "dead"}
        )
        return ActionVerificationDecision(
            valid=valid,
            reason=(
                "目标服务已由独立状态工具确认恢复为 active。"
                if valid
                else "目标服务重启后未达到 active，系统不自动重试并转人工处理。"
            ),
            details={
                "unit": unit,
                "active_state_before": before.get("ActiveState"),
                "sub_state_before": before.get("SubState"),
                "active_state_after": after.get("ActiveState"),
                "sub_state_after": after.get("SubState"),
                "main_pid_before": _optional_int(before.get("ExecMainPID")),
                "main_pid_after": _optional_int(after.get("ExecMainPID")),
                "result_after": after.get("Result"),
            },
        )

    pre = _observations_by_path(pre_verifier_output)
    post = _observations_by_path(post_verifier_output)
    action_observation = _first_observation(action_output)

    if tool_name == "safe_log_rotate":
        source_path = _required_path(payload, "path")
        artifact_path = _required_path(action_observation, "artifact_path")
        source_before = _complete_observation(pre, source_path)
        source_after = _complete_observation(post, source_path)
        artifact_after = _complete_observation(
            post,
            artifact_path,
            require_logical_content=True,
        )
        if source_before is None or source_after is None or artifact_after is None:
            return _invalid("轮转后的源文件或备份缺少完整独立哈希证据。")
        artifact_hash = _logical_content_hash(artifact_after)
        valid = source_after.get("size_bytes") == 0 and artifact_hash == source_before["sha256"]
        return ActionVerificationDecision(
            valid=valid,
            reason=(
                "源日志已截断，备份内容 SHA256 与执行前源日志一致。"
                if valid
                else "源日志截断状态或备份内容 SHA256 与执行前证据不一致。"
            ),
            details={
                "source_path": source_after["path"],
                "source_size_before": source_before["size_bytes"],
                "source_size_after": source_after["size_bytes"],
                "source_sha256_before": source_before["sha256"],
                "artifact_path": artifact_after["path"],
                "artifact_content_sha256": artifact_hash,
            },
        )

    if tool_name == "restore_log_backup":
        artifact_path = _required_path(payload, "artifact_path")
        target_path = _required_path(payload, "restore_target")
        snapshot_path = _required_path(action_observation, "pre_restore_snapshot_path")
        artifact_before = _complete_observation(
            pre,
            artifact_path,
            require_logical_content=True,
        )
        target_before = _complete_observation(pre, target_path)
        target_after = _complete_observation(post, target_path)
        snapshot_after = _complete_observation(
            post,
            snapshot_path,
            require_logical_content=True,
        )
        if any(
            item is None
            for item in (artifact_before, target_before, target_after, snapshot_after)
        ):
            return _invalid("恢复目标或恢复前快照缺少完整独立哈希证据。")
        assert artifact_before is not None
        assert target_before is not None
        assert target_after is not None
        assert snapshot_after is not None
        artifact_hash = _logical_content_hash(artifact_before)
        snapshot_hash = _logical_content_hash(snapshot_after)
        valid = (
            target_after["sha256"] == artifact_hash
            and snapshot_hash == target_before["sha256"]
        )
        return ActionVerificationDecision(
            valid=valid,
            reason=(
                "恢复目标 SHA256 与备份内容一致，恢复前内容也已由独立快照保留。"
                if valid
                else "恢复目标或恢复前快照 SHA256 与执行前证据不一致。"
            ),
            details={
                "artifact_path": artifact_before["path"],
                "artifact_content_sha256": artifact_hash,
                "target_path": target_after["path"],
                "target_sha256_before": target_before["sha256"],
                "target_sha256_after": target_after["sha256"],
                "snapshot_path": snapshot_after["path"],
                "snapshot_content_sha256": snapshot_hash,
            },
        )

    return _invalid("当前副作用工具没有独立验证规则。")


def file_integrity_state(payload: BaseModel) -> ToolResult:
    args = FileIntegrityStateInput.model_validate(payload)
    observations: list[dict] = []
    warnings: list[str] = []
    evidence_refs: list[str] = []

    for raw_path in args.paths:
        path = Path(raw_path)
        evidence_refs.append(str(path))
        if not path.exists():
            observations.append({"path": str(path), "exists": False})
            continue
        try:
            file_stat = path.stat()
        except OSError as exc:
            warnings.append(f"unable to stat verification path {path}: {exc}")
            observations.append({"path": str(path), "exists": True, "readable": False})
            continue
        if not stat.S_ISREG(file_stat.st_mode):
            warnings.append(f"verification path is not a regular file: {path}")
            observations.append(
                {
                    "path": str(path),
                    "exists": True,
                    "file_type": "non_regular",
                }
            )
            continue

        try:
            with path.open("rb") as stream:
                digest, hashed_bytes, truncated = _bounded_sha256(stream, args.max_bytes)
        except OSError as exc:
            warnings.append(f"unable to hash verification path {path}: {exc}")
            observations.append({"path": str(path), "exists": True, "readable": False})
            continue

        observation = {
            "path": str(path),
            "exists": True,
            "file_type": "file",
            "size_bytes": file_stat.st_size,
            "mtime_ns": file_stat.st_mtime_ns,
            "mode": oct(file_stat.st_mode & 0o777),
            "uid": file_stat.st_uid,
            "gid": file_stat.st_gid,
            "sha256": digest,
            "hashed_bytes": hashed_bytes,
            "hash_truncated": truncated,
        }

        if path.name.endswith(".gz"):
            try:
                with gzip.open(path, "rb") as stream:
                    content_digest, content_bytes, content_truncated = _bounded_sha256(
                        stream,
                        args.max_bytes,
                    )
                observation.update(
                    {
                        "gzip_valid": True if not content_truncated else None,
                        "content_sha256": content_digest,
                        "content_size_bytes": content_bytes,
                        "content_hash_truncated": content_truncated,
                    }
                )
                if content_truncated:
                    warnings.append(
                        f"gzip content validation stopped at byte limit: {path}"
                    )
            except (OSError, EOFError, gzip.BadGzipFile) as exc:
                observation.update(
                    {
                        "gzip_valid": False,
                        "content_sha256": None,
                        "content_size_bytes": 0,
                        "content_hash_truncated": False,
                    }
                )
                warnings.append(f"gzip verification failed for {path}: {exc}")

        observations.append(observation)

    return ToolResult(
        status="partial" if warnings else "ok",
        observations=observations,
        warnings=warnings[:10],
        evidence_refs=evidence_refs,
    )


def register_file_integrity_verifier(registry: ToolRegistry) -> None:
    registry.register(
        ToolDefinition(
            name="file_integrity_state",
            version="1.0.0",
            description=(
                "Read bounded metadata and hashes for allowlisted action files without "
                "returning file content."
            ),
            risk_level=RiskLevel.R0,
            input_model=FileIntegrityStateInput,
            output_model=ToolResult,
            handler=file_integrity_state,
            capability_requirements=("filesystem.read",),
        )
    )


def _required_path(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"verification payload missing path field: {key}")
    return str(Path(value).resolve(strict=False))


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing {key}")
    return value.strip()


def _service_state_observation(payload: dict[str, Any], unit: str) -> dict[str, Any] | None:
    observations = payload.get("observations")
    if not isinstance(observations, list):
        return None
    for item in observations:
        if not isinstance(item, dict):
            continue
        observed_unit = item.get("Id") or item.get("unit")
        if observed_unit == unit:
            return {
                **item,
                "Id": observed_unit,
                "LoadState": item.get(
                    "LoadState",
                    item.get("load_state", item.get("load")),
                ),
                "ActiveState": item.get(
                    "ActiveState",
                    item.get("active_state", item.get("active")),
                ),
                "SubState": item.get(
                    "SubState",
                    item.get("sub_state", item.get("sub")),
                ),
                "ExecMainPID": item.get(
                    "ExecMainPID",
                    item.get("main_pid"),
                ),
                "Result": item.get("Result", item.get("result")),
            }
    return None


def _config_state_observation(payload: dict[str, Any], path: str) -> dict[str, Any] | None:
    observations = payload.get("observations")
    if not isinstance(observations, list):
        return None
    normalized = str(Path(path))
    for item in observations:
        if not isinstance(item, dict):
            continue
        if item.get("path") == normalized:
            return item
    return None


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _first_observation(payload: dict[str, Any]) -> dict[str, Any]:
    observations = payload.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("action output is missing its primary observation")
    observation = observations[0]
    if not isinstance(observation, dict):
        raise ValueError("action output observation is not structured")
    return observation


def _observations_by_path(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    observations = payload.get("observations")
    if not isinstance(observations, list):
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        path = observation.get("path")
        if isinstance(path, str) and path:
            indexed[str(Path(path).resolve(strict=False))] = observation
    return indexed


def _complete_observation(
    observations: dict[str, dict[str, Any]],
    path: str,
    *,
    require_logical_content: bool = False,
) -> dict[str, Any] | None:
    observation = observations.get(str(Path(path).resolve(strict=False)))
    if observation is None:
        return None
    digest = observation.get("sha256")
    if (
        observation.get("exists") is not True
        or observation.get("file_type") != "file"
        or observation.get("hash_truncated") is not False
        or not isinstance(digest, str)
        or len(digest) != 64
    ):
        return None
    if require_logical_content and str(observation.get("path", "")).endswith(".gz"):
        content_digest = observation.get("content_sha256")
        if (
            observation.get("gzip_valid") is not True
            or observation.get("content_hash_truncated") is not False
            or not isinstance(content_digest, str)
            or len(content_digest) != 64
        ):
            return None
    return observation


def _logical_content_hash(observation: dict[str, Any]) -> str:
    if str(observation.get("path", "")).endswith(".gz"):
        value = observation.get("content_sha256")
    else:
        value = observation.get("sha256")
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("verification observation is missing a complete content hash")
    return value


def _invalid(reason: str) -> ActionVerificationDecision:
    return ActionVerificationDecision(valid=False, reason=reason, details={})


def _bounded_sha256(stream: BinaryIO, max_bytes: int) -> tuple[str, int, bool]:
    digest = hashlib.sha256()
    consumed = 0
    while consumed < max_bytes:
        chunk = stream.read(min(1024 * 1024, max_bytes - consumed))
        if not chunk:
            return digest.hexdigest(), consumed, False
        digest.update(chunk)
        consumed += len(chunk)
    return digest.hexdigest(), consumed, stream.read(1) != b""
