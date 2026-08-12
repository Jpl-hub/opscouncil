from __future__ import annotations

from dataclasses import dataclass
import getpass
import os
import shutil
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from backend.app.core.config import settings
from backend.app.mcp.registry import ToolRegistry


REQUIRED_COMMANDS = ("journalctl", "ss", "ps")


@dataclass(frozen=True)
class DeploymentEnvironment:
    app_env: str
    frontend_index: str | Path
    database_url: str
    ai_key_configured: bool
    chat_model: str
    embedding_model: str

    @classmethod
    def from_settings(cls) -> "DeploymentEnvironment":
        return cls(
            app_env=settings.app_env,
            frontend_index=settings.frontend_dist_dir / "index.html",
            database_url=settings.database_url,
            ai_key_configured=bool(settings.bailian_api_key),
            chat_model=settings.bailian_chat_model,
            embedding_model=settings.bailian_embedding_model,
        )


class DeploymentReadinessService:
    def __init__(
        self,
        registry: ToolRegistry,
        command_exists: Callable[[str], bool] | None = None,
        runtime_user: Callable[[], tuple[str, int]] | None = None,
        environment: DeploymentEnvironment | None = None,
        path_exists: Callable[[Path], bool] | None = None,
        database_probe: Callable[[str], dict[str, Any]] | None = None,
    ) -> None:
        self.registry = registry
        self.command_exists = command_exists or (lambda command: shutil.which(command) is not None)
        self.runtime_user = runtime_user or _runtime_user
        self.environment = environment or DeploymentEnvironment.from_settings()
        self.path_exists = path_exists or (lambda path: path.exists())
        self.database_probe = database_probe or _probe_database

    def read(self) -> dict[str, Any]:
        snapshot = self._snapshot()
        os_release = snapshot.get("os_release") if isinstance(snapshot.get("os_release"), dict) else {}
        runtime_name, runtime_uid = self.runtime_user()
        frontend_index = Path(self.environment.frontend_index)
        frontend_ready = self.path_exists(frontend_index)
        checks = [
            self._os_check(snapshot, os_release),
            self._arch_check(snapshot),
            self._tools_check(),
            self._mcp_check(),
            self._database_check(),
            self._frontend_check(frontend_index, frontend_ready),
            self._model_check(),
            self._executor_check(runtime_name, runtime_uid),
        ]
        overall_status = _overall_status(checks)
        return {
            "overall_status": overall_status,
            "summary": _summary(overall_status),
            "platform": {
                "hostname": snapshot.get("hostname"),
                "machine": snapshot.get("machine"),
                "kernel": snapshot.get("kernel"),
                "os": os_release.get("pretty_name") or os_release.get("name") or "-",
                "version_id": os_release.get("version_id"),
                "os_family": snapshot.get("os_family") or "linux",
                "is_loongarch": bool(snapshot.get("is_loongarch")),
            },
            "executor": {
                "runtime_user": runtime_name,
                "runtime_uid": runtime_uid,
                "root_runtime": runtime_uid == 0,
            },
            "environment": {
                "app_env": self.environment.app_env,
                "frontend_index": str(frontend_index),
                "frontend_ready": frontend_ready,
                "database": _database_kind(self.environment.database_url),
                "model_configured": self.environment.ai_key_configured,
                "chat_model": self.environment.chat_model,
                "embedding_model": self.environment.embedding_model,
            },
            "checks": checks,
        }

    def _snapshot(self) -> dict[str, Any]:
        try:
            result = self.registry.call("system_snapshot", {})
        except Exception as exc:
            return {"snapshot_error": str(exc)}
        observations = result.model_dump(mode="json").get("observations", [])
        if observations and isinstance(observations[0], dict):
            return observations[0]
        return {}

    def _os_check(
        self,
        snapshot: dict[str, Any],
        os_release: dict[str, Any],
    ) -> dict[str, str]:
        version_text = " ".join(
            str(os_release.get(key) or "")
            for key in ("pretty_name", "name", "version")
        ).strip()
        is_linux = str(snapshot.get("os_family") or "linux").lower() == "linux"
        identified = bool(os_release.get("id") or os_release.get("name") or version_text)
        return {
            "key": "os",
            "name": "Linux 运行环境",
            "status": "ok" if is_linux and identified else "blocked",
            "detail": version_text or "未读取到 /etc/os-release",
        }

    def _arch_check(self, snapshot: dict[str, Any]) -> dict[str, str]:
        machine = str(snapshot.get("machine") or "-")
        supported = machine.lower() in {
            "x86_64",
            "amd64",
            "aarch64",
            "arm64",
            "loongarch64",
            "riscv64",
        }
        return {
            "key": "arch",
            "name": "处理器架构",
            "status": "ok" if supported else "warn",
            "detail": machine,
        }

    def _tools_check(self) -> dict[str, Any]:
        missing = [command for command in REQUIRED_COMMANDS if not self.command_exists(command)]
        return {
            "key": "tools",
            "name": "运维工具链",
            "status": "blocked" if missing else "ok",
            "detail": "缺失：" + "、".join(missing) if missing else "journalctl、ss、ps 可用",
            "missing": missing,
        }

    def _mcp_check(self) -> dict[str, Any]:
        try:
            tools = self.registry.list_tools()
        except Exception as exc:
            return {
                "key": "mcp",
                "name": "MCP 工具注册",
                "status": "blocked",
                "detail": f"工具注册表不可读：{_short_error(exc)}",
                "evidence": [],
            }
        tool_names = [str(tool.get("name") or "-") for tool in tools]
        count = len(tool_names)
        return {
            "key": "mcp",
            "name": "MCP 工具注册",
            "status": "ok" if count >= 4 else "blocked",
            "detail": f"已注册 {count} 个 MCP 工具",
            "evidence": tool_names[:8],
        }

    def _database_check(self) -> dict[str, Any]:
        database_url = self.environment.database_url
        kind = _database_kind(database_url)
        if kind != "postgresql":
            return {
                "key": "database",
                "name": "PostgreSQL / pgvector",
                "status": "warn" if self.environment.app_env == "development" else "blocked",
                "detail": "当前不是 PostgreSQL；生产部署需启用 PostgreSQL 与 pgvector。",
                "evidence": [kind],
            }
        result = self.database_probe(database_url)
        status = str(result.get("status") or "blocked")
        if status not in {"ok", "warn", "blocked"}:
            status = "blocked"
        return {
            "key": "database",
            "name": "PostgreSQL / pgvector",
            "status": status,
            "detail": str(result.get("detail") or "数据库检查未返回细节"),
            "evidence": result.get("evidence", []),
        }

    def _frontend_check(self, index_path: Path, frontend_ready: bool) -> dict[str, Any]:
        if frontend_ready:
            status = "ok"
            detail = f"前端入口已生成：{index_path}"
        else:
            status = "warn" if self.environment.app_env == "development" else "blocked"
            detail = f"未找到前端入口：{index_path}"
        return {
            "key": "frontend",
            "name": "B/S 前端产物",
            "status": status,
            "detail": detail,
        }

    def _model_check(self) -> dict[str, Any]:
        configured = self.environment.ai_key_configured
        return {
            "key": "model",
            "name": "大模型服务",
            "status": "ok" if configured else "warn",
            "detail": (
                f"{self.environment.chat_model} / {self.environment.embedding_model}"
                if configured
                else "未配置模型密钥；智能研判与向量化能力不可用。"
            ),
            "evidence": [self.environment.chat_model, self.environment.embedding_model],
        }

    def _executor_check(self, runtime_name: str, runtime_uid: int) -> dict[str, Any]:
        return {
            "key": "executor",
            "name": "最小权限运行",
            "status": "blocked" if runtime_uid == 0 else "ok",
            "detail": f"{runtime_name} / uid {runtime_uid}",
        }


def _runtime_user() -> tuple[str, int]:
    return getpass.getuser(), os.geteuid() if hasattr(os, "geteuid") else -1


def _database_kind(database_url: str) -> str:
    if database_url.startswith("postgresql"):
        return "postgresql"
    if database_url.startswith("sqlite"):
        return "sqlite"
    return "unknown"


def _probe_database(database_url: str) -> dict[str, Any]:
    try:
        engine = create_engine(
            database_url,
            connect_args={"connect_timeout": 2} if database_url.startswith("postgresql") else {},
            future=True,
        )
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                vector_enabled = connection.execute(
                    text("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
                ).scalar()
        finally:
            engine.dispose()
    except SQLAlchemyError as exc:
        return {
            "status": "blocked",
            "detail": f"数据库连接或扩展检查失败：{_short_error(exc)}",
            "evidence": ["postgresql"],
        }
    return {
        "status": "ok" if vector_enabled else "blocked",
        "detail": "PostgreSQL 可连接，pgvector 已启用" if vector_enabled else "PostgreSQL 可连接，但 pgvector 未启用",
        "evidence": ["postgresql", "pgvector" if vector_enabled else "pgvector_missing"],
    }


def _short_error(exc: BaseException) -> str:
    message = str(exc).replace("\n", " ").strip()
    return message[:180] if message else exc.__class__.__name__


def _overall_status(checks: list[dict[str, Any]]) -> str:
    if any(check["status"] == "blocked" for check in checks):
        return "blocked"
    if any(check["status"] == "warn" for check in checks):
        return "warn"
    return "ok"


def _summary(status: str) -> str:
    if status == "ok":
        return "Linux 平台与运行边界满足部署要求。"
    if status == "blocked":
        return "存在阻断项，部署前需要处理工具链或运行身份。"
    return "当前环境可运行，但仍有建议项需要复核。"
