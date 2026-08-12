from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parents[3]
load_dotenv(ROOT_DIR / ".env")


def _csv_env(name: str) -> tuple[str, ...]:
    return tuple(
        item.strip()
        for item in os.getenv(name, "").split(",")
        if item.strip()
    )


@dataclass(frozen=True)
class Settings:
    app_name: str = "OpsCouncil"
    app_env: str = os.getenv("APP_ENV", "development")
    frontend_dist_dir: Path = Path(os.getenv("OPSCOUNCIL_FRONTEND_DIST", str(ROOT_DIR / "frontend" / "dist")))
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://opscouncil@127.0.0.1:5432/opscouncil",
    )
    embedding_dim: int = int(os.getenv("EMBEDDING_DIM", "1024"))
    bailian_api_key: str = os.getenv("BAILIAN_API_KEY", os.getenv("DASHSCOPE_API_KEY", ""))
    bailian_base_url: str = os.getenv(
        "BAILIAN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"
    )
    bailian_chat_model: str = os.getenv("BAILIAN_CHAT_MODEL", "qwen-plus-latest")
    bailian_embedding_model: str = os.getenv("BAILIAN_EMBEDDING_MODEL", "text-embedding-v4")
    bailian_rerank_model: str = os.getenv("BAILIAN_RERANK_MODEL", "qwen3-rerank")
    bailian_rerank_base_url: str = os.getenv(
        "BAILIAN_RERANK_BASE_URL", "https://dashscope.aliyuncs.com/compatible-api/v1"
    )
    investigation_max_iterations: int = int(os.getenv("OPSCOUNCIL_INVESTIGATION_MAX_ITERATIONS", "4"))
    investigation_max_tool_calls: int = int(os.getenv("OPSCOUNCIL_INVESTIGATION_MAX_TOOL_CALLS", "12"))
    investigation_max_elapsed_ms: int = int(os.getenv("OPSCOUNCIL_INVESTIGATION_MAX_ELAPSED_MS", "120000"))
    lab_evaluation_task_timeout_seconds: float = float(
        os.getenv("OPSCOUNCIL_LAB_EVALUATION_TASK_TIMEOUT_SECONDS", "420")
    )
    patrol_enabled: bool = os.getenv("OPSCOUNCIL_PATROL_ENABLED", "true").lower() in {"1", "true", "yes"}
    patrol_seed_default_policy: bool = os.getenv("OPSCOUNCIL_PATROL_SEED_DEFAULT_POLICY", "true").lower() in {
        "1",
        "true",
        "yes",
    }
    patrol_interval_seconds: int = int(os.getenv("OPSCOUNCIL_PATROL_INTERVAL_SECONDS", "300"))
    worker_heartbeat_seconds: float = float(os.getenv("OPSCOUNCIL_WORKER_HEARTBEAT_SECONDS", "5"))
    worker_stale_seconds: int = int(os.getenv("OPSCOUNCIL_WORKER_STALE_SECONDS", "20"))
    worker_queue_warn_seconds: int = int(os.getenv("OPSCOUNCIL_WORKER_QUEUE_WARN_SECONDS", "60"))
    feishu_default_chat_id: str = os.getenv("OPSCOUNCIL_FEISHU_DEFAULT_CHAT_ID", "").strip()
    feishu_enabled: bool = os.getenv("OPSCOUNCIL_FEISHU_ENABLED", "false").lower() in {
        "1",
        "true",
        "yes",
    }
    channel_internal_token: str = os.getenv("OPSCOUNCIL_CHANNEL_INTERNAL_TOKEN", "").strip()
    executor_mode: str = os.getenv("OPSCOUNCIL_EXECUTOR_MODE", "restricted-local")
    executor_user: str = os.getenv("OPSCOUNCIL_EXECUTOR_USER", "opscouncil-agent")
    allow_root_executor: bool = os.getenv("OPSCOUNCIL_ALLOW_ROOT_EXECUTOR", "false").lower() in {"1", "true", "yes"}
    restartable_systemd_units: tuple[str, ...] = _csv_env("OPSCOUNCIL_RESTARTABLE_UNITS")
    repairable_config_paths: tuple[str, ...] = _csv_env("OPSCOUNCIL_REPAIRABLE_CONFIG_PATHS")
    agentteams_matrix_url: str = os.getenv("AGENTTEAMS_MATRIX_URL", "").strip()
    agentteams_username: str = os.getenv("AGENTTEAMS_USERNAME", "").strip()
    agentteams_password: str = os.getenv("AGENTTEAMS_PASSWORD", "").strip()
    agentteams_leader_room_id: str = os.getenv("AGENTTEAMS_LEADER_ROOM_ID", "").strip()
    agentteams_callback_secret: str = os.getenv("AGENTTEAMS_CALLBACK_SECRET", "").strip()


settings = Settings()


def ensure_runtime_dirs() -> None:
    (ROOT_DIR / "data").mkdir(exist_ok=True)
    (ROOT_DIR / "data" / "artifacts").mkdir(parents=True, exist_ok=True)
    (ROOT_DIR / "data" / "index").mkdir(parents=True, exist_ok=True)
