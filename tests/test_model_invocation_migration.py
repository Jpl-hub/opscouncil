from __future__ import annotations

from pathlib import Path
import tempfile

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def migration_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def test_upgrade_adds_bounded_model_invocation_ledger() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'model-invocations.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "0007_feishu_channel")

        command.upgrade(config, "0008_model_invocations")

        engine = create_engine(database_url, future=True)
        schema = inspect(engine)
        columns = {column["name"] for column in schema.get_columns("model_invocations")}
        assert {
            "task_id",
            "trace_id",
            "stage",
            "operation",
            "model",
            "duration_ms",
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "finish_reason",
            "error_category",
            "prompt_hash",
        }.issubset(columns)
        assert not {"prompt", "messages", "response", "api_key", "request_body"} & columns
        with engine.connect() as connection:
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert revision == "0008_model_invocations"


def test_model_invocation_constraints_reject_negative_tokens() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'model-constraints.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "head")
        engine = create_engine(database_url, future=True)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO tasks (trace_id, user_input, intent, status, risk_level, created_at, updated_at) "
                    "VALUES ('trace-model', '检查负载', 'general_system_health', 'SEALED', 'R0', "
                    "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                )
            )
            task_id = connection.execute(
                text("SELECT id FROM tasks WHERE trace_id='trace-model'")
            ).scalar_one()

        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO model_invocations "
                        "(task_id, trace_id, stage, operation, provider, model, status, duration_ms, "
                        "input_tokens, output_tokens, total_tokens, prompt_hash, created_at) VALUES "
                        "(:task_id, 'trace-model', 'intent', 'CHAT', 'bailian', 'qwen', 'SUCCEEDED', "
                        "10, -1, 2, 1, :prompt_hash, CURRENT_TIMESTAMP)"
                    ),
                    {"task_id": task_id, "prompt_hash": "a" * 64},
                )
        except IntegrityError:
            pass
        else:
            raise AssertionError("negative model token counts must be rejected")


def test_downgrade_preserves_feishu_channel_schema() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'model-downgrade.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "head")

        command.downgrade(config, "0007_feishu_channel")

        engine = create_engine(database_url, future=True)
        tables = set(inspect(engine).get_table_names())
        assert "model_invocations" not in tables
        assert "notification_outbox" in tables
