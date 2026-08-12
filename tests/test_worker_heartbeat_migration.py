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


def test_upgrade_adds_worker_heartbeat_table() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'worker-heartbeat.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "0008_model_invocations")

        command.upgrade(config, "0009_worker_heartbeat")

        engine = create_engine(database_url, future=True)
        schema = inspect(engine)
        columns = {column["name"] for column in schema.get_columns("worker_instances")}
        assert {
            "worker_id",
            "hostname",
            "pid",
            "status",
            "started_at",
            "last_seen_at",
            "updated_at",
        }.issubset(columns)
        with engine.connect() as connection:
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert revision == "0009_worker_heartbeat"


def test_worker_heartbeat_constraints_reject_invalid_pid() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'worker-constraints.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "head")
        engine = create_engine(database_url, future=True)

        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO worker_instances "
                        "(worker_id, hostname, pid, status, started_at, last_seen_at, updated_at) "
                        "VALUES ('worker-invalid', 'linux-node', 0, 'RUNNING', CURRENT_TIMESTAMP, "
                        "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    )
                )
        except IntegrityError:
            pass
        else:
            raise AssertionError("worker heartbeat pid must be positive")


def test_downgrade_preserves_model_observability_schema() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'worker-downgrade.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "head")

        command.downgrade(config, "0008_model_invocations")

        engine = create_engine(database_url, future=True)
        tables = set(inspect(engine).get_table_names())
        assert "worker_instances" not in tables
        assert "model_invocations" in tables
