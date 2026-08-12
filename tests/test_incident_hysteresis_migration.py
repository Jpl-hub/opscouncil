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


def test_upgrade_backfills_incident_recovery_state() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'incident-hysteresis.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "0009_worker_heartbeat")
        engine = create_engine(database_url, future=True)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO incidents "
                    "(host_key, signal_key, dedupe_key, status, severity, title, summary, "
                    "opened_at, updated_at) VALUES "
                    "('node-a', 'disk_pressure', 'node-a:disk_pressure', 'OPEN', 'WARN', "
                    "'磁盘压力', '根分区使用率偏高', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                )
            )

        command.upgrade(config, "0010_incident_hysteresis")

        columns = {column["name"] for column in inspect(engine).get_columns("incidents")}
        assert {"healthy_streak", "recovery_target", "last_healthy_at"}.issubset(columns)
        with engine.connect() as connection:
            state = connection.execute(
                text("SELECT healthy_streak, recovery_target, last_healthy_at FROM incidents")
            ).one()
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert tuple(state) == (0, 2, None)
        assert revision == "0010_incident_hysteresis"


def test_recovery_target_constraint_rejects_invalid_value() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'incident-constraint.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "head")
        engine = create_engine(database_url, future=True)
        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO incidents "
                        "(host_key, signal_key, status, severity, title, summary, recovery_target, "
                        "opened_at, updated_at) VALUES "
                        "('node-a', 'disk_pressure', 'OPEN', 'WARN', '磁盘压力', "
                        "'根分区使用率偏高', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    )
                )
        except IntegrityError:
            pass
        else:
            raise AssertionError("incident recovery target must be between 1 and 12")


def test_downgrade_removes_only_recovery_state() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'incident-downgrade.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "head")

        command.downgrade(config, "0009_worker_heartbeat")

        engine = create_engine(database_url, future=True)
        columns = {column["name"] for column in inspect(engine).get_columns("incidents")}
        assert "healthy_streak" not in columns
        assert "recovery_target" not in columns
        assert "last_healthy_at" not in columns
        assert "worker_instances" in inspect(engine).get_table_names()
