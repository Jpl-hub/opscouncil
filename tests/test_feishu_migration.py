from __future__ import annotations

from pathlib import Path
import tempfile

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FEISHU_TABLES = {
    "operators",
    "operator_external_identities",
    "channel_inbound_events",
    "task_channel_bindings",
    "channel_instances",
    "notification_outbox",
    "notification_deliveries",
    "approval_decision_tokens",
    "approval_decision_jobs",
}


def migration_config(database_url: str) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def test_upgrade_from_operational_memory_adds_governed_channel_schema() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'feishu-upgrade.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "0006_operational_memory")

        command.upgrade(config, "0007_feishu_channel")

        engine = create_engine(database_url, future=True)
        schema = inspect(engine)
        assert FEISHU_TABLES.issubset(set(schema.get_table_names()))
        with engine.connect() as connection:
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            local_admin = connection.execute(
                text("SELECT username, role, status FROM operators WHERE username='local-admin'")
            ).one()
        assert revision == "0007_feishu_channel"
        assert tuple(local_admin) == ("local-admin", "ADMIN", "ACTIVE")


def test_channel_schema_enforces_identity_and_decision_boundaries() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'feishu-constraints.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "head")
        engine = create_engine(database_url, future=True)

        with engine.begin() as connection:
            operator_id = connection.execute(
                text("SELECT id FROM operators WHERE username='local-admin'")
            ).scalar_one()
            connection.execute(
                text(
                    "INSERT INTO operator_external_identities "
                    "(operator_id, provider, tenant_key, external_user_id, status, created_at, updated_at) "
                    "VALUES (:operator_id, 'FEISHU', 'tenant-a', 'open-a', 'ACTIVE', "
                    "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                ),
                {"operator_id": operator_id},
            )

        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO operator_external_identities "
                        "(operator_id, provider, tenant_key, external_user_id, status, created_at, updated_at) "
                        "VALUES (:operator_id, 'FEISHU', 'tenant-a', 'open-a', 'ACTIVE', "
                        "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    ),
                    {"operator_id": operator_id},
                )
        except IntegrityError:
            pass
        else:
            raise AssertionError("the same Feishu identity must not map twice")

        try:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO operators "
                        "(username, display_name, role, status, created_at, updated_at) "
                        "VALUES ('invalid-role', 'invalid', 'ROOT', 'ACTIVE', "
                        "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    )
                )
        except IntegrityError:
            pass
        else:
            raise AssertionError("unknown operator roles must be rejected")


def test_downgrade_removes_only_feishu_channel_tables() -> None:
    with tempfile.TemporaryDirectory(dir="/tmp") as temp_dir:
        database_url = f"sqlite+pysqlite:///{Path(temp_dir) / 'feishu-downgrade.db'}"
        config = migration_config(database_url)
        command.upgrade(config, "head")

        command.downgrade(config, "0006_operational_memory")

        engine = create_engine(database_url, future=True)
        tables = set(inspect(engine).get_table_names())
        assert not (FEISHU_TABLES & tables)
        assert "operational_memories" in tables
        with engine.connect() as connection:
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert revision == "0006_operational_memory"
