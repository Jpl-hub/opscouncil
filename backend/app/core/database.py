from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.app.core.config import ROOT_DIR, settings


class Base(DeclarativeBase):
    pass


engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
    future=True,
)


@event.listens_for(Engine, "connect")
def set_sqlite_pragmas(dbapi_connection, connection_record) -> None:  # type: ignore[no-untyped-def]
    if not settings.database_url.startswith("sqlite"):
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def assert_schema_current(
    target_engine: Engine = engine,
    *,
    script_location: Path | None = None,
) -> None:
    migration_config = Config()
    migration_config.set_main_option(
        "script_location",
        str(script_location or ROOT_DIR / "migrations"),
    )
    expected_revision = ScriptDirectory.from_config(migration_config).get_current_head()
    with target_engine.connect() as connection:
        actual_revision = MigrationContext.configure(connection).get_current_revision()
    if actual_revision != expected_revision:
        raise RuntimeError(
            "database schema is not current: "
            f"expected {expected_revision}, found {actual_revision or 'unversioned'}; "
            "run 'alembic upgrade head' before starting OpsCouncil"
        )


def init_db() -> None:
    with engine.begin() as connection:
        if settings.database_url.startswith("postgresql"):
            connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    assert_schema_current()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    with session_scope() as session:
        yield session
