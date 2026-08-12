"""hybrid knowledge

Revision ID: 0005_hybrid_knowledge
Revises: 0004_patrol_incidents
Create Date: 2026-07-12 15:20:00.000000
"""
from typing import Sequence, Union
import re

from alembic import op
import jieba
import sqlalchemy as sa


revision: str = "0005_hybrid_knowledge"
down_revision: Union[str, Sequence[str], None] = "0004_patrol_incidents"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "knowledge_documents",
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
    )
    op.add_column(
        "knowledge_documents",
        sa.Column("status", sa.String(length=16), nullable=False, server_default="ACTIVE"),
    )
    op.create_index(
        op.f("ix_knowledge_documents_status"),
        "knowledge_documents",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_knowledge_documents_status_type",
        "knowledge_documents",
        ["status", "source_type"],
        unique=False,
    )

    op.add_column(
        "knowledge_chunks",
        sa.Column("search_text", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "knowledge_chunks",
        sa.Column("chunk_kind", sa.String(length=64), nullable=False, server_default="content"),
    )

    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT id, content FROM knowledge_chunks")).mappings()
    for row in rows:
        connection.execute(
            sa.text("UPDATE knowledge_chunks SET search_text=:search_text WHERE id=:chunk_id"),
            {"chunk_id": row["id"], "search_text": _tokenize(row["content"])},
        )

    if connection.dialect.name == "postgresql":
        op.create_check_constraint(
            "ck_knowledge_documents_version",
            "knowledge_documents",
            "version >= 1",
        )
        op.create_check_constraint(
            "ck_knowledge_documents_status",
            "knowledge_documents",
            "status IN ('ACTIVE', 'INACTIVE')",
        )
        op.execute(
            "CREATE INDEX ix_knowledge_chunks_search_tsv "
            "ON knowledge_chunks USING gin (to_tsvector('simple', search_text))"
        )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        op.execute("DROP INDEX IF EXISTS ix_knowledge_chunks_search_tsv")
        op.drop_constraint(
            "ck_knowledge_documents_status",
            "knowledge_documents",
            type_="check",
        )
        op.drop_constraint(
            "ck_knowledge_documents_version",
            "knowledge_documents",
            type_="check",
        )
    op.drop_column("knowledge_chunks", "chunk_kind")
    op.drop_column("knowledge_chunks", "search_text")
    op.drop_index("ix_knowledge_documents_status_type", table_name="knowledge_documents")
    op.drop_index(op.f("ix_knowledge_documents_status"), table_name="knowledge_documents")
    op.drop_column("knowledge_documents", "status")
    op.drop_column("knowledge_documents", "version")


def _tokenize(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip().lower())
    return " ".join(
        token.strip()
        for token in jieba.cut(normalized, cut_all=False)
        if token.strip() and re.search(r"[a-z0-9_\-\u4e00-\u9fff]", token)
    )
