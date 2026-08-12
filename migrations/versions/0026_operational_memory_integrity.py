"""bind operational memory content and evidence to a version hash chain

Revision ID: 0026_memory_integrity
Revises: 0025_listener_expectations
Create Date: 2026-07-30 19:10:00.000000
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0026_memory_integrity"
down_revision: Union[str, Sequence[str], None] = "0025_listener_expectations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_CONTRACT = "operational-memory-content.v1"


def upgrade() -> None:
    op.add_column(
        "operational_memories",
        sa.Column("content_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "operational_memories",
        sa.Column("parent_content_hash", sa.String(length=64), nullable=True),
    )

    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT id, memory_key, version, source_task_id, supersedes_id,
                   host_scope, service_scope, symptom_fingerprint,
                   applicability_json, confidence_score, title, root_cause,
                   resolution, evidence_refs_json, created_by
              FROM operational_memories
             ORDER BY memory_key, version, id
            """
        )
    ).mappings()
    previous_by_key: dict[str, str] = {}
    for row in rows:
        memory_key = str(row["memory_key"])
        parent_hash = previous_by_key.get(memory_key)
        content_hash = _content_hash(row, parent_hash)
        bind.execute(
            sa.text(
                """
                UPDATE operational_memories
                   SET content_hash = :content_hash,
                       parent_content_hash = :parent_content_hash
                 WHERE id = :memory_id
                """
            ),
            {
                "content_hash": content_hash,
                "parent_content_hash": parent_hash,
                "memory_id": row["id"],
            },
        )
        previous_by_key[memory_key] = content_hash

    with op.batch_alter_table("operational_memories") as batch_op:
        batch_op.alter_column(
            "content_hash",
            existing_type=sa.String(length=64),
            nullable=False,
        )
        batch_op.create_check_constraint(
            "ck_operational_memories_content_hash",
            "length(content_hash) = 64",
        )
        batch_op.create_check_constraint(
            "ck_operational_memories_parent_content_hash",
            "parent_content_hash IS NULL OR length(parent_content_hash) = 64",
        )
        batch_op.create_index(
            "ix_operational_memories_content_hash",
            ["content_hash"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("operational_memories") as batch_op:
        batch_op.drop_index("ix_operational_memories_content_hash")
        batch_op.drop_constraint(
            "ck_operational_memories_parent_content_hash",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_operational_memories_content_hash",
            type_="check",
        )
        batch_op.drop_column("parent_content_hash")
        batch_op.drop_column("content_hash")


def _content_hash(row: Any, parent_hash: str | None) -> str:
    payload = {
        "contract": _CONTRACT,
        "memory_key": str(row["memory_key"] or ""),
        "version": int(row["version"] or 0),
        "source_task_id": int(row["source_task_id"] or 0),
        "supersedes_id": row["supersedes_id"],
        "host_scope": str(row["host_scope"] or ""),
        "service_scope": str(row["service_scope"] or ""),
        "symptom_fingerprint": str(row["symptom_fingerprint"] or ""),
        "applicability": row["applicability_json"] or {},
        "confidence_score": int(row["confidence_score"] or 0),
        "title": str(row["title"] or ""),
        "root_cause": str(row["root_cause"] or ""),
        "resolution": str(row["resolution"] or ""),
        "evidence_refs": row["evidence_refs_json"] or [],
        "created_by": str(row["created_by"] or ""),
        "parent_content_hash": parent_hash,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
