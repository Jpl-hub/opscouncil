from __future__ import annotations

from typing import Any

from sqlalchemy import func, or_, select, text

from backend.app.knowledge.retrieval import (
    CandidateText,
    HybridKnowledgeRetriever,
    RankedCandidate,
    tsquery_from_search_text,
)
from backend.app.models.entities import OperationalMemory, utcnow
from backend.app.memory.integrity import verify_memory_content


class OperationalMemoryRetriever(HybridKnowledgeRetriever):
    source_kind = "memory"
    telemetry_stage_prefix = "memory"
    minimum_rerank_score = 0.65

    def __init__(
        self,
        session,
        model_client: Any,
        *,
        host_scope: str | None,
        service_scope: str | None,
    ) -> None:  # type: ignore[no-untyped-def]
        super().__init__(session, model_client)
        self.host_scope = _requested_scope(host_scope)
        self.service_scope = _requested_scope(service_scope)

    def _index_ready(self) -> bool:
        total, vector_count, lexical_count = self.session.execute(
            select(
                func.count(OperationalMemory.id),
                func.count(OperationalMemory.id).filter(OperationalMemory.embedding.is_not(None)),
                func.count(OperationalMemory.id).filter(OperationalMemory.search_text != ""),
            ).where(*confirmed_scope_filters(self.host_scope, self.service_scope))
        ).one()
        return int(total or 0) > 0 and int(total) == int(vector_count or 0) == int(lexical_count or 0)

    def _lexical_candidates(self, query_text: str, limit: int) -> list[RankedCandidate]:
        tsquery = tsquery_from_search_text(query_text)
        if not tsquery:
            return []
        scope_sql, params = _scope_sql(self.host_scope, self.service_scope)
        rows = self.session.execute(
            text(
                f"""
                SELECT om.id AS chunk_id,
                       ts_rank_cd(
                           to_tsvector('simple', om.search_text),
                           to_tsquery('simple', :tsquery)
                       ) AS score
                 FROM operational_memories AS om
                 WHERE om.status = 'CONFIRMED'
                   AND om.qualification_status = 'QUALIFIED'
                   {scope_sql}
                   AND to_tsvector('simple', om.search_text) @@ to_tsquery('simple', :tsquery)
                 ORDER BY score DESC, om.id ASC
                 LIMIT :candidate_limit
                """
            ),
            {**params, "tsquery": tsquery, "candidate_limit": limit},
        ).all()
        return [RankedCandidate(chunk_id=int(row.chunk_id), score=float(row.score)) for row in rows]

    def _vector_candidates(self, query_vector: list[float], limit: int) -> list[RankedCandidate]:
        distance = OperationalMemory.embedding.cosine_distance(query_vector).label("distance")
        rows = self.session.execute(
            select(OperationalMemory.id, distance)
            .where(
                *confirmed_scope_filters(self.host_scope, self.service_scope),
                OperationalMemory.embedding.is_not(None),
            )
            .order_by(distance, OperationalMemory.id.asc())
            .limit(limit)
        ).all()
        return [RankedCandidate(chunk_id=int(row[0]), score=float(row[1])) for row in rows]

    def _load_candidates(self, chunk_ids: list[int]) -> dict[int, CandidateText]:
        memories = list(
            self.session.scalars(
                select(OperationalMemory).where(
                    OperationalMemory.id.in_(chunk_ids),
                    *confirmed_scope_filters(self.host_scope, self.service_scope),
                )
            )
        )
        return {
            memory.id: CandidateText(
                chunk_id=memory.id,
                document_id=memory.id,
                title=memory.title,
                source_uri=f"memory://{memory.memory_key}/v{memory.version}",
                trust_level="operator_confirmed",
                content=(
                    f"主机作用域：{memory.host_scope}\n"
                    f"服务作用域：{memory.service_scope}\n"
                    f"经验可信分：{memory.confidence_score}\n"
                    f"有效期至：{memory.valid_until.isoformat() if memory.valid_until else '长期有效'}\n"
                    f"有效反馈：{memory.helpful_count}\n"
                    f"根因：{memory.root_cause}\n"
                    f"处置：{memory.resolution}"
                ),
            )
            for memory in memories
            if verify_memory_content(memory)
        }


def confirmed_scope_filters(
    host_scope: str | None,
    service_scope: str | None,
) -> list[Any]:
    filters: list[Any] = [
        OperationalMemory.status == "CONFIRMED",
        OperationalMemory.qualification_status == "QUALIFIED",
        or_(
            OperationalMemory.valid_until.is_(None),
            OperationalMemory.valid_until > utcnow(),
        ),
    ]
    normalized_host = _requested_scope(host_scope)
    normalized_service = _requested_scope(service_scope)
    if normalized_host is None:
        filters.append(OperationalMemory.host_scope == "*")
    else:
        filters.append(or_(OperationalMemory.host_scope == "*", OperationalMemory.host_scope == normalized_host))
    if normalized_service is not None:
        filters.append(
            or_(
                OperationalMemory.service_scope == "*",
                OperationalMemory.service_scope == normalized_service,
            )
        )
    return filters


def _scope_sql(host_scope: str | None, service_scope: str | None) -> tuple[str, dict[str, str]]:
    clauses: list[str] = []
    params: dict[str, str] = {}
    if host_scope is None:
        clauses.append("AND om.host_scope = '*'")
    else:
        clauses.append("AND (om.host_scope = '*' OR om.host_scope = :host_scope)")
        params["host_scope"] = host_scope
    if service_scope is not None:
        clauses.append("AND (om.service_scope = '*' OR om.service_scope = :service_scope)")
        params["service_scope"] = service_scope
    return "\n".join(clauses), params


def _requested_scope(value: str | None) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None
