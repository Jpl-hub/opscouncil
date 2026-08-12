from __future__ import annotations

from datetime import datetime, timezone
import math
import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.evaluations.store import EvaluationReportStore
from backend.app.memory.integrity import (
    inspect_memory_version_chains,
    verify_memory_content,
)
from backend.app.models.entities import OperationalMemory, utcnow


class OperationalMemoryEvaluationService:
    def __init__(self, session: Session, memory_service: Any) -> None:
        self.session = session
        self.memory_service = memory_service
        self.store = EvaluationReportStore(session, "OPERATIONAL_MEMORY")

    def run(self, *, limit: int = 8) -> dict[str, Any]:
        started_at = utcnow()
        memories = list(
            self.session.scalars(
                select(OperationalMemory).order_by(
                    OperationalMemory.updated_at.desc(),
                    OperationalMemory.id.desc(),
                )
            )
        )
        integrity_failures = inspect_memory_version_chains(memories)
        integrity_case = _integrity_case(memories, integrity_failures)
        integrity_cases = [integrity_case] if integrity_case is not None else []
        eligible = [memory for memory in memories if _is_retrievable(memory)][: max(1, min(limit, 20))]
        ineligible = [memory for memory in memories if not _is_retrievable(memory)]
        report_id = uuid.uuid4().hex
        if not eligible:
            integrity_failed = bool(integrity_failures)
            passed_count = sum(item["passed"] is True for item in integrity_cases)
            report = {
                "id": report_id,
                "report_type": "OPERATIONAL_MEMORY",
                "started_at": started_at.isoformat(),
                "completed_at": utcnow().isoformat(),
                "overall_status": "failed" if integrity_failed else "prerequisite_missing",
                "qualification_status": "failed" if integrity_failed else "prerequisite_missing",
                "summary": {
                    "memory_count": len(memories),
                    "eligible_count": 0,
                    "case_count": len(integrity_cases),
                    "passed_count": passed_count,
                    "top1_recall_rate": None,
                    "scope_isolation_rate": None,
                    "state_exclusion_rate": None,
                    "content_integrity_rate": _integrity_rate(
                        memories, integrity_failures
                    ),
                    "average_retrieval_ms": None,
                    "p95_retrieval_ms": None,
                },
                "model": _model_identity(self.memory_service),
                "cases": integrity_cases,
                "reason_codes": (
                    ["memory_content_integrity_failed"]
                    if integrity_failed
                    else ["confirmed_memory_required"]
                ),
            }
            self.store.save(report)
            return report

        cases: list[dict[str, Any]] = list(integrity_cases)
        retrieval_durations: list[int] = []
        observed_hit_ids: set[int] = set()
        for memory in eligible:
            query = _evaluation_query(memory)
            recall_case, hit_ids, duration_ms = self._search_case(
                case_id=f"recall-{memory.id}",
                category="RECALL",
                title=memory.title,
                query=query,
                host_scope=_query_scope(memory.host_scope),
                service_scope=_query_scope(memory.service_scope),
                expected_memory_id=memory.id,
                expect_present=True,
            )
            cases.append(recall_case)
            retrieval_durations.append(duration_ms)
            observed_hit_ids.update(hit_ids)

            if memory.host_scope != "*":
                scope_case, scope_hit_ids, scope_duration_ms = self._search_case(
                    case_id=f"scope-{memory.id}",
                    category="SCOPE_ISOLATION",
                    title=memory.title,
                    query=query,
                    host_scope=f"__scope_probe_{memory.id}__",
                    service_scope=_query_scope(memory.service_scope),
                    expected_memory_id=memory.id,
                    expect_present=False,
                )
                cases.append(scope_case)
                retrieval_durations.append(scope_duration_ms)
                observed_hit_ids.update(scope_hit_ids)

        for memory in ineligible[:3]:
            exclusion_case, hit_ids, duration_ms = self._search_case(
                case_id=f"state-{memory.id}",
                category="STATE_EXCLUSION",
                title=memory.title,
                query=_evaluation_query(memory),
                host_scope=_query_scope(memory.host_scope),
                service_scope=_query_scope(memory.service_scope),
                expected_memory_id=memory.id,
                expect_present=False,
            )
            cases.append(exclusion_case)
            retrieval_durations.append(duration_ms)
            observed_hit_ids.update(hit_ids)

        ineligible_ids = {memory.id for memory in ineligible}
        leaked_ids = sorted(observed_hit_ids & ineligible_ids)
        if leaked_ids:
            cases.append(
                {
                    "id": "global-state-exclusion",
                    "category": "STATE_EXCLUSION",
                    "title": "不可召回状态全局隔离",
                    "passed": False,
                    "expected_memory_id": None,
                    "observed_memory_ids": leaked_ids,
                    "duration_ms": 0,
                    "reason": "检索结果包含已纠正、冲突、停用、遗忘或过期经验。",
                }
            )

        passed_count = sum(item["passed"] is True for item in cases)
        overall_ok = passed_count == len(cases)
        summary = {
            "memory_count": len(memories),
            "eligible_count": len(eligible),
            "case_count": len(cases),
            "passed_count": passed_count,
            "top1_recall_rate": _case_rate(cases, "RECALL"),
            "scope_isolation_rate": _case_rate(cases, "SCOPE_ISOLATION"),
            "state_exclusion_rate": _case_rate(cases, "STATE_EXCLUSION"),
            "content_integrity_rate": _integrity_rate(memories, integrity_failures),
            "average_retrieval_ms": (
                round(sum(retrieval_durations) / len(retrieval_durations), 1)
                if retrieval_durations
                else None
            ),
            "p95_retrieval_ms": _percentile(retrieval_durations, 0.95),
        }
        report = {
            "id": report_id,
            "report_type": "OPERATIONAL_MEMORY",
            "started_at": started_at.isoformat(),
            "completed_at": utcnow().isoformat(),
            "overall_status": "ok" if overall_ok else "failed",
            "qualification_status": "qualified",
            "summary": summary,
            "model": _model_identity(self.memory_service),
            "cases": cases,
            "reason_codes": (
                []
                if overall_ok
                else (
                    ["memory_content_integrity_failed"]
                    if integrity_failures
                    else ["memory_governance_regression"]
                )
            ),
        }
        self.store.save(report)
        return report

    def latest(self) -> dict[str, Any] | None:
        return self.store.latest()

    def _search_case(
        self,
        *,
        case_id: str,
        category: str,
        title: str,
        query: str,
        host_scope: str | None,
        service_scope: str | None,
        expected_memory_id: int,
        expect_present: bool,
    ) -> tuple[dict[str, Any], list[int], int]:
        started = time.perf_counter()
        try:
            hits = self.memory_service.search_confirmed(
                query,
                host_scope=host_scope,
                service_scope=service_scope,
                limit=3,
                record_usage=False,
            )
            error = None
        except Exception as exc:
            hits = []
            error = f"{type(exc).__name__}: {str(exc)[:240]}"
        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        hit_ids = [int(hit.chunk_id) for hit in hits]
        if error is not None:
            passed = False
            reason = "检索链路未完成，已保留错误分类。"
        elif expect_present:
            passed = bool(hit_ids and hit_ids[0] == expected_memory_id)
            reason = "目标经验位于 Top-1。" if passed else "目标经验未位于 Top-1。"
        else:
            passed = expected_memory_id not in hit_ids
            reason = "目标经验已正确隔离。" if passed else "目标经验越过召回边界。"
        return (
            {
                "id": case_id,
                "category": category,
                "title": title,
                "passed": passed,
                "expected_memory_id": expected_memory_id,
                "observed_memory_ids": hit_ids,
                "duration_ms": duration_ms,
                "host_scope": host_scope,
                "service_scope": service_scope,
                "reason": reason,
                "error": error,
            },
            hit_ids,
            duration_ms,
        )


def _is_retrievable(memory: OperationalMemory) -> bool:
    if (
        memory.status != "CONFIRMED"
        or memory.qualification_status != "QUALIFIED"
        or not verify_memory_content(memory)
    ):
        return False
    valid_until = memory.valid_until
    if valid_until is None:
        return True
    expiry = valid_until if valid_until.tzinfo is not None else valid_until.replace(tzinfo=timezone.utc)
    return expiry > datetime.now(timezone.utc)


def _query_scope(value: str) -> str | None:
    normalized = str(value or "").strip()
    return None if not normalized or normalized == "*" else normalized


def _evaluation_query(memory: OperationalMemory) -> str:
    return " ".join(
        part
        for part in (memory.title, memory.root_cause, memory.resolution[:300])
        if isinstance(part, str) and part.strip()
    )[:1000]


def _case_rate(cases: list[dict[str, Any]], category: str) -> float | None:
    selected = [item for item in cases if item.get("category") == category]
    if not selected:
        return None
    return round(sum(item.get("passed") is True for item in selected) / len(selected), 4)


def _integrity_rate(
    memories: list[OperationalMemory],
    failures: dict[int, tuple[str, ...]],
) -> float | None:
    if not memories:
        return None
    return round((len(memories) - len(failures)) / len(memories), 4)


def _integrity_case(
    memories: list[OperationalMemory],
    failures: dict[int, tuple[str, ...]],
) -> dict[str, Any] | None:
    if not memories:
        return None
    failed_ids = sorted(failures)
    passed = not failed_ids
    return {
        "id": "content-integrity",
        "category": "CONTENT_INTEGRITY",
        "title": "运维经验版本链",
        "passed": passed,
        "expected_memory_id": None,
        "observed_memory_ids": failed_ids,
        "duration_ms": 0,
        "reason": (
            f"{len(memories)} 条经验的正文摘要和版本关系均连续。"
            if passed
            else f"{len(failed_ids)} 条经验未通过正文摘要或版本关系校验。"
        ),
        "error": None,
        "details": {
            str(memory_id): list(reason_codes)
            for memory_id, reason_codes in failures.items()
        },
    }


def _percentile(values: list[int], quantile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * quantile) - 1))
    return ordered[index]


def _model_identity(memory_service: Any) -> dict[str, str | None]:
    model = getattr(memory_service, "model_client", None)
    return {
        "provider": "bailian" if model is not None else None,
        "embedding_model": getattr(model, "embedding_model", None),
        "rerank_model": getattr(model, "rerank_model", None),
    }
