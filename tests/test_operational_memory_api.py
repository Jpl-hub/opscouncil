from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.api.routes import build_router
from backend.app.knowledge.retrieval import KnowledgeHit, RetrievalProvenance
from backend.app.memory.api import get_operational_memory_service


class EmptyRegistry:
    def list_tools(self) -> list[dict]:
        return []


def memory_record(**overrides):  # type: ignore[no-untyped-def]
    now = datetime(2026, 7, 12, 10, 0, tzinfo=timezone.utc)
    values = {
        "id": 7,
        "memory_key": "memory-key",
        "version": 1,
        "status": "CONFIRMED",
        "memory_kind": "INCIDENT_CASE",
        "source_task_id": 19,
        "supersedes_id": None,
        "host_scope": "linux-node-a",
        "service_scope": "sshd.service",
        "symptom_fingerprint": "a" * 64,
        "applicability_json": {"intent": "log_analysis"},
        "confidence_score": 92,
        "title": "sshd 配置参数无效",
        "root_cause": "升级后旧参数不再受支持。",
        "resolution": "备份配置、移除旧参数并完成语法核验。",
        "evidence_refs_json": [{"evidence_item_id": 3}],
        "created_by": "admin",
        "confirmed_by": "reviewer",
        "retrieval_count": 3,
        "helpful_count": 2,
        "incorrect_count": 0,
        "qualification_status": "QUALIFIED",
        "qualification_report_json": {
            "contract_version": "memory-qualification.v1",
            "passed": True,
            "permission_delta": 0,
            "cases": [],
        },
        "qualified_at": now,
        "created_at": now,
        "updated_at": now,
        "valid_from": now,
        "valid_until": None,
        "last_verified_at": now,
        "confirmed_at": now,
        "forgotten_at": None,
        "forgotten_by": None,
        "forget_reason": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class FakeMemoryService:
    def __init__(self) -> None:
        self.memory = memory_record()
        self.calls: list[tuple] = []

    def list_memories(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("list", kwargs))
        return [self.memory]

    def create_draft_from_task(self, task_id: int, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("create", task_id, kwargs))
        return memory_record(status="DRAFT", confirmed_by=None, confirmed_at=None)

    def confirm(self, memory_id: int, *, actor: str):  # type: ignore[no-untyped-def]
        self.calls.append(("confirm", memory_id, actor))
        return memory_record(
            qualification_status="PENDING",
            qualification_report_json={},
            qualified_at=None,
        )

    def qualify(self, memory_id: int, *, actor: str):  # type: ignore[no-untyped-def]
        self.calls.append(("qualify", memory_id, actor))
        return self.memory

    def correct(self, memory_id: int, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("correct", memory_id, kwargs))
        return memory_record(id=8, version=2, status="DRAFT", supersedes_id=memory_id)

    def deactivate(self, memory_id: int, *, actor: str):  # type: ignore[no-untyped-def]
        self.calls.append(("deactivate", memory_id, actor))
        return memory_record(status="INACTIVE")

    def forget(self, memory_id: int, *, actor: str, reason: str):  # type: ignore[no-untyped-def]
        self.calls.append(("forget", memory_id, actor, reason))
        return memory_record(
            status="FORGOTTEN",
            forgotten_at=datetime(2026, 7, 12, 10, 2, tzinfo=timezone.utc),
            forgotten_by=actor,
            forget_reason=reason,
        )

    def list_relations(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("relations", kwargs))
        now = datetime(2026, 7, 12, 10, 3, tzinfo=timezone.utc)
        return [
            SimpleNamespace(
                id=11,
                source_memory_id=8,
                target_memory_id=7,
                relation="CONFLICTS",
                reason="相同症状存在不同根因。",
                confidence_score=88,
                detected_by="governance_policy",
                status="PENDING",
                resolution=None,
                resolved_by=None,
                created_at=now,
                updated_at=now,
                resolved_at=None,
            )
        ]

    def resolve_relation(self, relation_id: int, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("resolve_relation", relation_id, kwargs))
        relation = self.list_relations()[0]
        relation.status = "RESOLVED"
        relation.resolution = f"{kwargs['decision']}: {kwargs['reason']}"
        relation.resolved_by = kwargs["actor"]
        relation.resolved_at = datetime(2026, 7, 12, 10, 4, tzinfo=timezone.utc)
        return relation

    def delete(self, memory_id: int, *, actor: str) -> None:
        self.calls.append(("delete", memory_id, actor))

    def search_confirmed(self, query: str, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("search", query, kwargs))
        return [
            KnowledgeHit(
                chunk_id=7,
                document_id=7,
                title=self.memory.title,
                source_uri="memory://memory-key/v1",
                trust_level="operator_confirmed",
                content="根因与处置经验",
                distance=0.1,
                retrieval=RetrievalProvenance(1, 1, 0.032, 0.98),
                source_kind="memory",
            )
        ]

    def record_feedback(self, task_id: int, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("feedback", task_id, kwargs))
        return SimpleNamespace(
            id=5,
            task_id=task_id,
            memory_id=kwargs.get("memory_id"),
            actor=kwargs["actor"],
            verdict=kwargs["verdict"],
            correction=kwargs.get("correction"),
            created_at=datetime(2026, 7, 12, 10, 1, tzinfo=timezone.utc),
        )


def build_client() -> tuple[TestClient, FakeMemoryService]:
    service = FakeMemoryService()
    app = FastAPI()
    app.include_router(build_router(EmptyRegistry()))  # type: ignore[arg-type]
    app.dependency_overrides[get_operational_memory_service] = lambda: service
    return TestClient(app), service


def test_memory_api_exposes_lifecycle_search_and_feedback_contracts() -> None:
    client, service = build_client()
    try:
        listed = client.get("/api/operational-memories", params={"status": "CONFIRMED"})
        created = client.post(
            "/api/operational-memories/from-task/19",
            json={
                "actor": "admin",
                "resolution": "备份配置、移除旧参数并完成语法核验。",
                "service_scope": "sshd.service",
            },
        )
        confirmed = client.post("/api/operational-memories/7/confirm", json={"actor": "reviewer"})
        qualified = client.post("/api/operational-memories/7/qualify", json={"actor": "reviewer"})
        corrected = client.post(
            "/api/operational-memories/7/correct",
            json={
                "actor": "reviewer",
                "root_cause": "旧参数与当前 OpenSSH 版本不兼容。",
                "resolution": "备份后移除旧参数，执行 sshd -t，再受控重启。",
                "host_scope": "linux-node-b",
                "service_scope": "*",
            },
        )
        deactivated = client.post("/api/operational-memories/7/deactivate", json={"actor": "reviewer"})
        forgotten = client.post(
            "/api/operational-memories/7/forget",
            json={
                "actor": "reviewer",
                "reason": "该节点已经退役，按数据保留策略移除经验。",
            },
        )
        relations = client.get("/api/operational-memories/8/relations")
        resolved_relation = client.post(
            "/api/operational-memory-relations/11/resolve",
            json={
                "actor": "reviewer",
                "decision": "SUPERSEDE_EXISTING",
                "reason": "新经验绑定了更完整的现场证据。",
            },
        )
        searched = client.get(
            "/api/operational-memories/search",
            params={"q": "sshd 启动失败", "host_scope": "linux-node-a"},
        )
        feedback = client.post(
            "/api/tasks/19/feedback",
            json={"actor": "admin", "verdict": "HELPFUL", "memory_id": 7},
        )
        deleted = client.request("DELETE", "/api/operational-memories/8", json={"actor": "admin"})
    finally:
        client.close()

    assert listed.status_code == 200
    assert listed.json()[0]["status"] == "CONFIRMED"
    assert created.status_code == 200 and created.json()["status"] == "DRAFT"
    assert confirmed.status_code == 200
    assert confirmed.json()["qualification_status"] == "PENDING"
    assert qualified.status_code == 200
    assert qualified.json()["qualification_status"] == "QUALIFIED"
    assert qualified.json()["qualification_report"]["permission_delta"] == 0
    assert corrected.status_code == 200 and corrected.json()["version"] == 2
    correction_call = next(call for call in service.calls if call[0] == "correct")
    assert correction_call[2]["host_scope"] == "linux-node-b"
    assert correction_call[2]["service_scope"] == "*"
    assert deactivated.status_code == 200 and deactivated.json()["status"] == "INACTIVE"
    assert forgotten.status_code == 200 and forgotten.json()["status"] == "FORGOTTEN"
    assert forgotten.json()["forgotten_by"] == "reviewer"
    assert relations.status_code == 200 and relations.json()[0]["relation"] == "CONFLICTS"
    assert resolved_relation.status_code == 200
    assert resolved_relation.json()["status"] == "RESOLVED"
    assert searched.status_code == 200
    assert searched.json()[0]["source_kind"] == "memory"
    assert searched.json()[0]["retrieval"]["rerank_score"] == 0.98
    assert feedback.status_code == 200 and feedback.json()["verdict"] == "HELPFUL"
    assert deleted.status_code == 200 and deleted.json()["deleted"] is True
    assert any(call[0] == "search" for call in service.calls)
