from __future__ import annotations

from collections import defaultdict
from typing import Any


_ASSURANCE_LABELS = {
    "CORROBORATED": "已交叉核验",
    "SINGLE_SOURCE": "单一来源",
    "CONFLICTED": "证据冲突",
    "UNSUPPORTED": "证据不足",
}
_SOURCE_FAMILIES = {
    "network_listeners": "socket_inventory",
    "socket_process_context": "socket_inventory",
    "service_dependency_snapshot": "socket_inventory",
    "service_desired_state": "operator_approved_service_catalog",
    "service_catalog_snapshot": "operator_approved_service_catalog",
    "disk_usage": "filesystem_capacity",
    "filesystem_mount_context": "filesystem_capacity",
    "process_file_handles": "process_descriptor_state",
    "process_runtime_detail": "process_descriptor_state",
    "config_integrity_scan": "configuration_integrity",
    "config_baseline_check": "configuration_integrity",
    "file_integrity_state": "configuration_integrity",
}


def build_decision_view(
    *,
    task: dict[str, Any],
    evidence_items: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]],
    action_options: list[dict[str, Any]],
    action_lifecycle: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a deterministic claim assurance view and its operator-facing graph."""
    evidence_by_id = {
        item.get("evidence_id"): item
        for item in evidence_items
        if isinstance(item.get("evidence_id"), int)
    }
    claims = [
        _assess_claim(hypothesis, evidence_by_id)
        for hypothesis in hypotheses
    ]
    primary_claim = claims[0] if claims else None
    alerts = _reliability_alerts(evidence_items, claims)
    assurance = {
        "status": primary_claim["status"] if primary_claim else "UNSUPPORTED",
        "status_label": _ASSURANCE_LABELS[
            primary_claim["status"] if primary_claim else "UNSUPPORTED"
        ],
        "primary_hypothesis_key": (
            primary_claim["hypothesis_key"] if primary_claim else None
        ),
        "independent_source_count": (
            primary_claim["independent_source_count"] if primary_claim else 0
        ),
        "support_count": primary_claim["support_count"] if primary_claim else 0,
        "refutation_count": (
            primary_claim["refutation_count"] if primary_claim else 0
        ),
        "claims": claims,
        "reliability_alerts": alerts,
    }
    graph = _build_graph(
        task=task,
        evidence_items=evidence_items,
        hypotheses=hypotheses,
        claims=claims,
        action_options=action_options,
        action_lifecycle=action_lifecycle,
    )
    return assurance, graph


def _assess_claim(
    hypothesis: dict[str, Any],
    evidence_by_id: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    links = hypothesis.get("evidence")
    if not isinstance(links, list):
        links = []

    relation_ids: dict[str, list[int]] = defaultdict(list)
    supporting_sources: set[str] = set()
    all_sources: set[str] = set()
    for link in links:
        if not isinstance(link, dict):
            continue
        relation = str(link.get("relation") or "CONTEXT").upper()
        if relation not in {"SUPPORTS", "REFUTES", "CONTEXT"}:
            relation = "CONTEXT"
        evidence_id = link.get("evidence_id")
        evidence = evidence_by_id.get(evidence_id) if isinstance(evidence_id, int) else None
        source_key = _independent_source_key(link, evidence)
        if source_key:
            all_sources.add(source_key)
            if relation == "SUPPORTS" and _evidence_is_usable(evidence):
                supporting_sources.add(source_key)
        if isinstance(evidence_id, int):
            relation_ids[relation].append(evidence_id)

    support_count = len(relation_ids["SUPPORTS"])
    refutation_count = len(relation_ids["REFUTES"])
    if support_count and refutation_count:
        status = "CONFLICTED"
    elif len(supporting_sources) >= 2:
        status = "CORROBORATED"
    elif support_count:
        status = "SINGLE_SOURCE"
    else:
        status = "UNSUPPORTED"

    evidence_gap = str(hypothesis.get("evidence_gap") or "").strip()
    if status == "SINGLE_SOURCE" and not evidence_gap:
        evidence_gap = "仍需第二类独立观测交叉核验。"
    elif status == "CONFLICTED" and not evidence_gap:
        evidence_gap = "支持证据与反证并存，需追加定向观测。"
    elif status == "UNSUPPORTED" and not evidence_gap:
        evidence_gap = "尚未绑定可验证的支持证据。"

    return {
        "hypothesis_key": str(hypothesis.get("key") or ""),
        "title": str(hypothesis.get("title") or "待验证结论"),
        "status": status,
        "status_label": _ASSURANCE_LABELS[status],
        "independent_source_count": len(supporting_sources),
        "all_source_count": len(all_sources),
        "support_count": support_count,
        "refutation_count": refutation_count,
        "context_count": len(relation_ids["CONTEXT"]),
        "independent_sources": sorted(supporting_sources),
        "supporting_evidence_ids": relation_ids["SUPPORTS"],
        "refuting_evidence_ids": relation_ids["REFUTES"],
        "context_evidence_ids": relation_ids["CONTEXT"],
        "evidence_gap": evidence_gap,
    }


def _independent_source_key(
    link: dict[str, Any],
    evidence: dict[str, Any] | None,
) -> str:
    if evidence is not None:
        source_type = str(evidence.get("source_type") or "MCP")
        source_key = str(
            evidence.get("source_key")
            or evidence.get("tool_name")
            or ""
        ).strip()
        if source_key:
            family = _SOURCE_FAMILIES.get(source_key, source_key)
            return f"{source_type}:{family}"
        refs = evidence.get("evidence_refs")
        if isinstance(refs, list) and refs:
            return f"{source_type}:{refs[0]}"
    source = str(link.get("source") or "").strip()
    return f"UNKNOWN:{source}" if source else ""


def _evidence_is_usable(evidence: dict[str, Any] | None) -> bool:
    if evidence is None:
        return True
    if str(evidence.get("trust_level") or "").upper() == "QUARANTINED":
        return False
    return str(evidence.get("status") or "ok").lower() == "ok"


def _reliability_alerts(
    evidence_items: list[dict[str, Any]],
    claims: list[dict[str, Any]],
) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    for evidence in evidence_items:
        if str(evidence.get("trust_level") or "").upper() == "QUARANTINED":
            alerts.append(
                {
                    "type": "UNTRUSTED_EVIDENCE",
                    "severity": "high",
                    "message": (
                        f"{evidence.get('title') or evidence.get('tool_name') or '证据源'}"
                        "包含疑似指令内容，已隔离且不参与结论支持。"
                    ),
                }
            )
        status = str(evidence.get("status") or "ok").lower()
        if status != "ok":
            alerts.append(
                {
                    "type": "SOURCE_FAILURE",
                    "severity": "high",
                    "message": (
                        f"{evidence.get('title') or evidence.get('tool_name') or '证据源'}"
                        "采集异常，不能作为有效支持证据。"
                    ),
                }
            )
        warnings = evidence.get("warnings")
        if isinstance(warnings, list):
            for warning in warnings[:2]:
                alerts.append(
                    {
                        "type": "SOURCE_WARNING",
                        "severity": "medium",
                        "message": str(warning),
                    }
                )
    for claim in claims:
        if claim["status"] == "CONFLICTED":
            alerts.append(
                {
                    "type": "CLAIM_CONFLICT",
                    "severity": "high",
                    "message": f"“{claim['title']}”同时存在支持证据与反证。",
                }
            )
    return alerts


def _build_graph(
    *,
    task: dict[str, Any],
    evidence_items: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    action_options: list[dict[str, Any]],
    action_lifecycle: dict[str, Any],
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    task_id = task.get("id")
    request_id = f"request:{task_id}"
    nodes.append(
        {
            "id": request_id,
            "kind": "REQUEST",
            "label": str(task.get("user_input") or "运维请求"),
            "status": str(task.get("status") or "PENDING"),
            "summary": str(task.get("summary") or ""),
            "source_ref": f"task:{task_id}",
            "metadata": {"intent": task.get("intent")},
        }
    )

    evidence_node_ids: dict[int, str] = {}
    for index, evidence in enumerate(evidence_items, start=1):
        evidence_id = evidence.get("evidence_id")
        stable_id = evidence_id if isinstance(evidence_id, int) else index
        node_id = f"evidence:{stable_id}"
        if isinstance(evidence_id, int):
            evidence_node_ids[evidence_id] = node_id
        nodes.append(
            {
                "id": node_id,
                "kind": "EVIDENCE",
                "label": str(
                    evidence.get("title")
                    or evidence.get("tool_name")
                    or f"证据 {stable_id}"
                ),
                "status": (
                    "QUARANTINED"
                    if str(evidence.get("trust_level") or "").upper() == "QUARANTINED"
                    else str(evidence.get("status") or "ok").upper()
                ),
                "summary": str(evidence.get("summary") or ""),
                "source_ref": _first_reference(evidence),
                "metadata": {
                    "source_type": evidence.get("source_type") or "MCP",
                    "source_key": evidence.get("source_key") or evidence.get("tool_name"),
                    "trust_level": evidence.get("trust_level"),
                    "observed_at": evidence.get("observed_at"),
                },
            }
        )
        edges.append(
            {
                "id": f"{request_id}->{node_id}",
                "source": request_id,
                "target": node_id,
                "relation": "OBSERVED_BY",
                "label": "采集",
                "polarity": "neutral",
            }
        )

    claim_by_key = {
        claim["hypothesis_key"]: claim
        for claim in claims
    }
    hypothesis_node_ids: dict[str, str] = {}
    for index, hypothesis in enumerate(hypotheses, start=1):
        key = str(hypothesis.get("key") or f"candidate_{index}")
        node_id = f"hypothesis:{key}"
        hypothesis_node_ids[key] = node_id
        claim = claim_by_key.get(key, {})
        nodes.append(
            {
                "id": node_id,
                "kind": "HYPOTHESIS",
                "label": str(hypothesis.get("title") or "候选根因"),
                "status": str(claim.get("status") or "UNSUPPORTED"),
                "summary": str(
                    hypothesis.get("rationale")
                    or hypothesis.get("root_cause")
                    or ""
                ),
                "source_ref": node_id,
                "metadata": {
                    "confidence": hypothesis.get("confidence"),
                    "confidence_score": hypothesis.get("confidence_score"),
                    "evidence_gap": claim.get("evidence_gap"),
                },
            }
        )
        links = hypothesis.get("evidence")
        if not isinstance(links, list):
            continue
        for link in links:
            if not isinstance(link, dict):
                continue
            evidence_id = link.get("evidence_id")
            source_id = (
                evidence_node_ids.get(evidence_id)
                if isinstance(evidence_id, int)
                else None
            )
            if source_id is None:
                continue
            relation = str(link.get("relation") or "CONTEXT").upper()
            edges.append(
                {
                    "id": f"{source_id}->{node_id}:{relation}",
                    "source": source_id,
                    "target": node_id,
                    "relation": relation,
                    "label": _relation_label(relation),
                    "polarity": (
                        "positive"
                        if relation == "SUPPORTS"
                        else "negative"
                        if relation == "REFUTES"
                        else "neutral"
                    ),
                }
            )

    primary_hypothesis_id = next(iter(hypothesis_node_ids.values()), request_id)
    action_node_ids: list[str] = []
    for index, action in enumerate(action_options, start=1):
        action_id = action.get("id")
        node_id = f"action:{action_id if isinstance(action_id, int) else index}"
        action_node_ids.append(node_id)
        nodes.append(
            {
                "id": node_id,
                "kind": "ACTION",
                "label": str(action.get("tool_name") or "处置建议"),
                "status": str(action.get("status") or "PREPARED"),
                "summary": str(action.get("reason") or ""),
                "source_ref": node_id,
                "metadata": {
                    "risk_level": action.get("risk_level"),
                    "requires_approval": bool(action.get("requires_approval")),
                },
            }
        )
        edges.append(
            {
                "id": f"{primary_hypothesis_id}->{node_id}",
                "source": primary_hypothesis_id,
                "target": node_id,
                "relation": "PROPOSES",
                "label": "建议",
                "polarity": "neutral",
            }
        )

    lifecycle_steps = action_lifecycle.get("steps")
    if isinstance(lifecycle_steps, list) and lifecycle_steps:
        verification_id = "verification:primary"
        verification_status = str(action_lifecycle.get("status") or "prepared")
        verification_summary = "；".join(
            str(step.get("summary") or "")
            for step in lifecycle_steps
            if isinstance(step, dict) and step.get("summary")
        )
        nodes.append(
            {
                "id": verification_id,
                "kind": "VERIFICATION",
                "label": "安全执行与结果核验",
                "status": verification_status.upper(),
                "summary": verification_summary,
                "source_ref": verification_id,
                "metadata": {"steps": lifecycle_steps},
            }
        )
        source_ids = action_node_ids or [primary_hypothesis_id]
        for source_id in source_ids:
            edges.append(
                {
                    "id": f"{source_id}->{verification_id}",
                    "source": source_id,
                    "target": verification_id,
                    "relation": "VERIFIED_BY",
                    "label": "校验",
                    "polarity": "neutral",
                }
            )

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "evidence_count": len(evidence_items),
            "hypothesis_count": len(hypotheses),
            "action_count": len(action_options),
            "corroborated_claim_count": sum(
                1 for claim in claims if claim["status"] == "CORROBORATED"
            ),
            "conflicted_claim_count": sum(
                1 for claim in claims if claim["status"] == "CONFLICTED"
            ),
        },
    }


def _first_reference(evidence: dict[str, Any]) -> str:
    references = evidence.get("evidence_refs")
    if isinstance(references, list) and references:
        return str(references[0])
    evidence_id = evidence.get("evidence_id")
    return f"evidence:{evidence_id}" if evidence_id is not None else ""


def _relation_label(relation: str) -> str:
    if relation == "SUPPORTS":
        return "支持"
    if relation == "REFUTES":
        return "反证"
    return "上下文"
