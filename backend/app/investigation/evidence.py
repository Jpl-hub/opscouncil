from __future__ import annotations

import json
import hashlib
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.investigation.schemas import InvestigationDecision
from backend.app.investigation.claim_boundaries import (
    bounded_service_claim,
    claims_unproven_service_intent,
    failed_service_context,
    service_desired_state_context,
)
from backend.app.knowledge.service import KnowledgeHit
from backend.app.models.entities import (
    EvidenceItem,
    Hypothesis,
    HypothesisEvidence,
    Investigation,
    ToolCall,
    utcnow,
)
from backend.app.safety.content import scan_untrusted_content


class EvidenceBindingError(ValueError):
    pass


_NEGATIVE_CONNECTION_CONTEXT = (
    "服务关系快照在本次采样中未记录到已建立连接；"
    "该缺口不用于证明依赖不存在或不可达。"
)
_NEGATIVE_CONNECTION_CAUSAL_RE = re.compile(
    r"[^；。]*(?:未观测到|未发现|未采到|未记录到|未捕获到|无(?:已建立)?)"
    r"[^；。]*连接[^；。]*(?:支持|佐证|证明|指向|表明)[^；。]*"
    r"(?:不可达|未建立|不存在|未响应)[；。]?"
)
_NEGATIVE_CONNECTION_ABSENCE_CLAUSE_RE = re.compile(
    r"(?:^|[，,；;。])\s*(?:服务关系快照|连接快照)[^；;。]*"
    r"(?:未观测到|未发现|未采到|未记录到|未捕获到|无(?:已建立)?)"
    r"[^；;。]*连接[^；;。]*[；;。]?"
)
_SERVICE_CATALOG_CLAIM_RE = re.compile(
    r"(?:服务目录|资产(?:清单|目录)|CMDB|经审批|批准|授权|纳管|登记|责任方|"
    r"允许监听|期望(?:状态|监听|范围)|业务清单|业务必要性|白名单|合规范围|监听要求)"
)
_SERVICE_CATALOG_CONTEXT = (
    "经审批服务目录仅提供责任方、期望状态和允许监听范围；"
    "不证明实时监听状态、进程归属或故障因果。"
)
_ADVISORY_KNOWLEDGE_CONTEXT = (
    "知识文档或经确认的历史经验仅用于引导本次核查；"
    "不证明当前主机状态，也不单独支持或反驳故障因果。"
)


_TOOL_LABELS = {
    "platform_capability_profile": "主机能力画像",
    "system_snapshot": "系统快照",
    "disk_usage": "磁盘用量",
    "find_large_files": "大文件定位",
    "process_list": "进程状态",
    "process_file_handles": "文件句柄",
    "journal_query": "系统日志",
    "service_status": "服务状态",
    "service_desired_state": "服务期望状态",
    "service_catalog_snapshot": "服务目录快照",
    "network_listeners": "网络监听",
    "service_dependency_snapshot": "服务关系快照",
    "config_integrity_scan": "配置完整性",
    "config_baseline_check": "配置基线比较",
    "file_integrity_state": "文件完整性校验",
    "process_runtime_detail": "进程运行详情",
    "journal_storage_status": "日志存储状态",
    "deleted_open_files": "已删除未释放文件",
    "socket_process_context": "端口进程归属",
    "filesystem_mount_context": "文件系统挂载",
    "service_health_probe": "服务健康检查",
    "application_log_query": "应用日志",
}
_TOOL_SCHEMA_CONTROL_FIELDS = {
    "service_desired_state": frozenset({"source_ref"}),
    "service_catalog_snapshot": frozenset({"source_ref"}),
}


def bound_investigation_decision_claims(
    decision: InvestigationDecision,
    evidence_items: list[Any],
) -> InvestigationDecision:
    decision = _bound_advisory_knowledge_links(decision, evidence_items)
    decision = _bound_service_catalog_evidence_links(decision, evidence_items)
    context = failed_service_context(evidence_items)
    if context is None:
        return decision
    desired = service_desired_state_context(evidence_items, unit=context.unit)
    bounded_links = _bound_service_evidence_links(
        decision,
        evidence_items,
        unit=context.unit,
        desired_state_present=desired is not None,
    )

    conclusion = decision.conclusion
    analyzed_text = "\n".join(
        [
            decision.stop_reason,
            *(
                text
                for item in decision.hypotheses
                for text in (item.title, item.rationale, item.evidence_gap)
            ),
            *(
                (
                    conclusion.conclusion,
                    conclusion.root_cause,
                    conclusion.residual_risk,
                    *(action.rationale for action in conclusion.recommended_actions),
                )
                if conclusion is not None
                else ()
            ),
        ]
    )
    if not claims_unproven_service_intent(analyzed_text):
        return decision.model_copy(update={"evidence_links": bounded_links})

    boundary = bounded_service_claim(context, desired)
    bounded_hypotheses = []
    for item in decision.hypotheses:
        item_text = "\n".join((item.title, item.rationale, item.evidence_gap))
        if not claims_unproven_service_intent(item_text):
            bounded_hypotheses.append(item)
            continue
        bounded_hypotheses.append(
            item.model_copy(
                update={
                    "title": boundary.title,
                    "rationale": boundary.rationale,
                    "evidence_gap": boundary.evidence_gap,
                }
            )
        )

    bounded_conclusion = conclusion
    if conclusion is not None:
        payload = conclusion.model_dump(mode="python")
        payload.update(
            {
                "conclusion": (
                    boundary.conclusion
                ),
                "root_cause": boundary.rationale,
                "reasoning_summary": [
                    boundary.reasoning_summary
                ],
                "counter_evidence": [],
                "recommended_actions": [
                    {
                        "title": boundary.action_title,
                        "rationale": boundary.action_rationale,
                        "safety_gate": (
                            "只读核查可继续；任何服务或配置变更必须重新进入审批。"
                        ),
                        "tool_name": None,
                    }
                ],
                "residual_risk": boundary.residual_risk,
            }
        )
        bounded_conclusion = conclusion.__class__.model_validate(payload)

    return decision.model_copy(
        update={
            "hypotheses": bounded_hypotheses,
            "evidence_links": bounded_links,
            "conclusion": bounded_conclusion,
            "stop_reason": boundary.stop_reason,
        }
    )


def _bound_advisory_knowledge_links(
    decision: InvestigationDecision,
    evidence_items: list[Any],
) -> InvestigationDecision:
    evidence_by_id = {
        int(getattr(item, "id")): item
        for item in evidence_items
        if getattr(item, "id", None) is not None
    }
    links = []
    changed = False
    for link in decision.evidence_links:
        evidence = evidence_by_id.get(link.evidence_id)
        if str(getattr(evidence, "source_type", "")).upper() != "KNOWLEDGE":
            links.append(link)
            continue
        bounded = link.model_copy(
            update={
                "relation": "CONTEXT",
                "rationale": _ADVISORY_KNOWLEDGE_CONTEXT,
            }
        )
        changed = changed or bounded != link
        links.append(bounded)
    if not changed:
        return decision
    return decision.model_copy(update={"evidence_links": links})


def _bound_service_catalog_evidence_links(
    decision: InvestigationDecision,
    evidence_items: list[Any],
) -> InvestigationDecision:
    evidence_by_id = {
        int(getattr(item, "id")): item
        for item in evidence_items
        if getattr(item, "id", None) is not None
    }
    hypotheses = {
        item.key: item
        for item in decision.hypotheses
    }
    links = []
    changed = False
    for link in decision.evidence_links:
        evidence = evidence_by_id.get(link.evidence_id)
        if str(getattr(evidence, "source_key", "")) != "service_catalog_snapshot":
            links.append(link)
            continue
        hypothesis = hypotheses.get(link.hypothesis_key)
        claim_text = "\n".join(
            (
                str(getattr(hypothesis, "title", "")),
                str(getattr(hypothesis, "rationale", "")),
                link.rationale,
            )
        )
        relation = link.relation
        if relation != "CONTEXT" and not _SERVICE_CATALOG_CLAIM_RE.search(claim_text):
            relation = "CONTEXT"
        bounded = link.model_copy(
            update={
                "relation": relation,
                "rationale": _SERVICE_CATALOG_CONTEXT,
            }
        )
        changed = changed or bounded != link
        links.append(bounded)
    if not changed:
        return decision
    return decision.model_copy(update={"evidence_links": links})


def _bound_service_evidence_links(
    decision: InvestigationDecision,
    evidence_items: list[Any],
    *,
    unit: str,
    desired_state_present: bool,
) -> list[Any]:
    evidence_by_id = {
        int(getattr(item, "id")): item
        for item in evidence_items
        if getattr(item, "id", None) is not None
    }
    bounded_links = []
    for link in decision.evidence_links:
        evidence = evidence_by_id.get(link.evidence_id)
        source_key = str(getattr(evidence, "source_key", ""))
        payload = getattr(evidence, "payload_json", {})
        evidence_unit = str(payload.get("unit") or "") if isinstance(payload, dict) else ""
        matches_unit = evidence_unit == unit
        if source_key == "service_status":
            rationale = (
                "systemd 状态证据支持该单元当前为 failed，并定位非零退出机制；"
                "不证明该状态符合资产期望。"
                if matches_unit
                else "该状态证据属于其他服务单元，不能证明当前失败服务的运行状态。"
            )
        elif source_key == "service_desired_state":
            if not matches_unit:
                rationale = "该目录记录属于其他服务单元，不能证明当前失败服务的期望状态。"
            elif desired_state_present:
                rationale = "经审批服务目录记录该单元应停止；当前 failed 与停止态不相等。"
            else:
                rationale = "服务目录未提供当前有效记录，不能据此确认资产期望。"
        elif source_key == "journal_query":
            rationale = (
                "近期日志支持该单元启动失败的事实；日志中的名称或描述不用于推断资产意图。"
            )
        elif claims_unproven_service_intent(link.rationale):
            rationale = "该证据不用于证明失败状态符合资产期望。"
        else:
            rationale = link.rationale
        bounded_links.append(link.model_copy(update={"rationale": rationale}))
    return bounded_links


def ingest_tool_call(
    session: Session,
    investigation: Investigation,
    tool_call: ToolCall,
) -> list[EvidenceItem]:
    output = tool_call.output_json if isinstance(tool_call.output_json, dict) else {}
    observations = output.get("observations", [])
    observations = observations if isinstance(observations, list) else []
    evidence_refs = output.get("evidence_refs", [])
    evidence_refs = evidence_refs if isinstance(evidence_refs, list) else []
    observed_at = tool_call.ended_at or tool_call.started_at
    title = _TOOL_LABELS.get(tool_call.tool_name, tool_call.tool_name)

    items: list[EvidenceItem] = []
    if observations:
        for index, raw_observation in enumerate(observations):
            observation = raw_observation if isinstance(raw_observation, dict) else {"value": raw_observation}
            threats = _scan_tool_observation(tool_call.tool_name, observation)
            source_ref = f"tool_call:{tool_call.id}:observation:{index}"
            evidence_ref = evidence_refs[index] if index < len(evidence_refs) else None
            payload = dict(observation)
            if isinstance(evidence_ref, str) and evidence_ref:
                payload["evidence_ref"] = evidence_ref
            if threats:
                payload["content_safety"] = {
                    "status": "quarantined",
                    "threats": [threat.to_dict() for threat in threats],
                    "content_sha256": _content_sha256(observation),
                }
            item = _get_or_create_evidence(
                session,
                investigation,
                source_ref=source_ref,
                source_type="MCP",
                source_key=tool_call.tool_name,
                tool_call_id=tool_call.id,
                title=title,
                summary=(
                    _quarantine_summary(threats)
                    if threats
                    else _summarize_observation(observation, tool_call.tool_name)
                ),
                payload=payload,
                trust_level="QUARANTINED" if threats else "SYSTEM_OBSERVATION",
                observed_at=observed_at,
            )
            items.append(item)
        return items

    warnings = output.get("warnings", [])
    warnings = warnings if isinstance(warnings, list) else []
    risk_hints = output.get("risk_hints", [])
    risk_hints = risk_hints if isinstance(risk_hints, list) else []
    status = str(output.get("status") or tool_call.status)
    summary_parts = [str(item) for item in [*risk_hints, *warnings] if str(item).strip()]
    summary = "；".join(summary_parts[:3]) or f"{title}未返回观测，状态为 {status}。"
    threats = scan_untrusted_content(summary_parts)
    items.append(
        _get_or_create_evidence(
            session,
            investigation,
            source_ref=f"tool_call:{tool_call.id}:result",
            source_type="MCP",
            source_key=tool_call.tool_name,
            tool_call_id=tool_call.id,
            title=title,
            summary=_quarantine_summary(threats) if threats else summary[:500],
            payload={
                "status": status,
                "warnings": warnings[:10],
                "risk_hints": risk_hints[:10],
                "summary_fields": output.get("summary_fields", {}),
                "evidence_refs": evidence_refs[:10],
                **(
                    {
                        "content_safety": {
                            "status": "quarantined",
                            "threats": [threat.to_dict() for threat in threats],
                            "content_sha256": _content_sha256(summary_parts),
                        }
                    }
                    if threats
                    else {}
                ),
            },
            trust_level="QUARANTINED" if threats else "SYSTEM_OBSERVATION",
            observed_at=observed_at,
        )
    )
    return items


def ingest_knowledge_hits(
    session: Session,
    investigation: Investigation,
    hits: list[KnowledgeHit],
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for hit in hits:
        threats = scan_untrusted_content(hit.content)
        source_ref = (
            f"operational_memory:{hit.document_id}"
            if hit.source_kind == "memory"
            else f"knowledge_chunk:{hit.chunk_id}"
        )
        source_key = (
            f"operational_memory:{hit.document_id}"
            if hit.source_kind == "memory"
            else f"knowledge_document:{hit.document_id}"
        )
        items.append(
            _get_or_create_evidence(
                session,
                investigation,
                source_ref=source_ref,
                source_type="KNOWLEDGE",
                source_key=source_key,
                tool_call_id=None,
                title=hit.title,
                summary=_quarantine_summary(threats) if threats else hit.content[:500],
                payload={
                    "chunk_id": hit.chunk_id,
                    "document_id": hit.document_id,
                    "source_uri": hit.source_uri,
                    "distance": hit.distance,
                    "content": hit.content[:2000],
                    "source_kind": hit.source_kind,
                    "retrieval": hit.retrieval.to_dict(),
                    **(
                        {
                            "content_safety": {
                                "status": "quarantined",
                                "threats": [threat.to_dict() for threat in threats],
                                "content_sha256": _content_sha256(hit.content),
                            }
                        }
                        if threats
                        else {}
                    ),
                },
                trust_level="QUARANTINED" if threats else hit.trust_level,
                observed_at=utcnow(),
            )
        )
    return items


def apply_hypothesis_updates(
    session: Session,
    investigation: Investigation,
    decision: InvestigationDecision,
    *,
    iteration: int,
) -> list[Hypothesis]:
    hypothesis_keys = {item.key for item in decision.hypotheses}
    for link in decision.evidence_links:
        if link.hypothesis_key not in hypothesis_keys:
            raise EvidenceBindingError(
                f"evidence link references undeclared hypothesis {link.hypothesis_key}"
            )

    requested_ids = {link.evidence_id for link in decision.evidence_links}
    evidence_by_id: dict[int, EvidenceItem] = {}
    if requested_ids:
        evidence_items = list(
            session.scalars(
                select(EvidenceItem).where(
                    EvidenceItem.investigation_id == investigation.id,
                    EvidenceItem.id.in_(requested_ids),
                )
            )
        )
        evidence_by_id = {item.id: item for item in evidence_items}
        missing_ids = sorted(requested_ids - set(evidence_by_id))
        if missing_ids:
            raise EvidenceBindingError(
                f"evidence IDs do not belong to investigation {investigation.id}: {missing_ids}"
            )
        quarantined_ids = sorted(
            evidence_id
            for evidence_id, evidence in evidence_by_id.items()
            if str(evidence.trust_level).upper() == "QUARANTINED"
        )
        if quarantined_ids:
            raise EvidenceBindingError(
                "quarantined evidence cannot influence hypotheses: "
                f"{quarantined_ids}"
            )
    empty_connection_hypothesis_keys = {
        link.hypothesis_key
        for link in decision.evidence_links
        if _is_empty_connection_snapshot(evidence_by_id[link.evidence_id])
    }
    observed_timeout_hypothesis_keys = {
        link.hypothesis_key
        for link in decision.evidence_links
        if _has_observed_dependency_timeout(evidence_by_id[link.evidence_id])
    }
    empty_connection_snapshot_present = any(
        _is_empty_connection_snapshot(item)
        for item in session.scalars(
            select(EvidenceItem).where(
                EvidenceItem.investigation_id == investigation.id,
                EvidenceItem.source_key == "service_dependency_snapshot",
            )
        )
    )

    hypotheses: list[Hypothesis] = []
    hypotheses_by_key: dict[str, Hypothesis] = {}
    for update in decision.hypotheses:
        bounded_rationale = _bound_negative_connection_claim(update.rationale)
        if update.key in observed_timeout_hypothesis_keys:
            bounded_rationale = _bound_observed_dependency_timeout_rationale(
                bounded_rationale
            )
        if (
            update.key in empty_connection_hypothesis_keys
            or empty_connection_snapshot_present
        ):
            bounded_rationale = _bound_empty_connection_snapshot_rationale(
                bounded_rationale
            )
        hypothesis = session.scalar(
            select(Hypothesis).where(
                Hypothesis.investigation_id == investigation.id,
                Hypothesis.key == update.key,
            )
        )
        if hypothesis is None:
            hypothesis = Hypothesis(
                investigation_id=investigation.id,
                key=update.key,
                title=update.title,
                rationale=bounded_rationale,
                evidence_gap=update.evidence_gap,
                status="OPEN",
                confidence_level="LOW",
                confidence_score=0,
                first_seen_iteration=iteration,
                last_updated_iteration=iteration,
            )
            session.add(hypothesis)
            session.flush()
        else:
            hypothesis.title = update.title
            hypothesis.rationale = bounded_rationale
            hypothesis.evidence_gap = update.evidence_gap
            hypothesis.last_updated_iteration = iteration
            hypothesis.updated_at = utcnow()
        hypotheses.append(hypothesis)
        hypotheses_by_key[update.key] = hypothesis

    for requested_link in decision.evidence_links:
        hypothesis = hypotheses_by_key[requested_link.hypothesis_key]
        evidence_item = evidence_by_id[requested_link.evidence_id]
        relation = requested_link.relation
        rationale = _bound_negative_connection_claim(requested_link.rationale)
        if str(evidence_item.source_type).upper() == "KNOWLEDGE":
            relation = "CONTEXT"
            rationale = _ADVISORY_KNOWLEDGE_CONTEXT
        elif _is_empty_connection_snapshot(evidence_item):
            relation = "CONTEXT"
            rationale = _NEGATIVE_CONNECTION_CONTEXT
        link = session.get(
            HypothesisEvidence,
            (hypothesis.id, evidence_item.id),
        )
        if link is None:
            link = HypothesisEvidence(
                hypothesis=hypothesis,
                evidence_item=evidence_item,
                relation=relation,
                rationale=rationale,
            )
            session.add(link)
        else:
            link.relation = relation
            link.rationale = rationale
    session.flush()

    for hypothesis in hypotheses:
        recalculate_hypothesis_confidence(session, hypothesis)
    session.flush()
    return hypotheses


def _bound_negative_connection_claim(text: str) -> str:
    if not _NEGATIVE_CONNECTION_CAUSAL_RE.search(text):
        return text
    bounded = _NEGATIVE_CONNECTION_CAUSAL_RE.sub(
        _NEGATIVE_CONNECTION_CONTEXT,
        text,
    )
    return re.sub(r"[；。]{2,}", "。", bounded).strip()


def _bound_empty_connection_snapshot_rationale(text: str) -> str:
    if not _NEGATIVE_CONNECTION_ABSENCE_CLAUSE_RE.search(text):
        return text
    cleaned = _NEGATIVE_CONNECTION_ABSENCE_CLAUSE_RE.sub("", text)
    cleaned = re.sub(r"[，,；;。]{2,}", "。", cleaned).strip(" ，,；;。")
    if not cleaned:
        return _NEGATIVE_CONNECTION_CONTEXT
    return f"{cleaned}。{_NEGATIVE_CONNECTION_CONTEXT}"


def _is_empty_connection_snapshot(evidence: EvidenceItem) -> bool:
    if evidence.source_key != "service_dependency_snapshot":
        return False
    payload = evidence.payload_json if isinstance(evidence.payload_json, dict) else {}
    return payload.get("connection_relation_count") == 0


_TIMEOUT_OR_UNREACHABLE_RE = re.compile(
    r"(?:响应(?:延迟|迟滞)|响应过慢)\s*(?:或|、)\s*不可达|"
    r"不可达\s*(?:或|、)\s*(?:响应(?:延迟|迟滞)|响应过慢)"
)
_ASSERTED_UNREACHABLE_RE = re.compile(
    r"(?:指向|支持|佐证|证明)[^；。]{0,40}不可达"
)


def _bound_observed_dependency_timeout_rationale(text: str) -> str:
    bounded = _TIMEOUT_OR_UNREACHABLE_RE.sub("调用耗时达到超时阈值", text)
    return _ASSERTED_UNREACHABLE_RE.sub(
        lambda match: match.group(0).replace("不可达", "调用超时"),
        bounded,
    )


def _has_observed_dependency_timeout(evidence: EvidenceItem) -> bool:
    if evidence.source_key != "application_log_query":
        return False
    payload = evidence.payload_json if isinstance(evidence.payload_json, dict) else {}
    records = payload.get("records")
    if not isinstance(records, list):
        return False
    for record in records:
        if not isinstance(record, dict) or record.get("reason") != "dependency_timeout":
            continue
        observed = record.get("observed_latency_ms")
        threshold = record.get("dependency_timeout_ms")
        if isinstance(observed, (int, float)) and isinstance(threshold, (int, float)):
            if threshold > 0 and observed >= threshold:
                return True
    return False


def recalculate_hypothesis_confidence(
    session: Session,
    hypothesis: Hypothesis,
) -> Hypothesis:
    rows = session.execute(
        select(HypothesisEvidence, EvidenceItem)
        .join(EvidenceItem, EvidenceItem.id == HypothesisEvidence.evidence_item_id)
        .where(HypothesisEvidence.hypothesis_id == hypothesis.id)
    ).all()
    rows = [
        (link, evidence)
        for link, evidence in rows
        if str(evidence.trust_level).upper() != "QUARANTINED"
    ]
    support_rows = [(link, evidence) for link, evidence in rows if link.relation == "SUPPORTS"]
    refute_rows = [(link, evidence) for link, evidence in rows if link.relation == "REFUTES"]
    support_sources = {independent_source_key(evidence) for _, evidence in support_rows}
    refute_sources = {independent_source_key(evidence) for _, evidence in refute_rows}
    support_observations = {_evidence_fingerprint(evidence) for _, evidence in support_rows}
    refute_observations = {_evidence_fingerprint(evidence) for _, evidence in refute_rows}

    score = (
        len(support_observations) * 20
        + len(support_sources) * 20
        - len(refute_observations) * 30
        - len(refute_sources) * 10
    )
    bounded_score = max(0, min(100, score))
    if support_rows and len(support_sources) < 2:
        bounded_score = min(69, bounded_score)
    hypothesis.confidence_score = bounded_score
    if refute_rows and len(refute_sources) >= len(support_sources):
        hypothesis.status = "REJECTED"
        hypothesis.confidence_level = "LOW"
    elif support_rows:
        hypothesis.status = "SUPPORTED"
        if (
            hypothesis.confidence_score >= 70
            and len(support_sources) >= 2
            and not refute_rows
        ):
            hypothesis.confidence_level = "HIGH"
        elif hypothesis.confidence_score >= 40:
            hypothesis.confidence_level = "MEDIUM"
        else:
            hypothesis.confidence_level = "LOW"
    else:
        hypothesis.status = "OPEN"
        hypothesis.confidence_level = "LOW"
    hypothesis.updated_at = utcnow()
    return hypothesis


def mark_open_hypotheses_inconclusive(
    session: Session,
    investigation: Investigation,
) -> None:
    hypotheses = list(
        session.scalars(
            select(Hypothesis).where(
                Hypothesis.investigation_id == investigation.id,
                Hypothesis.status == "OPEN",
            )
        )
    )
    for hypothesis in hypotheses:
        hypothesis.status = "INCONCLUSIVE"
        hypothesis.updated_at = utcnow()
    session.flush()


def _get_or_create_evidence(
    session: Session,
    investigation: Investigation,
    *,
    source_ref: str,
    source_type: str,
    source_key: str,
    tool_call_id: int | None,
    title: str,
    summary: str,
    payload: dict[str, Any],
    trust_level: str,
    observed_at,
) -> EvidenceItem:  # type: ignore[no-untyped-def]
    existing = session.scalar(
        select(EvidenceItem).where(
            EvidenceItem.investigation_id == investigation.id,
            EvidenceItem.source_ref == source_ref,
        )
    )
    if existing is not None:
        return existing
    item = EvidenceItem(
        investigation_id=investigation.id,
        source_ref=source_ref,
        source_type=source_type,
        source_key=source_key,
        tool_call_id=tool_call_id,
        title=title[:256],
        summary=summary[:500],
        payload_json=payload,
        trust_level=trust_level[:32],
        observed_at=observed_at,
    )
    session.add(item)
    session.flush()
    return item


def _summarize_observation(
    observation: dict[str, Any],
    source_key: str | None = None,
) -> str:
    if source_key == "system_snapshot":
        return _system_snapshot_summary(observation)
    if source_key == "service_status":
        return _service_status_summary(observation)
    if source_key == "service_desired_state":
        return _service_desired_state_summary(observation)
    if source_key == "service_catalog_snapshot":
        return _service_catalog_snapshot_summary(observation)
    if source_key == "process_runtime_detail":
        return _process_runtime_summary(observation)
    if source_key == "journal_storage_status":
        return _journal_storage_summary(observation)
    if source_key == "deleted_open_files":
        return _scalar_summary(
            observation,
            (
                "path",
                "size_bytes",
                "open_handle_count",
                "pid",
                "process",
                "uid",
                "systemd_unit",
                "retained_file_count",
                "retained_bytes",
                "scan_complete",
            ),
            max_parts=10,
        )
    if source_key == "socket_process_context":
        return _socket_process_context_summary(observation)
    if source_key == "service_dependency_snapshot":
        return _service_dependency_snapshot_summary(observation)
    if source_key == "filesystem_mount_context":
        return _filesystem_mount_context_summary(observation)
    if source_key == "service_health_probe":
        return _service_health_summary(observation)
    if source_key == "application_log_query":
        return _application_log_summary(observation)
    parts: list[str] = []
    priority = (
        "path",
        "unit",
        "local_address",
        "exposure_scope",
        "process",
        "process_name",
        "name",
        "pid",
        "user",
        "active_state",
        "status",
        "open_fd_count",
        "fd_utilization_percent",
        "systemd_unit",
        "reported_disk_usage_bytes",
        "settings_available",
        "used_percent",
        "size_bytes",
        "comm",
        "state",
        "hostname",
        "machine",
    )
    ordered_keys = [key for key in priority if key in observation]
    ordered_keys.extend(key for key in observation if key not in set(ordered_keys))
    for key in ordered_keys:
        value = observation[key]
        if isinstance(value, (str, int, float, bool)) or value is None:
            normalized = "-" if value is None else str(value)
            parts.append(f"{key}={normalized[:120]}")
        if len(parts) >= 5:
            break
    if parts:
        return "，".join(parts)[:500]
    return "已记录结构化观测；详细字段保存在 MCP 工具调用结果中。"


def _service_status_summary(observation: dict[str, Any]) -> str:
    if observation.get("scope") == "failed_services":
        return _scalar_summary(
            observation,
            ("scope", "failed_count"),
            max_parts=2,
        )
    normalized = {
        "unit": observation.get("unit") or observation.get("Id"),
        "active_state": observation.get("active_state") or observation.get("active"),
        "sub_state": observation.get("sub_state") or observation.get("sub"),
        "result": observation.get("result") or observation.get("Result"),
        "exec_start_path": observation.get("exec_start_path"),
        "exec_main_status": observation.get("exec_main_status"),
        "main_pid": observation.get("main_pid"),
        "fragment_path": observation.get("fragment_path"),
    }
    present = {key: value for key, value in normalized.items() if value is not None}
    return _scalar_summary(present, tuple(present), max_parts=8)


def _service_desired_state_summary(observation: dict[str, Any]) -> str:
    fields = (
        "unit",
        "host_key",
        "expected_active_state",
        "service_owner",
        "criticality",
        "environment",
        "version",
        "source_ref",
    )
    return _scalar_summary(observation, fields, max_parts=8)


def _service_catalog_snapshot_summary(observation: dict[str, Any]) -> str:
    listeners = observation.get("listener_expectations")
    listener_count = len(listeners) if isinstance(listeners, list) else 0
    normalized = {
        "unit_name": observation.get("unit_name"),
        "host_key": observation.get("host_key"),
        "expected_active_state": observation.get("expected_active_state"),
        "service_owner": observation.get("service_owner"),
        "criticality": observation.get("criticality"),
        "environment": observation.get("environment"),
        "listener_expectation_count": listener_count,
        "version": observation.get("version"),
        "source_ref": observation.get("source_ref"),
    }
    return _scalar_summary(normalized, tuple(normalized), max_parts=9)


def _quarantine_summary(threats: tuple[Any, ...]) -> str:
    labels = "、".join(dict.fromkeys(str(threat.label) for threat in threats))
    return f"证据内容命中非可信指令规则（{labels}），已隔离且未送入模型上下文。"[:500]


def _scan_tool_observation(
    tool_name: str,
    observation: dict[str, Any],
) -> tuple[Any, ...]:
    schema_fields = _TOOL_SCHEMA_CONTROL_FIELDS.get(tool_name, frozenset())
    if not schema_fields:
        return scan_untrusted_content(observation)
    structural_payload = {
        key: value
        for key, value in observation.items()
        if key not in schema_fields
    }
    threats = list(scan_untrusted_content(structural_payload))
    for key in schema_fields:
        if key in observation:
            threats.extend(scan_untrusted_content(observation[key]))
    return tuple(dict.fromkeys(threats))


def _service_health_summary(observation: dict[str, Any]) -> str:
    body = observation.get("body_summary")
    body = body if isinstance(body, dict) else {}
    facts = [
        f"url={observation.get('url') or '-'}",
        f"status_code={observation.get('status_code') or '-'}",
        f"latency_ms={observation.get('latency_ms') or '-'}",
        f"available={observation.get('available')}",
    ]
    for key in ("service", "status", "dependency", "reason", "correlation_id", "log_path"):
        value = body.get(key)
        if value is not None:
            facts.append(f"{key}={str(value)[:160]}")
    return "，".join(facts)[:500]


def _application_log_summary(observation: dict[str, Any]) -> str:
    facts = [
        f"path={observation.get('path') or '-'}",
        f"line_count={observation.get('line_count') or 0}",
    ]
    records = observation.get("records")
    records = records if isinstance(records, list) else []
    for record in reversed(records):
        if not isinstance(record, dict):
            continue
        if record.get("event") == "request_failed":
            for key in (
                "event",
                "correlation_id",
                "dependency",
                "reason",
                "server.address",
                "server.port",
                "network.transport",
                "error.type",
                "dependency_timeout_ms",
                "observed_latency_ms",
                "http_status",
            ):
                value = record.get(key)
                if value is not None:
                    facts.append(f"{key}={str(value)[:120]}")
            break
    config_record = next(
        (
            record
            for record in reversed(records)
            if isinstance(record, dict) and record.get("event") == "config_metadata_changed"
        ),
        None,
    )
    if config_record is not None:
        facts.append(f"config_path={config_record.get('path') or '-'}")
        facts.append(
            f"content_hash_unchanged={config_record.get('content_hash_unchanged')}"
        )
    return "，".join(facts)[:500]


def _content_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _system_snapshot_summary(observation: dict[str, Any]) -> str:
    facts: dict[str, Any] = {
        "hostname": observation.get("hostname"),
        "machine": observation.get("machine"),
        "is_loongarch": observation.get("is_loongarch"),
    }
    loadavg = observation.get("loadavg")
    if isinstance(loadavg, list):
        for key, value in zip(("load_1m", "load_5m", "load_15m"), loadavg[:3]):
            facts[key] = value
    memory = observation.get("memory")
    if isinstance(memory, dict):
        facts["memory_used_percent"] = memory.get("used_percent")
        facts["memory_available_kb"] = memory.get("available_kb")
    pressure = observation.get("pressure")
    if isinstance(pressure, dict):
        facts["psi_cpu_some_avg10"] = _nested_value(pressure, "cpu", "some", "avg10")
        facts["psi_memory_some_avg10"] = _nested_value(pressure, "memory", "some", "avg10")
        facts["psi_io_some_avg10"] = _nested_value(pressure, "io", "some", "avg10")
        facts["psi_io_full_avg10"] = _nested_value(pressure, "io", "full", "avg10")
    return _scalar_summary(facts, tuple(facts), max_parts=12)


def _nested_value(values: dict[str, Any], *path: str) -> Any:
    current: Any = values
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _process_runtime_summary(observation: dict[str, Any]) -> str:
    facts = dict(observation)
    fd_type_counts = observation.get("fd_type_counts")
    if isinstance(fd_type_counts, dict):
        facts["fd_types"] = "/".join(
            f"{key}:{value}"
            for key, value in fd_type_counts.items()
            if isinstance(value, int) and value > 0
        )
    keys = (
        "name",
        "pid",
        "state",
        "uid",
        "vm_rss_kb",
        "vm_size_kb",
        "open_fd_count",
        "max_open_files_soft",
        "max_open_files_hard",
        "max_processes_soft",
        "max_processes_hard",
        "fd_utilization_percent",
        "systemd_unit",
        "container_hint",
        "executable_path",
        "fd_types",
        "fd_scan_truncated",
    )
    return _scalar_summary(facts, keys, max_parts=18)


def _journal_storage_summary(observation: dict[str, Any]) -> str:
    facts: dict[str, Any] = {
        "reported_disk_usage_bytes": observation.get("reported_disk_usage_bytes"),
        "settings_status": observation.get("settings_status"),
        "settings_available": observation.get("settings_available"),
    }
    storage = observation.get("storage")
    if isinstance(storage, list):
        for item in storage:
            if not isinstance(item, dict):
                continue
            storage_type = item.get("storage_type")
            if storage_type not in {"persistent", "runtime"}:
                continue
            facts[f"{storage_type}_bytes"] = item.get("total_bytes")
            facts[f"{storage_type}_archived_file_count"] = item.get(
                "archived_file_count"
            )
            facts[f"{storage_type}_scan_truncated"] = item.get("scan_truncated")
    settings = observation.get("settings")
    if isinstance(settings, dict):
        for key in ("Storage", "SystemMaxUse", "RuntimeMaxUse", "MaxRetentionSec"):
            if key in settings:
                facts[key] = settings[key]
    return _scalar_summary(facts, tuple(facts), max_parts=10)


def _socket_process_context_summary(observation: dict[str, Any]) -> str:
    facts: dict[str, Any] = {
        key: observation.get(key)
        for key in (
            "protocol",
            "port",
            "listener_count",
            "unattributed_count",
            "scan_truncated",
        )
    }
    listeners = observation.get("listeners")
    if isinstance(listeners, list) and listeners and isinstance(listeners[0], dict):
        first = listeners[0]
        for key in (
            "local_address",
            "exposure_scope",
            "pid",
            "process_name",
            "user",
            "systemd_unit",
            "container_hint",
            "attribution_source",
        ):
            facts[key] = first.get(key)
    return _scalar_summary(facts, tuple(facts), max_parts=13)


def _service_dependency_snapshot_summary(observation: dict[str, Any]) -> str:
    facts = {
        "services": observation.get("service_count", 0),
        "systemd_units": observation.get("systemd_unit_count", 0),
        "processes": observation.get("process_count", 0),
        "listeners": observation.get("listener_count", 0),
        "connections": observation.get("connection_relation_count", 0),
        "external_endpoints": observation.get("external_endpoint_count", 0),
        "evidence_gaps": len(observation.get("evidence_gaps", []))
        if isinstance(observation.get("evidence_gaps"), list)
        else 0,
    }
    summary = _scalar_summary(facts, tuple(facts), max_parts=6)
    nodes = observation.get("nodes")
    edges = observation.get("edges")
    node_labels = {
        str(node.get("id")): _relationship_node_label(node)
        for node in nodes
        if isinstance(node, dict) and node.get("id")
    } if isinstance(nodes, list) else {}
    relation_labels = {
        "RUNS_PROCESS": "运行进程",
        "LISTENS_ON": "监听",
        "CONNECTS_TO": "已建立连接",
        "REQUIRES": "强依赖",
        "WANTS": "弱依赖",
        "BINDS_TO": "绑定",
        "PART_OF": "随目标启停",
        "PROPAGATES_STOP_TO": "停止传播",
        "PROPAGATES_RELOAD_TO": "重载传播",
        "TRIGGERS": "触发",
        "BEFORE": "先于",
        "AFTER": "后于",
    }
    relation_samples: list[str] = []
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            source = node_labels.get(str(edge.get("source")), str(edge.get("source") or "-"))
            target = node_labels.get(str(edge.get("target")), str(edge.get("target") or "-"))
            relation = relation_labels.get(
                str(edge.get("relation")),
                str(edge.get("relation") or "关联"),
            )
            count = edge.get("observation_count")
            suffix = f"({count}条)" if relation == "已建立连接" and isinstance(count, int) else ""
            relation_samples.append(f"{source}->{relation}->{target}{suffix}")
            if len(relation_samples) >= 4:
                break
    if relation_samples:
        summary = f"{summary}，relations={'；'.join(relation_samples)}"
    impact = observation.get("change_impact")
    if isinstance(impact, dict) and impact.get("action") != "observe":
        summary = (
            f"{summary}，change_impact={impact.get('status')}"
            f"/propagated_units:{impact.get('propagated_unit_count', 0)}"
            f"/current_clients:{impact.get('possible_client_count', 0)}"
        )
    return summary[:500]


def _relationship_node_label(node: dict[str, Any]) -> str:
    label = str(node.get("label") or node.get("id") or "-")
    pid = node.get("pid")
    if node.get("kind") == "process" and isinstance(pid, int):
        return f"{label}(pid={pid})"
    return label


def _filesystem_mount_context_summary(observation: dict[str, Any]) -> str:
    keys = (
        "resolved_path",
        "mount_target",
        "source",
        "filesystem_type",
        "read_only",
        "noexec",
        "nosuid",
        "nodev",
        "is_network_filesystem",
        "used_percent",
    )
    return _scalar_summary(observation, keys, max_parts=10)


def _scalar_summary(
    values: dict[str, Any],
    keys: tuple[str, ...],
    *,
    max_parts: int = 8,
) -> str:
    parts: list[str] = []
    for key in keys:
        value = values.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            normalized = "-" if value is None else str(value)
            parts.append(f"{key}={normalized[:120]}")
        if len(parts) >= max_parts:
            break
    return "，".join(parts)[:500] or "已记录结构化观测。"


def independent_source_key(evidence: EvidenceItem | Any) -> str:
    if evidence.source_type != "MCP":
        return f"{evidence.source_type}:{evidence.source_key}"
    return f"MCP:{_mcp_probe_family(evidence)}"


def _mcp_probe_family(evidence: EvidenceItem | Any) -> str:
    source_key = evidence.source_key
    if source_key in {
        "network_listeners",
        "socket_process_context",
        "service_dependency_snapshot",
    }:
        return "socket_inventory"
    if source_key in {"service_desired_state", "service_catalog_snapshot"}:
        return "operator_approved_service_catalog"
    if source_key in {"disk_usage", "filesystem_mount_context"}:
        return "filesystem_capacity"
    if source_key in {"process_file_handles", "process_runtime_detail"}:
        return "process_descriptor_state"
    if source_key == "journal_storage_status":
        return "journal_storage"
    if source_key == "find_large_files":
        raw_payload = getattr(evidence, "payload_json", {})
        payload = raw_payload if isinstance(raw_payload, dict) else {}
        path = str(payload.get("path") or "")
        if path == "/var/log/journal" or path.startswith("/var/log/journal/"):
            return "journal_storage"
    return source_key


def _evidence_fingerprint(evidence: EvidenceItem) -> str:
    payload = evidence.payload_json if isinstance(evidence.payload_json, dict) else {}
    return json.dumps(
        {
            "source_type": evidence.source_type,
            "source_key": evidence.source_key,
            "payload": payload,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
