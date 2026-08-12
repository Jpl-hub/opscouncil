from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class DocumentChunk:
    content: str
    kind: str


_SECTION_KINDS: dict[str, tuple[tuple[str, ...], str]] = {
    "runbook": (
        (("排查流程", "推荐流程", "排查顺序", "处置流程", "操作步骤"), "procedure"),
        (("处置边界", "执行边界", "安全边界", "回滚要求", "审批要求", "异常处置"), "safety"),
        (("适用场景", "适用对象", "排查目标"), "context"),
    ),
    "incident_review": (
        (("故障现象", "影响范围", "告警现象"), "symptom"),
        (("时间线", "事件过程", "故障过程"), "event"),
        (("根因", "直接原因", "根本原因"), "root_cause"),
        (("恢复过程", "解决过程", "处置结果", "修复过程"), "resolution"),
    ),
    "architecture": (
        (("架构", "组件", "模块", "数据流", "部署"), "architecture"),
    ),
    "policy": (
        (("判断规则", "控制要求", "管理要求"), "rule"),
        (("处置边界", "审批要求", "禁止事项", "安全要求"), "safety"),
        (("适用对象", "适用范围"), "scope"),
    ),
}


def split_document(
    content: str,
    source_type: str,
    *,
    max_chars: int = 900,
    overlap: int = 120,
) -> list[DocumentChunk]:
    if max_chars < 40:
        raise ValueError("max_chars must be at least 40")
    if overlap < 0 or overlap >= max_chars:
        raise ValueError("overlap must be non-negative and smaller than max_chars")

    normalized = re.sub(r"\r\n?", "\n", content).strip()
    if not normalized:
        return []

    paragraphs = [item.strip() for item in re.split(r"\n\s*\n", normalized) if item.strip()]
    grouped: list[DocumentChunk] = []
    for paragraph in paragraphs:
        kind = _section_kind(paragraph, source_type)
        if grouped and grouped[-1].kind == kind:
            combined = f"{grouped[-1].content}\n\n{paragraph}"
            if len(combined) <= max_chars:
                grouped[-1] = DocumentChunk(content=combined, kind=kind)
                continue
        grouped.extend(
            DocumentChunk(content=piece, kind=kind)
            for piece in _split_oversized(paragraph, max_chars=max_chars, overlap=overlap)
        )
    return grouped


def _section_kind(paragraph: str, source_type: str) -> str:
    normalized_type = source_type.strip().lower()
    for prefixes, kind in _SECTION_KINDS.get(normalized_type, ()):
        if paragraph.startswith(prefixes):
            return kind
    return {
        "runbook": "guidance",
        "incident_review": "analysis",
        "architecture": "architecture",
        "policy": "policy",
    }.get(normalized_type, "content")


def _split_oversized(text: str, *, max_chars: int, overlap: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    step = max_chars - overlap
    return [
        text[start : start + max_chars].strip()
        for start in range(0, len(text), step)
        if text[start : start + max_chars].strip()
    ]
