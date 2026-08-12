from __future__ import annotations

import re
from typing import Any


class AgentResponder:
    def compose(
        self,
        task: Any,
        analysis_result: dict[str, Any] | None,
        canonical_summary: str,
    ) -> str:
        if not analysis_result:
            return canonical_summary

        actions = analysis_result.get("recommended_actions")
        next_step = ""
        if isinstance(actions, list) and actions and isinstance(actions[0], dict):
            next_step = _sanitize_text(
                _stringify(actions[0].get("rationale") or actions[0].get("title")),
                max_chars=150,
            )
        safety_note = _sanitize_text(
            _stringify(analysis_result.get("residual_risk")),
            max_chars=150,
        )

        parts = [canonical_summary]
        if next_step:
            parts.append("研判建议：" + next_step)
        if safety_note:
            parts.append("待确认风险：" + safety_note)
        return " ".join(part for part in parts if part).strip()


def _sanitize_text(value: str, max_chars: int) -> str:
    text = value.strip()
    text = _humanize_diagnostic_terms(text)
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"(?im)^\s*(?:[-*]|\d+[.)])\s*", "", text)
    text = re.sub(r"\b(?:sudo\s+)?rm\s+-[^\s，。；;]*\s+\S+", "危险删除命令", text)
    text = re.sub(r"[*_#>]+", "", text)
    text = re.sub(r"\s+", " ", text).strip(" -；;")
    text = re.sub(r"(?<=[\u4e00-\u9fff])\s+(?=[\u4e00-\u9fff])", "", text)
    if len(text) > max_chars:
        return f"{text[: max_chars - 3].rstrip()}..."
    return text


def _humanize_diagnostic_terms(value: str) -> str:
    labels = {
        "fd_utilization_percent": "文件句柄使用率",
        "open_fd_count": "打开句柄数",
        "max_open_files_soft": "文件句柄软上限",
        "fd_type_counts": "句柄类型分布",
        "systemd_unit": "服务单元",
    }
    text = value
    for field, label in labels.items():
        text = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(field)}(?![A-Za-z0-9_])",
            label,
            text,
            flags=re.IGNORECASE,
        )
    scope_labels = {
        "loopback": "本机回环",
        "private": "内网",
        "link_local": "链路本地",
        "wildcard": "所有地址",
        "public": "公网",
        "unknown": "范围未知",
    }
    for scope, label in scope_labels.items():
        text = re.sub(
            rf"(?<![A-Za-z0-9_])exposure_?scope\s*=\s*{scope}(?![A-Za-z0-9_])",
            f"暴露范围为{label}",
            text,
            flags=re.IGNORECASE,
        )
    return text


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)
