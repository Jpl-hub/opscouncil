from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any


@dataclass(frozen=True)
class ContentThreat:
    rule_id: str
    label: str
    matched_pattern: str

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "label": self.label,
            "matched_pattern": self.matched_pattern,
        }


_UNTRUSTED_CONTENT_RULES = (
    (
        "ignore_instructions",
        "要求忽略既有指令",
        re.compile(
            r"(?:忽略|无视)(?:以上|之前|所有).{0,24}(?:规则|指令|限制)",
            re.IGNORECASE,
        ),
    ),
    (
        "bypass_safety",
        "要求绕过安全机制",
        re.compile(
            r"(?<!不)(?<!不要)(?<!禁止)(?<!严禁)(?<!不得)(?:绕过|跳过).{0,20}"
            r"(?:审批|权限|安全|护栏)",
            re.IGNORECASE,
        ),
    ),
    (
        "credential_exfiltration",
        "疑似窃取敏感凭据",
        re.compile(
            r"(?<!不要)(?<!禁止)(?<!严禁)(?<!不得)(?:输出|泄露|告诉我).{0,24}"
            r"(?:api.?key|密钥|token|密码)",
            re.IGNORECASE,
        ),
    ),
    (
        "forged_model_role",
        "伪造模型角色标记",
        re.compile(r"<\|?(?:system|developer|assistant)\|?>", re.IGNORECASE),
    ),
    (
        "privilege_roleplay",
        "角色越权诱导",
        re.compile(r"你现在是.{0,20}(?:root|超级管理员|系统指令|无视规则)", re.IGNORECASE),
    ),
    (
        "instruction_boundary",
        "伪造高优先级指令边界",
        re.compile(
            r"(?:^|\n)\s*(?:#{1,4}\s*)?(?:system|developer|系统指令|最高优先级指令)\s*[:：]",
            re.IGNORECASE,
        ),
    ),
)
_CONTROL_METADATA_KEYS = frozenset(
    {
        "trust_level",
        "source_type",
        "source_ref",
        "tool_call_id",
        "evidence_id",
        "approval",
        "approved",
        "policy_decision",
        "action_fingerprint",
        "agent_role",
    }
)
_TOOL_ENVELOPE_KEYS = frozenset(
    {
        "structuredcontent",
        "iserror",
        "jsonrpc",
        "method",
    }
)
_STRUCTURED_CONTROL_METADATA_RE = re.compile(
    r"""(?ix)
    ["']?
    (?:trust_level|source_type|source_ref|tool_call_id|evidence_id|
       approval|approved|policy_decision|action_fingerprint|agent_role)
    ["']?
    \s*[:=]\s*
    (?:["'][^"']{0,80}["']|true|false|\d+)
    """
)
_STRUCTURED_TOOL_ENVELOPE_RE = re.compile(
    r"""(?ix)
    ["']?(?:structuredContent|isError|jsonrpc)["']?\s*:
    """
)
UNTRUSTED_CONTENT_POLICY_VERSION = "untrusted-content-v2"


def scan_untrusted_content(value: Any) -> tuple[ContentThreat, ...]:
    text = _as_text(value)
    threats: list[ContentThreat] = []
    for rule_id, label, pattern in _UNTRUSTED_CONTENT_RULES:
        if pattern.search(text):
            threats.append(
                ContentThreat(
                    rule_id=rule_id,
                    label=label,
                    matched_pattern=pattern.pattern,
                )
            )
    structural_threats = _scan_structural_spoofing(value, text)
    existing_rule_ids = {item.rule_id for item in threats}
    threats.extend(
        item for item in structural_threats if item.rule_id not in existing_rule_ids
    )
    return tuple(threats)


def untrusted_content_policy_identity() -> dict[str, str]:
    payload = {
        "text_rules": [
            {
                "rule_id": rule_id,
                "label": label,
                "pattern": pattern.pattern,
                "flags": pattern.flags,
            }
            for rule_id, label, pattern in _UNTRUSTED_CONTENT_RULES
        ],
        "control_metadata_keys": sorted(_CONTROL_METADATA_KEYS),
        "tool_envelope_keys": sorted(_TOOL_ENVELOPE_KEYS),
        "structured_control_pattern": _STRUCTURED_CONTROL_METADATA_RE.pattern,
        "structured_tool_pattern": _STRUCTURED_TOOL_ENVELOPE_RE.pattern,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "version": UNTRUSTED_CONTENT_POLICY_VERSION,
        "digest": hashlib.sha256(encoded).hexdigest(),
    }


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return str(value)


def _scan_structural_spoofing(
    value: Any,
    text: str,
) -> tuple[ContentThreat, ...]:
    control_path = _first_reserved_key_path(value, _CONTROL_METADATA_KEYS)
    envelope_path = _first_reserved_key_path(value, _TOOL_ENVELOPE_KEYS)
    if control_path is None:
        match = _STRUCTURED_CONTROL_METADATA_RE.search(text)
        control_path = match.group(0)[:120] if match else None
    if envelope_path is None:
        match = _STRUCTURED_TOOL_ENVELOPE_RE.search(text)
        envelope_path = match.group(0)[:120] if match else None

    threats: list[ContentThreat] = []
    if control_path is not None:
        threats.append(
            ContentThreat(
                rule_id="control_metadata_spoofing",
                label="疑似伪造 Agent 控制元数据",
                matched_pattern=control_path,
            )
        )
    if envelope_path is not None:
        threats.append(
            ContentThreat(
                rule_id="tool_envelope_spoofing",
                label="疑似伪造工具返回信封",
                matched_pattern=envelope_path,
            )
        )
    return tuple(threats)


def _first_reserved_key_path(
    value: Any,
    reserved: frozenset[str],
    *,
    path: str = "$",
) -> str | None:
    if isinstance(value, dict):
        for raw_key, nested in value.items():
            key = str(raw_key)
            normalized = re.sub(r"[^a-z0-9_]", "", key.lower())
            current_path = f"{path}.{key}"
            if normalized in reserved:
                return current_path
            nested_path = _first_reserved_key_path(
                nested,
                reserved,
                path=current_path,
            )
            if nested_path is not None:
                return nested_path
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            nested_path = _first_reserved_key_path(
                nested,
                reserved,
                path=f"{path}[{index}]",
            )
            if nested_path is not None:
                return nested_path
    return None
