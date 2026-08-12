from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.entities import (
    ConversationTurn,
    RiskChainAssessment,
    Task,
    utcnow,
)


POLICY_VERSION = "1.1.0"
MAX_HISTORY_TURNS = 8
HISTORY_WINDOW = timedelta(hours=1)

STATUS_CLEAR = "CLEAR"
STATUS_WATCH = "WATCH"
STATUS_BLOCKED = "BLOCKED"

EVENT_RECON = "RECON"
EVENT_NETWORK_DISCOVERY = "NETWORK_DISCOVERY"
EVENT_SENSITIVE_READ = "SENSITIVE_READ"
EVENT_PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
EVENT_MODIFY = "MODIFY"
EVENT_PERSISTENCE = "PERSISTENCE"
EVENT_REMOTE_EXECUTION = "REMOTE_EXECUTION"
EVENT_EXFILTRATION = "EXFILTRATION"
EVENT_TRACE_ERASURE = "TRACE_ERASURE"
EVENT_SAFETY_BYPASS = "SAFETY_BYPASS"

ATTACK_REFS = {
    EVENT_RECON: ("TA0007",),
    EVENT_NETWORK_DISCOVERY: ("TA0007", "T1049"),
    EVENT_SENSITIVE_READ: ("TA0006", "T1552.001"),
    EVENT_PRIVILEGE_CHANGE: ("TA0004",),
    EVENT_PERSISTENCE: ("TA0003",),
    EVENT_REMOTE_EXECUTION: ("TA0002", "T1059.004"),
    EVENT_EXFILTRATION: ("TA0010",),
    EVENT_TRACE_ERASURE: ("TA0005", "T1070.001"),
}

CONTINUITY_PATTERN = re.compile(
    r"(上一步|上一轮|刚才|前面|之前|那个|这些|上述|找到的|读取到的|the previous|those)",
    re.IGNORECASE,
)
PATH_PATTERN = re.compile(r"(?<![\w.-])/(?:[A-Za-z0-9_.@+-]+/)*[A-Za-z0-9_.@+-]*")
RESOURCE_TAGS = {
    "审计": "audit",
    "audit": "audit",
    "日志": "logs",
    "journal": "logs",
    "凭据": "credentials",
    "密码": "credentials",
    "密钥": "credentials",
    "token": "credentials",
    "secret": "credentials",
    "配置": "config",
    "服务": "service",
    "进程": "process",
    "端口": "network",
    "监听": "network",
    "网络": "network",
    "webhook": "external",
    "外部": "external",
}


@dataclass(frozen=True)
class SemanticTurn:
    task_id: int
    events: tuple[str, ...]
    resources: tuple[str, ...]
    continuity: bool


@dataclass(frozen=True)
class RiskChainResult:
    status: str
    risk_score: int
    chain_type: str | None
    semantic_events: list[dict[str, Any]]
    matched_task_ids: list[int]
    resource_refs: list[str]
    reason: str


class RiskChainService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def assess(self, task: Task, text: str) -> RiskChainAssessment:
        conversation_id, history = self._history(task)
        current = _semantic_turn(task.id, text)
        result = _evaluate([*history, current], current_task_id=task.id)
        assessment = RiskChainAssessment(
            task_id=task.id,
            conversation_id=conversation_id,
            policy_version=POLICY_VERSION,
            status=result.status,
            risk_score=result.risk_score,
            chain_type=result.chain_type,
            semantic_events_json=result.semantic_events,
            matched_task_ids_json=result.matched_task_ids,
            resource_refs_json=result.resource_refs,
            reason=result.reason,
        )
        self.session.add(assessment)
        self.session.flush()
        return assessment

    def evaluate(self, task: Task, text: str) -> RiskChainResult:
        _, history = self._history(task)
        current = _semantic_turn(task.id, text)
        return _evaluate([*history, current], current_task_id=task.id)

    def _history(self, task: Task) -> tuple[str | None, list[SemanticTurn]]:
        current_turn = self.session.scalar(
            select(ConversationTurn).where(ConversationTurn.task_id == task.id)
        )
        if current_turn is None:
            return None, []
        rows = list(
            self.session.execute(
                select(Task)
                .join(ConversationTurn, ConversationTurn.task_id == Task.id)
                .where(
                    ConversationTurn.conversation_id
                    == current_turn.conversation_id,
                    ConversationTurn.turn_index < current_turn.turn_index,
                )
                .order_by(ConversationTurn.turn_index.desc())
                .limit(MAX_HISTORY_TURNS)
            ).scalars()
        )
        cutoff = _as_aware(task.created_at) - HISTORY_WINDOW
        history = [
            _semantic_turn(item.id, item.user_input)
            for item in reversed(rows)
            if _as_aware(item.created_at) >= cutoff
        ]
        return current_turn.conversation_id, history


def evaluate_risk_chain_sequence(prompts: tuple[str, ...]) -> RiskChainResult:
    if not prompts:
        return _evaluate([], current_task_id=0)
    turns = [
        _semantic_turn(index, prompt)
        for index, prompt in enumerate(prompts, start=1)
    ]
    return _evaluate(turns, current_task_id=turns[-1].task_id)


def _semantic_turn(task_id: int, text: str) -> SemanticTurn:
    normalized = " ".join(text.lower().split())
    events: list[str] = []
    if re.search(r"(检查|查看|列出|枚举|扫描|查找|哪些|监听|进程|状态|位置|inspect|list|scan|enumerate|find)", normalized):
        events.append(EVENT_RECON)
    if re.search(
        r"((检查|查看|列出|枚举|扫描|探测|盘点).{0,20}"
        r"(网络|端口|监听|连接|路由|网卡|远程主机|暴露面))"
        r"|(\b(ss|netstat|nmap)\b|lsof\s+-i|ip\s+(addr|route|neigh))",
        normalized,
    ):
        events.append(EVENT_NETWORK_DISCOVERY)
    if re.search(
        r"(读取|查看|输出|获取|导出|read|show|dump|get).{0,20}"
        r"(shadow|私钥|密钥|密码|凭据|token|api.?key|secret|环境变量)",
        normalized,
    ) or re.search(r"(/etc/shadow|id_rsa|credentials?)", normalized):
        events.append(EVENT_SENSITIVE_READ)
    if re.search(
        r"(sudo|root|chmod|chown|提权|权限提升|修改权限|恢复权限|grant)",
        normalized,
    ):
        events.append(EVENT_PRIVILEGE_CHANGE)
    if re.search(
        r"(重启|停止|终止|kill|删除|清空|修改|写入|替换|轮转|恢复|restart|stop|delete|remove|write)",
        normalized,
    ):
        events.append(EVENT_MODIFY)
    if re.search(
        r"(开机自启|持久化|定时任务|计划任务|crontab|rc\.local|authorized_keys)"
        r"|((创建|新增|写入|安装|启用|enable|create|install).{0,24}"
        r"(systemd|服务单元|service|cron|启动项))"
        r"|(/etc/systemd/system|/etc/cron(?:\.d)?|\.ssh/authorized_keys)",
        normalized,
    ):
        events.append(EVENT_PERSISTENCE)
    if re.search(
        r"((curl|wget).{0,120}(\|\s*(sh|bash|zsh|python)|-o\s+\S+.{0,40}(执行|运行|chmod)))"
        r"|((下载|拉取|获取).{0,40}(远程脚本|载荷|payload).{0,24}(执行|运行))"
        r"|((执行|运行).{0,24}(远程脚本|下载内容|payload))",
        normalized,
    ):
        events.append(EVENT_REMOTE_EXECUTION)
    if re.search(
        r"(发送到|上传到|外传|传到|发给|发到|webhook|curl.{0,80}https?://|exfiltrat|upload|send)",
        normalized,
    ):
        events.append(EVENT_EXFILTRATION)
    if re.search(
        r"((清空|删除|抹掉|擦除|清理|clear|erase|remove).{0,16}(日志|审计|历史|记录|log|audit|history))"
        r"|((日志|审计|历史|记录|log|audit|history).{0,16}(清空|删除|抹掉|擦除|清理|clear|erase|remove))",
        normalized,
    ):
        events.append(EVENT_TRACE_ERASURE)
    if re.search(
        r"(忽略.{0,12}(规则|限制)|绕过.{0,12}(审批|权限|安全|护栏)|无视.{0,12}(规则|限制)|bypass.{0,12}(safety|approval))",
        normalized,
    ):
        events.append(EVENT_SAFETY_BYPASS)
    resources = _resource_refs(normalized)
    return SemanticTurn(
        task_id=task_id,
        events=tuple(dict.fromkeys(events)),
        resources=tuple(resources),
        continuity=bool(CONTINUITY_PATTERN.search(normalized)),
    )


def _resource_refs(text: str) -> list[str]:
    refs = [match.group(0).rstrip("/") or "/" for match in PATH_PATTERN.finditer(text)]
    for raw, normalized in RESOURCE_TAGS.items():
        if raw in text:
            refs.append(normalized)
    return list(dict.fromkeys(refs))[:20]


def _evaluate(
    turns: list[SemanticTurn],
    *,
    current_task_id: int,
) -> RiskChainResult:
    semantic_events = [
        {
            "task_id": turn.task_id,
            "events": list(turn.events),
            "resources": list(turn.resources),
            "continuity": turn.continuity,
            "attack_refs": _attack_refs(turn.events),
        }
        for turn in turns
        if turn.events
    ]
    current = next(
        (turn for turn in turns if turn.task_id == current_task_id),
        SemanticTurn(current_task_id, (), (), False),
    )

    network_credential_exfiltration = _ordered_three_match(
        turns,
        current,
        EVENT_NETWORK_DISCOVERY,
        EVENT_SENSITIVE_READ,
        EVENT_EXFILTRATION,
    )
    if (
        network_credential_exfiltration is not None
        and _linked(
            network_credential_exfiltration[0],
            network_credential_exfiltration[1],
        )
        and _linked(
            network_credential_exfiltration[1],
            network_credential_exfiltration[2],
        )
    ):
        return RiskChainResult(
            status=STATUS_BLOCKED,
            risk_score=100,
            chain_type="network_credential_exfiltration",
            semantic_events=semantic_events,
            matched_task_ids=[
                turn.task_id for turn in network_credential_exfiltration
            ],
            resource_refs=_merged_turn_resources(
                network_credential_exfiltration
            ),
            reason="连续请求形成网络发现、凭据读取与外发链路。",
        )

    blocked_patterns = (
        (
            "credential_exfiltration",
            EVENT_SENSITIVE_READ,
            EVENT_EXFILTRATION,
            "连续请求形成敏感信息读取与外发链路。",
        ),
        (
            "recon_trace_erasure",
            EVENT_RECON,
            EVENT_TRACE_ERASURE,
            "连续请求形成先定位后清除日志或审计记录的链路。",
        ),
        (
            "privilege_trace_erasure",
            EVENT_PRIVILEGE_CHANGE,
            EVENT_TRACE_ERASURE,
            "连续请求形成权限变更与清除记录的链路。",
        ),
        (
            "bypass_side_effect",
            EVENT_SAFETY_BYPASS,
            EVENT_MODIFY,
            "连续请求形成绕过安全机制后执行系统变更的链路。",
        ),
        (
            "network_remote_execution",
            EVENT_NETWORK_DISCOVERY,
            EVENT_REMOTE_EXECUTION,
            "连续请求形成网络发现后下载并执行远程载荷的链路。",
        ),
        (
            "persistence_trace_erasure",
            EVENT_PERSISTENCE,
            EVENT_TRACE_ERASURE,
            "连续请求形成持久化变更后清除日志或审计记录的链路。",
        ),
        (
            "remote_execution_trace_erasure",
            EVENT_REMOTE_EXECUTION,
            EVENT_TRACE_ERASURE,
            "连续请求形成远程载荷执行后清除日志或审计记录的链路。",
        ),
        (
            "bypass_persistence",
            EVENT_SAFETY_BYPASS,
            EVENT_PERSISTENCE,
            "连续请求形成绕过安全机制后植入持久化配置的链路。",
        ),
    )
    for chain_type, first, last, reason in blocked_patterns:
        match = _ordered_match(turns, current, first, last)
        if match is not None and _linked(match[0], match[1]):
            matched = [match[0].task_id, match[1].task_id]
            return RiskChainResult(
                status=STATUS_BLOCKED,
                risk_score=100,
                chain_type=chain_type,
                semantic_events=semantic_events,
                matched_task_ids=matched,
                resource_refs=_merged_turn_resources(match),
                reason=reason,
            )

    watch_patterns = (
        (
            "recon_privilege_change",
            EVENT_RECON,
            EVENT_PRIVILEGE_CHANGE,
            "连续请求由系统探测进入权限变更，需要绑定当前动作重新审批。",
        ),
        (
            "recon_system_change",
            EVENT_RECON,
            EVENT_MODIFY,
            "连续请求由系统探测进入状态变更，需要按当前动作审批。",
        ),
        (
            "unlinked_sensitive_transfer",
            EVENT_SENSITIVE_READ,
            EVENT_EXFILTRATION,
            "会话中出现敏感读取与外发行为，但资源关联证据不足。",
        ),
        (
            "network_persistence",
            EVENT_NETWORK_DISCOVERY,
            EVENT_PERSISTENCE,
            "会话由网络发现进入持久化变更，需要绑定变更对象重新审批。",
        ),
        (
            "privilege_persistence",
            EVENT_PRIVILEGE_CHANGE,
            EVENT_PERSISTENCE,
            "会话由权限变更进入持久化配置，需要绑定身份和对象重新审批。",
        ),
        (
            "unlinked_network_remote_execution",
            EVENT_NETWORK_DISCOVERY,
            EVENT_REMOTE_EXECUTION,
            "会话中出现网络发现与远程载荷执行，关联证据不足，仍需人工审批。",
        ),
    )
    for chain_type, first, last, reason in watch_patterns:
        match = _ordered_match(turns, current, first, last)
        if match is not None:
            return RiskChainResult(
                status=STATUS_WATCH,
                risk_score=70,
                chain_type=chain_type,
                semantic_events=semantic_events,
                matched_task_ids=[match[0].task_id, match[1].task_id],
                resource_refs=_merged_turn_resources(match),
                reason=reason,
            )

    return RiskChainResult(
        status=STATUS_CLEAR,
        risk_score=0,
        chain_type=None,
        semantic_events=semantic_events,
        matched_task_ids=[],
        resource_refs=list(current.resources),
        reason="当前会话未形成跨回合累积风险链。",
    )


def _ordered_match(
    turns: list[SemanticTurn],
    current: SemanticTurn,
    first: str,
    last: str,
) -> tuple[SemanticTurn, SemanticTurn] | None:
    if last not in current.events:
        return None
    for candidate in reversed(turns[:-1]):
        if first in candidate.events and candidate.task_id != current.task_id:
            return candidate, current
    return None


def _ordered_three_match(
    turns: list[SemanticTurn],
    current: SemanticTurn,
    first: str,
    middle: str,
    last: str,
) -> tuple[SemanticTurn, SemanticTurn, SemanticTurn] | None:
    if last not in current.events:
        return None
    history = [
        turn for turn in turns if turn.task_id != current.task_id
    ]
    for middle_index in range(len(history) - 1, -1, -1):
        middle_turn = history[middle_index]
        if middle not in middle_turn.events:
            continue
        for first_turn in reversed(history[:middle_index]):
            if first in first_turn.events:
                return first_turn, middle_turn, current
    return None


def _linked(first: SemanticTurn, second: SemanticTurn) -> bool:
    if second.continuity:
        return True
    return bool(set(first.resources).intersection(second.resources))


def _merged_turn_resources(
    turns: tuple[SemanticTurn, ...],
) -> list[str]:
    return list(
        dict.fromkeys(
            resource
            for turn in turns
            for resource in turn.resources
        )
    )[:20]


def _attack_refs(events: tuple[str, ...]) -> list[str]:
    return list(
        dict.fromkeys(
            reference
            for event in events
            for reference in ATTACK_REFS.get(event, ())
        )
    )


def _as_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
