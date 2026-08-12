#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


DEFAULT_API_URL = "http://127.0.0.1:8000/api"
TERMINAL_QUEUE_STATUSES = {"SUCCEEDED", "FAILED", "CANCELLED"}


class CliError(RuntimeError):
    """A user-facing command failure."""


class ApiClient:
    def __init__(self, base_url: str, timeout_seconds: float = 20.0) -> None:
        normalized = base_url.rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise CliError("API 地址必须使用 http:// 或 https://。")
        self.base_url = normalized
        self.timeout_seconds = timeout_seconds

    def get(self, path: str, query: dict[str, Any] | None = None) -> Any:
        suffix = f"?{urlencode(query)}" if query else ""
        return self._request(f"{path}{suffix}", method="GET")

    def post(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        return self._request(path, method="POST", payload=payload)

    def _request(
        self,
        path: str,
        *,
        method: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.base_url}/{path.lstrip('/')}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                response_body = response.read()
        except HTTPError as exc:
            detail = _error_detail(exc.read())
            raise CliError(f"API 返回 {exc.code}：{detail}") from exc
        except URLError as exc:
            raise CliError(f"无法连接 OpsCouncil API：{exc.reason}") from exc
        except TimeoutError as exc:
            raise CliError("OpsCouncil API 请求超时。") from exc
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CliError("OpsCouncil API 返回了无效 JSON。") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opscouncilctl",
        description="OpsCouncil 本机运维控制台",
    )
    parser.add_argument(
        "--api-url",
        default=os.getenv("OPSCOUNCIL_API_URL", DEFAULT_API_URL),
        help=f"OpsCouncil API 地址，默认 {DEFAULT_API_URL}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="输出机器可读 JSON",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="检查节点、工具链和部署边界")
    doctor.add_argument(
        "--strict",
        action="store_true",
        help="存在部署阻断项时返回非零退出码",
    )

    ask = subparsers.add_parser("ask", help="向受控 Agent 发起自然语言任务")
    ask.add_argument("text", nargs="+", help="自然语言运维请求")
    ask.add_argument("--conversation", help="继续指定会话")
    ask.add_argument("--no-wait", action="store_true", help="任务入队后立即返回")
    ask.add_argument("--timeout", type=float, default=180.0, help="等待完成的秒数")
    ask.add_argument(
        "--poll-interval",
        type=float,
        default=0.5,
        help=argparse.SUPPRESS,
    )

    task = subparsers.add_parser("task", help="查看任务结论、处置建议和审计状态")
    task.add_argument("task_id", type=int)

    approvals = subparsers.add_parser("approvals", help="查看审批或人工接管队列")
    approvals.add_argument(
        "--status",
        default="PENDING_APPROVAL",
        choices=(
            "PENDING_APPROVAL",
            "NEEDS_OPERATOR",
            "EXECUTED",
            "REJECTED",
            "FAILED",
            "ROLLED_BACK",
        ),
    )
    approvals.add_argument("--limit", type=int, default=20)

    audit = subparsers.add_parser("audit", help="校验审计链并重放当前安全策略")
    audit.add_argument("trace_id")
    return parser


def run(
    args: argparse.Namespace,
    client: ApiClient,
    *,
    output: TextIO = sys.stdout,
) -> int:
    handlers = {
        "doctor": _doctor,
        "ask": _ask,
        "task": _task,
        "approvals": _approvals,
        "audit": _audit,
    }
    try:
        handler = handlers[args.command]
    except KeyError as exc:
        raise CliError(f"未知命令：{args.command}") from exc
    return handler(args, client, output)


def _doctor(args: argparse.Namespace, client: ApiClient, output: TextIO) -> int:
    health = client.get("/health")
    capabilities = client.get("/platform/capabilities")
    readiness = client.get("/deployment/readiness")
    result = {"health": health, "capabilities": capabilities, "readiness": readiness}
    if args.as_json:
        _print_json(result, output)
    else:
        platform = capabilities.get("platform", {})
        worker = health.get("worker", {})
        ai = health.get("ai", {})
        supported = sum(
            item.get("status") == "SUPPORTED"
            for item in capabilities.get("capabilities", {}).values()
        )
        total = len(capabilities.get("capabilities", {}))
        _line(output, "OpsCouncil 节点自检")
        _line(
            output,
            f"节点      {platform.get('hostname', '-')} | "
            f"{platform.get('os_release', {}).get('pretty_name', '-')} | "
            f"{platform.get('machine', '-')}",
        )
        _line(
            output,
            f"运行面    API {health.get('status', '-')} | "
            f"Worker {worker.get('online_worker_count', 0)} 在线 | "
            f"MCP {health.get('mcp', {}).get('tool_count', 0)} 项",
        )
        _line(
            output,
            f"模型      {ai.get('chat_model', '-')} | "
            f"向量 {ai.get('embedding_model', '-')}",
        )
        _line(output, f"能力画像  {supported}/{total} 可用")
        _line(
            output,
            f"部署边界  {readiness.get('overall_status', '-')} | "
            f"{readiness.get('summary', '-')}",
        )
        for check in readiness.get("checks", []):
            if check.get("status") != "ok":
                _line(
                    output,
                    f"  [{check.get('status', '-').upper()}] "
                    f"{check.get('name', '-')}：{check.get('detail', '-')}",
                )
    strict_failed = (
        health.get("status") != "ok"
        or readiness.get("overall_status") == "blocked"
    )
    return 3 if args.strict and strict_failed else 0


def _ask(args: argparse.Namespace, client: ApiClient, output: TextIO) -> int:
    text = " ".join(args.text).strip()
    if not text:
        raise CliError("自然语言请求不能为空。")
    payload: dict[str, Any] = {"input": text}
    if args.conversation:
        payload["conversation_id"] = args.conversation
    accepted = client.post("/tasks", payload)
    if args.no_wait:
        if args.as_json:
            _print_json(accepted, output)
        else:
            _line(output, f"任务 #{accepted['id']} 已入队，Trace {accepted['trace_id']}。")
        return 0

    deadline = time.monotonic() + max(args.timeout, 1.0)
    task = accepted
    last_queue_status = ""
    while time.monotonic() < deadline:
        queue_status = str(task.get("queue_status") or "")
        if not args.as_json and queue_status and queue_status != last_queue_status:
            _line(output, f"任务 #{task['id']}：{_queue_label(queue_status)}")
            last_queue_status = queue_status
        if queue_status in TERMINAL_QUEUE_STATUSES:
            break
        time.sleep(max(args.poll_interval, 0.0))
        task = client.get(f"/tasks/{task['id']}")
    else:
        raise CliError(f"任务 #{accepted['id']} 在等待期限内未完成。")

    details = _task_details(client, task)
    if args.as_json:
        _print_json(details, output)
    else:
        _print_task(details, output)
    return 0 if task.get("queue_status") == "SUCCEEDED" else 4


def _task(args: argparse.Namespace, client: ApiClient, output: TextIO) -> int:
    task = client.get(f"/tasks/{args.task_id}")
    details = _task_details(client, task)
    if args.as_json:
        _print_json(details, output)
    else:
        _print_task(details, output)
    return 0


def _approvals(args: argparse.Namespace, client: ApiClient, output: TextIO) -> int:
    rows = client.get(
        "/proposals",
        {"status_filter": args.status, "limit": max(1, min(args.limit, 200))},
    )
    if args.as_json:
        _print_json(rows, output)
        return 0
    _line(output, f"{args.status}：{len(rows)} 项")
    for row in rows:
        _line(
            output,
            f"#{row['id']} 任务 #{row['task_id']} | {row['risk_level']} | "
            f"{row['tool_name']} | {row['reason']}",
        )
    if not rows:
        _line(output, "当前队列为空。")
    return 0


def _audit(args: argparse.Namespace, client: ApiClient, output: TextIO) -> int:
    replay = client.get(f"/audit/traces/{args.trace_id}/replay")
    if args.as_json:
        _print_json(replay, output)
    else:
        _print_audit(replay, output)
    valid = bool(replay.get("integrity", {}).get("valid"))
    drifted = replay.get("policy_replay", {}).get("status") == "drifted"
    return 0 if valid and not drifted else 5


def _task_details(client: ApiClient, task: dict[str, Any]) -> dict[str, Any]:
    return {
        "task": task,
        "proposals": client.get(f"/tasks/{task['id']}/proposals"),
        "audit": client.get(f"/audit/traces/{task['trace_id']}/replay"),
    }


def _print_task(details: dict[str, Any], output: TextIO) -> None:
    task = details["task"]
    _line(
        output,
        f"任务 #{task['id']} | {task.get('status', '-')} | "
        f"{task.get('risk_level', '-')} | Trace {task.get('trace_id', '-')}",
    )
    _line(output, f"结论      {task.get('summary') or '尚未形成结论'}")
    proposals = details["proposals"]
    if proposals:
        for proposal in proposals:
            _line(
                output,
                f"处置建议  #{proposal['id']} {proposal['tool_name']} | "
                f"{proposal['status']} | {proposal['reason']}",
            )
    else:
        _line(output, "处置建议  无")
    _print_audit(details["audit"], output)


def _print_audit(replay: dict[str, Any], output: TextIO) -> None:
    integrity = replay.get("integrity", {})
    policy = replay.get("policy_replay", {})
    _line(
        output,
        f"审计链    {'可信' if integrity.get('valid') else '异常'} | "
        f"{integrity.get('entry_count', 0)} 项 | "
        f"{_short_hash(str(integrity.get('head_hash') or ''))}",
    )
    _line(
        output,
        f"策略复核  {_policy_label(str(policy.get('status') or ''))} | "
        f"复核 {policy.get('evaluated_count', 0)} 项 | "
        f"变化 {policy.get('changed_count', 0)} 项",
    )


def _queue_label(status: str) -> str:
    return {
        "QUEUED": "已入队",
        "RUNNING": "正在调查",
        "SUCCEEDED": "已完成",
        "FAILED": "处理失败",
        "CANCELLED": "已取消",
    }.get(status, status)


def _policy_label(status: str) -> str:
    return {
        "consistent": "当前策略一致",
        "drifted": "发现策略变化",
        "partial": "部分可复核",
        "unavailable": "暂无可复核裁决",
    }.get(status, status or "-")


def _short_hash(value: str) -> str:
    if len(value) <= 16:
        return value or "-"
    return f"{value[:8]}...{value[-6:]}"


def _error_detail(body: bytes) -> str:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body.decode("utf-8", errors="replace")[:300] or "请求失败"
    return str(payload.get("detail") or payload)[:300]


def _print_json(value: Any, output: TextIO) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2), file=output)


def _line(output: TextIO, value: str) -> None:
    print(value, file=output)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args, ApiClient(args.api_url))
    except CliError as exc:
        print(f"opscouncilctl：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
