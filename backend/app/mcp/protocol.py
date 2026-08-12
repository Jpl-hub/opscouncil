from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from backend.app.mcp.registry import (
    ScopedToolRegistry,
    ToolCapabilityUnavailableError,
    ToolIntegrityError,
    ToolNotFoundError,
    ToolRegistry,
    ToolValidationError,
)
from backend.app.mcp.types import ToolDefinition, ToolResult, schema_hash
from backend.app.schemas.enums import RiskLevel
from backend.app.collaboration.auth import (
    CollaborationIdentityConfigurationError,
    callback_token_matches,
)


MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = {MCP_PROTOCOL_VERSION}

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603
JSONRPC_SERVER_ERROR = -32000

LOCAL_ORIGIN_HOSTS = {"localhost", "127.0.0.1", "::1"}
READONLY_RISKS = {RiskLevel.R0.value, RiskLevel.R1.value}

TOOL_TITLES = {
    "platform_capability_profile": "主机能力画像",
    "system_snapshot": "系统快照",
    "disk_usage": "磁盘用量",
    "process_list": "进程清单",
    "journal_query": "日志查询",
    "network_listeners": "监听端口",
    "service_dependency_snapshot": "服务关系快照",
    "process_file_handles": "文件句柄",
    "service_status": "服务状态",
    "find_large_files": "大文件扫描",
    "config_integrity_scan": "配置完整性",
    "config_baseline_check": "配置基线比较",
    "safe_log_rotate": "安全日志轮转",
    "restore_log_backup": "日志备份恢复",
    "restart_managed_service": "受控服务重启",
    "restore_config_mode": "配置权限恢复",
    "file_integrity_state": "文件完整性校验",
    "process_runtime_detail": "进程运行详情",
    "journal_storage_status": "日志存储状态",
    "deleted_open_files": "已删除未释放文件",
    "socket_process_context": "端口进程归属",
    "filesystem_mount_context": "文件系统挂载",
    "time_sync_status": "时间同步状态",
    "service_health_probe": "服务健康检查",
    "application_log_query": "应用日志",
    "service_catalog_snapshot": "服务目录快照",
}


RegistryLike = ToolRegistry | ScopedToolRegistry


def build_mcp_router(
    registry: RegistryLike,
    *,
    path: str = "/mcp",
    server_name: str = "opscouncil-agent",
    server_title: str = "OpsCouncil Operations Agent",
    identity_subject: str | None = None,
) -> APIRouter:
    router = APIRouter()

    route_name = server_name.replace("-", "_")

    @router.get(path, include_in_schema=False, name=f"{route_name}_mcp_get")
    async def mcp_get_not_supported() -> JSONResponse:
        return JSONResponse(
            _jsonrpc_error(None, JSONRPC_SERVER_ERROR, "MCP Streamable HTTP endpoint accepts POST requests"),
            status_code=405,
            headers={"Allow": "POST"},
        )

    @router.post(path, include_in_schema=True, name=f"{route_name}_mcp_post")
    async def mcp_endpoint(request: Request) -> Response:
        if not _origin_allowed(request.headers.get("origin")):
            return JSONResponse(
                _jsonrpc_error(
                    None,
                    JSONRPC_SERVER_ERROR,
                    "Forbidden origin for local MCP endpoint",
                ),
                status_code=403,
            )

        if identity_subject is not None:
            try:
                identity_valid = callback_token_matches(
                    identity_subject,
                    request.headers.get("x-opscouncil-agent-token"),
                )
            except CollaborationIdentityConfigurationError as exc:
                return JSONResponse(
                    _jsonrpc_error(None, JSONRPC_SERVER_ERROR, str(exc)),
                    status_code=503,
                )
            if not identity_valid:
                return JSONResponse(
                    _jsonrpc_error(None, JSONRPC_SERVER_ERROR, "Invalid MCP role identity"),
                    status_code=401,
                )

        try:
            message = await request.json()
        except json.JSONDecodeError:
            return JSONResponse(_jsonrpc_error(None, JSONRPC_PARSE_ERROR, "Parse error"))

        if not isinstance(message, dict) or isinstance(message, list):
            return JSONResponse(
                _jsonrpc_error(None, JSONRPC_INVALID_REQUEST, "MCP endpoint accepts one JSON-RPC message")
            )

        protocol_response = _validate_http_protocol_version(message, request.headers.get("mcp-protocol-version"))
        if protocol_response is not None:
            return protocol_response

        result = handle_jsonrpc_message(
            registry,
            message,
            server_name=server_name,
            server_title=server_title,
        )
        if result is None:
            return Response(status_code=202)
        return JSONResponse(result)

    return router


def handle_jsonrpc_message(
    registry: RegistryLike,
    message: dict[str, Any],
    *,
    server_name: str = "opscouncil-agent",
    server_title: str = "OpsCouncil Operations Agent",
) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")

    if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
        return _jsonrpc_error(request_id, JSONRPC_INVALID_REQUEST, "Invalid JSON-RPC request")

    if request_id is None:
        _handle_notification(method)
        return None

    if method == "initialize":
        return _jsonrpc_result(
            request_id,
            _initialize_result(
                message.get("params") or {},
                server_name=server_name,
                server_title=server_title,
            ),
        )
    if method == "ping":
        return _jsonrpc_result(request_id, {})
    if method == "tools/list":
        return _jsonrpc_result(request_id, _list_tools(registry))
    if method == "tools/call":
        return _handle_tool_call(registry, request_id, message.get("params"))

    return _jsonrpc_error(request_id, JSONRPC_METHOD_NOT_FOUND, f"Method not found: {method}")


def _handle_notification(method: str) -> None:
    if method in {"notifications/initialized", "notifications/cancelled"}:
        return
    return


def _initialize_result(
    params: dict[str, Any],
    *,
    server_name: str,
    server_title: str,
) -> dict[str, Any]:
    requested_version = params.get("protocolVersion")
    protocol_version = requested_version if requested_version in SUPPORTED_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSION
    return {
        "protocolVersion": protocol_version,
        "capabilities": {
            "tools": {"listChanged": True},
        },
        "serverInfo": {
            "name": server_name,
            "title": server_title,
            "version": "0.1.0",
            "description": "MCP server for evidence-bearing Linux perception and approval-gated operations.",
        },
        "instructions": "Read-only perception tools may be called directly. Side-effect tools require dry_run=true through MCP and must be executed through the audited approval workflow.",
    }


def _list_tools(registry: RegistryLike) -> dict[str, Any]:
    return {
        "tools": [
            _tool_to_mcp(
                registry.get(item["name"]),
                availability=item.get("availability"),
                integrity=item.get("integrity"),
            )
            for item in registry.list_tools()
        ]
    }


def _handle_tool_call(
    registry: RegistryLike,
    request_id: str | int,
    params: Any,
) -> dict[str, Any]:
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        return _jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, "tools/call requires params.name")

    name = params["name"]
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return _jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, "tools/call params.arguments must be an object")

    try:
        tool = registry.get(name)
    except ToolNotFoundError:
        return _jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, f"Unknown tool: {name}")

    if _requires_approval(tool, arguments):
        return _jsonrpc_result(
            request_id,
            _tool_error_result(
                f"Tool {name} requires approval for non-dry-run execution; call with dry_run=true or use the audited approval workflow."
            ),
        )

    try:
        result = registry.call(name, arguments)
    except ToolCapabilityUnavailableError as exc:
        return _jsonrpc_result(
            request_id,
            _tool_error_result(
                str(exc),
                status="unavailable",
                details={
                    "requirements": exc.requirements,
                    "reasons": exc.reasons,
                },
            ),
        )
    except ToolIntegrityError as exc:
        return _jsonrpc_result(
            request_id,
            _tool_error_result(str(exc), status="integrity_error"),
        )
    except ToolValidationError as exc:
        return _jsonrpc_result(request_id, _tool_error_result(str(exc)))
    except ValueError as exc:
        return _jsonrpc_result(request_id, _tool_error_result(str(exc)))
    except Exception as exc:
        return _jsonrpc_error(request_id, JSONRPC_INTERNAL_ERROR, "Tool execution failed", {"detail": str(exc)})

    return _jsonrpc_result(request_id, _tool_success_result(result))


def _tool_to_mcp(
    tool: ToolDefinition,
    *,
    availability: dict[str, Any] | None = None,
    integrity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    read_only = tool.risk_level.value in READONLY_RISKS
    input_schema = tool.input_model.model_json_schema()
    output_schema = tool.output_model.model_json_schema()
    return {
        "name": tool.name,
        "title": TOOL_TITLES.get(tool.name, tool.name),
        "description": tool.description,
        "inputSchema": input_schema,
        "outputSchema": output_schema,
        "annotations": {
            "title": TOOL_TITLES.get(tool.name, tool.name),
            "readOnlyHint": read_only,
            "destructiveHint": not read_only,
            "idempotentHint": read_only,
            "openWorldHint": False,
        },
        "execution": {"taskSupport": "forbidden"},
        "_meta": {
            "version": tool.version,
            "riskLevel": tool.risk_level.value,
            "dryRunSupported": tool.dry_run_supported,
            "rollbackStrategy": tool.rollback_strategy,
            "capabilityRequirements": list(tool.capability_requirements),
            "availability": availability
            or {
                "status": "UNKNOWN",
                "available": True,
                "required_capabilities": list(tool.capability_requirements),
                "reasons": [],
            },
            "integrity": integrity or {"status": "UNKNOWN"},
            "approval": "required_for_execution" if not read_only else "not_required",
            "inputSchemaHash": schema_hash(input_schema),
            "outputSchemaHash": schema_hash(output_schema),
        },
    }


def _tool_success_result(result: ToolResult) -> dict[str, Any]:
    structured = result.model_dump(mode="json")
    return {
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=False, sort_keys=True)}],
        "structuredContent": structured,
        "isError": False,
    }


def _tool_error_result(
    message: str,
    *,
    status: str = "error",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": message}],
        "structuredContent": {
            "status": status,
            "message": message,
            **(details or {}),
        },
        "isError": True,
    }


def _requires_approval(tool: ToolDefinition, arguments: dict[str, Any]) -> bool:
    if tool.risk_level.value in READONLY_RISKS:
        return False
    if not tool.dry_run_supported:
        return True
    return arguments.get("dry_run", True) is not True


def _origin_allowed(origin: str | None) -> bool:
    if not origin:
        return True
    parsed = urlparse(origin)
    return parsed.hostname in LOCAL_ORIGIN_HOSTS


def _validate_http_protocol_version(message: dict[str, Any], header_version: str | None) -> JSONResponse | None:
    if message.get("method") == "initialize" or not header_version:
        return None
    if header_version not in SUPPORTED_PROTOCOL_VERSIONS:
        return JSONResponse(
            _jsonrpc_error(
                message.get("id"),
                JSONRPC_INVALID_PARAMS,
                "Unsupported MCP protocol version",
                {"supported": sorted(SUPPORTED_PROTOCOL_VERSIONS), "requested": header_version},
            ),
            status_code=400,
        )
    return None


def _jsonrpc_result(request_id: str | int, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(
    request_id: str | int | None,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}
