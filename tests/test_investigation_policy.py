from __future__ import annotations

import unittest
from types import SimpleNamespace

from backend.app.core.pydantic_compat import BaseModel, Field
from backend.app.investigation.policy import (
    InvestigationBudget,
    InvestigationPolicy,
    InvestigationPolicyError,
    tool_call_signature,
)
from backend.app.investigation.schemas import InvestigationToolRequest
from backend.app.mcp.registry import ToolRegistry
from backend.app.mcp.types import ToolDefinition, ToolResult
from backend.app.schemas.enums import RiskLevel


class LimitInput(BaseModel):
    limit: int = Field(default=5, ge=1, le=20)


class UnitInput(BaseModel):
    unit: str | None = None


class JournalInput(BaseModel):
    unit: str | None = None
    lines: int = Field(default=80, ge=1, le=500)


class PidInput(BaseModel):
    pid: int = Field(ge=1)


class SocketInput(BaseModel):
    protocol: str
    port: int = Field(ge=1, le=65535)


class FocusPortsInput(BaseModel):
    focus_ports: list[int] = Field(default_factory=list)


class PathInput(BaseModel):
    path: str


class UrlInput(BaseModel):
    url: str


class PathsInput(BaseModel):
    paths: list[str]


class FindLargeFilesInput(BaseModel):
    roots: list[str] = Field(default_factory=lambda: ["/var/log", "/tmp"])
    limit: int = Field(default=20, ge=1, le=100)
    min_size_mb: int = Field(default=10, ge=1, le=10240)


def noop_tool(_: BaseModel) -> ToolResult:
    return ToolResult()


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name="process_list",
            version="1.0.0",
            description="读取进程列表",
            risk_level=RiskLevel.R0,
            input_model=LimitInput,
            output_model=ToolResult,
            handler=noop_tool,
        )
    )
    registry.register(
        ToolDefinition(
            name="service_status",
            version="1.0.0",
            description="读取服务状态",
            risk_level=RiskLevel.R1,
            input_model=UnitInput,
            output_model=ToolResult,
            handler=noop_tool,
        )
    )
    registry.register(
        ToolDefinition(
            name="safe_log_rotate",
            version="1.0.0",
            description="轮转日志",
            risk_level=RiskLevel.R2,
            input_model=LimitInput,
            output_model=ToolResult,
            handler=noop_tool,
        )
    )
    for name, input_model in (
        ("journal_query", JournalInput),
        ("process_runtime_detail", PidInput),
        ("socket_process_context", SocketInput),
        ("service_dependency_snapshot", FocusPortsInput),
        ("filesystem_mount_context", PathInput),
        ("application_log_query", PathInput),
        ("service_health_probe", UrlInput),
        ("config_integrity_scan", PathsInput),
        ("find_large_files", FindLargeFilesInput),
    ):
        registry.register(
            ToolDefinition(
                name=name,
                version="1.0.0",
                description="定向只读证据",
                risk_level=RiskLevel.R0,
                input_model=input_model,
                output_model=ToolResult,
                handler=noop_tool,
            )
        )
    return registry


def request(tool_name: str = "process_list", arguments: dict | None = None) -> InvestigationToolRequest:
    return InvestigationToolRequest(
        tool_name=tool_name,
        arguments=arguments if arguments is not None else {},
        reason="补充判别性证据",
    )


class InvestigationPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = build_registry()
        self.policy = InvestigationPolicy(self.registry)
        self.budget = InvestigationBudget(max_iterations=4, max_tool_calls=12, max_elapsed_ms=120000)

    def validate(
        self,
        tool_request: InvestigationToolRequest,
        *,
        allowed_tools: set[str] | None = None,
        signatures: set[str] | None = None,
        total_tool_calls: int = 2,
        elapsed_ms: int = 1000,
        iteration: int = 1,
        evidence_items: list | None = None,
        user_input: str = "",
    ):
        return self.policy.validate_tool_request(
            tool_request,
            allowed_tools=allowed_tools
            or {
                "process_list",
                "service_status",
                "journal_query",
                "safe_log_rotate",
                "process_runtime_detail",
                "socket_process_context",
                "service_dependency_snapshot",
                "filesystem_mount_context",
                "application_log_query",
                "service_health_probe",
                "config_integrity_scan",
                "find_large_files",
            },
            existing_signatures=signatures or set(),
            total_tool_calls=total_tool_calls,
            elapsed_ms=elapsed_ms,
            iteration=iteration,
            budget=self.budget,
            evidence_items=evidence_items or [],
            user_input=user_input,
        )

    def test_valid_request_returns_normalized_arguments_and_signature(self) -> None:
        validated = self.validate(request(arguments={}))

        self.assertEqual(validated.tool_name, "process_list")
        self.assertEqual(validated.arguments, {"limit": 5})
        self.assertEqual(
            validated.signature,
            tool_call_signature("process_list", {"limit": 5}),
        )

    def test_large_file_scan_uses_sensitive_default_without_explicit_threshold(self) -> None:
        validated = self.validate(
            request(
                "find_large_files",
                {"roots": ["/var/log", "/tmp"], "limit": 20, "min_size_mb": 100},
            ),
            user_input="分析磁盘空间，定位异常大日志并判断能否安全处置",
        )

        self.assertEqual(validated.arguments["min_size_mb"], 10)

    def test_large_file_scan_respects_an_explicit_user_threshold(self) -> None:
        validated = self.validate(
            request(
                "find_large_files",
                {"roots": ["/var/log"], "limit": 20, "min_size_mb": 10},
            ),
            user_input="只定位超过 0.5 GiB 的日志文件",
        )

        self.assertEqual(validated.arguments["min_size_mb"], 512)

    def test_generic_large_file_scan_keeps_both_operational_roots(self) -> None:
        validated = self.validate(
            request(
                "find_large_files",
                {"roots": ["/var/log"], "limit": 20, "min_size_mb": 100},
            ),
            user_input="分析磁盘空间，定位异常大日志并判断能否安全处置",
        )

        self.assertEqual(validated.arguments["roots"], ["/var/log", "/tmp"])

    def test_explicit_scan_path_is_preserved_without_adding_unrelated_defaults(self) -> None:
        validated = self.validate(
            request(
                "find_large_files",
                {"roots": ["/var/log"], "limit": 20, "min_size_mb": 10},
            ),
            user_input="检查 /var/log 下的大文件",
        )

        self.assertEqual(validated.arguments["roots"], ["/var/log"])

    def test_root_scan_is_rejected_by_investigation_policy(self) -> None:
        with self.assertRaisesRegex(InvestigationPolicyError, "outside allowed") as caught:
            self.validate(
                request(
                    "find_large_files",
                    {"roots": ["/"], "limit": 20, "min_size_mb": 10},
                ),
                user_input="分析磁盘空间",
            )

        self.assertEqual(caught.exception.code, "INVALID_SCAN_SCOPE")

    def test_tool_outside_selected_skill_is_rejected(self) -> None:
        with self.assertRaisesRegex(InvestigationPolicyError, "selected skill") as caught:
            self.validate(request("service_status"), allowed_tools={"process_list"})

        self.assertEqual(caught.exception.code, "TOOL_OUTSIDE_SKILL")

    def test_side_effect_tool_is_rejected_even_when_skill_lists_it(self) -> None:
        with self.assertRaisesRegex(InvestigationPolicyError, "read-only") as caught:
            self.validate(request("safe_log_rotate"))

        self.assertEqual(caught.exception.code, "SIDE_EFFECT_TOOL")

    def test_invalid_tool_arguments_are_rejected(self) -> None:
        with self.assertRaisesRegex(InvestigationPolicyError, "schema") as caught:
            self.validate(request(arguments={"limit": 999}))

        self.assertEqual(caught.exception.code, "INVALID_ARGUMENTS")

    def test_duplicate_normalized_tool_call_is_rejected(self) -> None:
        signature = tool_call_signature("process_list", {"limit": 5})

        with self.assertRaisesRegex(InvestigationPolicyError, "duplicate") as caught:
            self.validate(request(arguments={}), signatures={signature})

        self.assertEqual(caught.exception.code, "DUPLICATE_TOOL_CALL")

    def test_total_tool_call_budget_is_enforced(self) -> None:
        with self.assertRaisesRegex(InvestigationPolicyError, "tool-call budget") as caught:
            self.validate(request(), total_tool_calls=12)

        self.assertEqual(caught.exception.code, "TOOL_CALL_BUDGET_EXHAUSTED")

    def test_elapsed_time_budget_is_enforced(self) -> None:
        with self.assertRaisesRegex(InvestigationPolicyError, "elapsed-time budget") as caught:
            self.validate(request(), elapsed_ms=120000)

        self.assertEqual(caught.exception.code, "ELAPSED_BUDGET_EXHAUSTED")

    def test_model_iteration_budget_is_enforced(self) -> None:
        with self.assertRaisesRegex(InvestigationPolicyError, "iteration budget") as caught:
            self.validate(request(), iteration=5)

        self.assertEqual(caught.exception.code, "ITERATION_BUDGET_EXHAUSTED")

    def test_service_unit_must_come_from_existing_evidence(self) -> None:
        evidence = [
            SimpleNamespace(
                payload_json={
                    "pid": 42,
                    "process_name": "uvicorn",
                    "systemd_unit": None,
                }
            )
        ]

        with self.assertRaisesRegex(InvestigationPolicyError, "outside user and evidence") as caught:
            self.validate(
                request("service_status", {"unit": "uvicorn"}),
                evidence_items=evidence,
                user_input="确认 systemd 服务归属",
            )

        self.assertEqual(caught.exception.code, "ARGUMENT_OUTSIDE_EVIDENCE")

    def test_observed_service_unit_is_allowed(self) -> None:
        validated = self.validate(
            request("service_status", {"unit": "gateway"}),
            evidence_items=[
                SimpleNamespace(payload_json={"systemd_unit": "gateway.service"})
            ],
        )

        self.assertEqual(validated.arguments, {"unit": "gateway"})

    def test_process_pid_must_be_observed_or_explicitly_requested(self) -> None:
        evidence = [SimpleNamespace(payload_json={"pid": 390})]

        validated = self.validate(
            request("process_runtime_detail", {"pid": 390}),
            evidence_items=evidence,
        )
        self.assertEqual(validated.arguments["pid"], 390)
        with self.assertRaises(InvestigationPolicyError) as caught:
            self.validate(
                request("process_runtime_detail", {"pid": 999}),
                evidence_items=evidence,
            )
        self.assertEqual(caught.exception.code, "ARGUMENT_OUTSIDE_EVIDENCE")

    def test_socket_target_must_match_user_or_listener_scope(self) -> None:
        validated = self.validate(
            request("socket_process_context", {"protocol": "tcp", "port": 8000}),
            user_input="核对 TCP/8000 端口",
        )
        self.assertEqual(validated.arguments["port"], 8000)
        with self.assertRaises(InvestigationPolicyError) as caught:
            self.validate(
                request("socket_process_context", {"protocol": "udp", "port": 53}),
                user_input="核对 TCP/8000 端口",
            )
        self.assertEqual(caught.exception.code, "ARGUMENT_OUTSIDE_EVIDENCE")

    def test_relationship_snapshot_ports_must_match_user_or_evidence_scope(self) -> None:
        validated = self.validate(
            request("service_dependency_snapshot", {"focus_ports": [8000]}),
            user_input="核对 TCP/8000 的服务连接关系",
        )

        self.assertEqual(validated.arguments["focus_ports"], [8000])
        with self.assertRaises(InvestigationPolicyError) as caught:
            self.validate(
                request("service_dependency_snapshot", {"focus_ports": [5432]}),
                user_input="核对 TCP/8000 的服务连接关系",
            )
        self.assertEqual(caught.exception.code, "ARGUMENT_OUTSIDE_EVIDENCE")

    def test_mount_path_must_be_related_to_observed_or_user_path(self) -> None:
        evidence = [SimpleNamespace(payload_json={"path": "/var/log/app.log"})]

        validated = self.validate(
            request("filesystem_mount_context", {"path": "/var/log"}),
            evidence_items=evidence,
        )
        self.assertEqual(validated.arguments["path"], "/var/log")
        with self.assertRaises(InvestigationPolicyError) as caught:
            self.validate(
                request("filesystem_mount_context", {"path": "/etc/shadow"}),
                evidence_items=evidence,
            )
        self.assertEqual(caught.exception.code, "ARGUMENT_OUTSIDE_EVIDENCE")

    def test_service_health_url_must_be_explicit_or_observed(self) -> None:
        url = "http://127.0.0.1:18080/health"
        validated = self.validate(
            request("service_health_probe", {"url": url}),
            user_input=f"调查 {url} 返回 503 的原因",
        )

        self.assertEqual(validated.arguments["url"], url)
        with self.assertRaises(InvestigationPolicyError) as caught:
            self.validate(
                request("service_health_probe", {"url": "http://127.0.0.1:19090/health"}),
                user_input=f"调查 {url} 返回 503 的原因",
            )
        self.assertEqual(caught.exception.code, "ARGUMENT_OUTSIDE_EVIDENCE")

    def test_application_log_and_config_paths_are_bound_to_structured_evidence(self) -> None:
        evidence = [
            SimpleNamespace(
                payload_json={
                    "body_summary": {"log_path": "/tmp/opscouncil-lab/case/app.jsonl"},
                    "records": [{"path": "/tmp/opscouncil-lab/case/app.conf"}],
                }
            )
        ]

        log_request = self.validate(
            request(
                "application_log_query",
                {"path": "/tmp/opscouncil-lab/case/app.jsonl"},
            ),
            evidence_items=evidence,
        )
        config_request = self.validate(
            request(
                "config_integrity_scan",
                {"paths": ["/tmp/opscouncil-lab/case/app.conf"]},
            ),
            evidence_items=evidence,
        )

        self.assertEqual(log_request.arguments["path"], "/tmp/opscouncil-lab/case/app.jsonl")
        self.assertEqual(config_request.arguments["paths"], ["/tmp/opscouncil-lab/case/app.conf"])
        with self.assertRaises(InvestigationPolicyError) as caught:
            self.validate(
                request(
                    "application_log_query",
                    {"path": "/tmp/opscouncil-lab/case/unobserved.jsonl"},
                ),
                evidence_items=evidence,
            )
        self.assertEqual(caught.exception.code, "ARGUMENT_OUTSIDE_EVIDENCE")

    def test_allowed_argument_values_are_derived_from_user_and_evidence(self) -> None:
        values = self.policy.allowed_argument_values(
            evidence_items=[
                SimpleNamespace(
                    payload_json={
                        "pid": 42,
                        "protocol": "tcp",
                        "local_address": "127.0.0.1:8000",
                        "systemd_unit": "gateway.service",
                        "path": "/var/log/app.log",
                    }
                )
            ],
            user_input="继续核对 PID 43 和 /var/log",
        )

        self.assertEqual(values["process_runtime_detail.pid"], [42, 43])
        self.assertEqual(values["socket_process_context.port"], [8000])
        self.assertEqual(values["socket_process_context.protocol"], ["tcp"])
        self.assertEqual(values["service_dependency_snapshot.focus_ports"], [8000])
        self.assertEqual(values["service_status.unit"], ["gateway.service"])
        self.assertEqual(values["journal_query.unit"], ["gateway.service"])
        self.assertIn("/var/log", values["filesystem_mount_context.path"])

    def test_journal_query_is_limited_to_an_observed_service_unit(self) -> None:
        evidence = [
            SimpleNamespace(
                payload_json={"unit": "gateway.service", "active": "failed"}
            )
        ]

        validated = self.validate(
            request("journal_query", {"unit": "gateway.service", "lines": 80}),
            evidence_items=evidence,
        )

        self.assertEqual(validated.arguments["unit"], "gateway.service")
        with self.assertRaises(InvestigationPolicyError) as caught:
            self.validate(
                request("journal_query", {"unit": "unobserved.service", "lines": 80}),
                evidence_items=evidence,
            )
        self.assertEqual(caught.exception.code, "ARGUMENT_OUTSIDE_EVIDENCE")

    def test_opentelemetry_endpoint_fields_extend_only_read_only_scope(self) -> None:
        values = self.policy.allowed_argument_values(
            evidence_items=[
                SimpleNamespace(
                    payload_json={
                        "records": [
                            {
                                "event": "request_failed",
                                "server.address": "127.0.0.1",
                                "server.port": 18091,
                                "network.transport": "tcp",
                            }
                        ]
                    }
                )
            ],
            user_input="排查服务依赖超时",
        )

        self.assertEqual(values["socket_process_context.port"], [18091])
        self.assertEqual(values["socket_process_context.protocol"], ["tcp"])
        self.assertEqual(
            values["service_dependency_snapshot.focus_ports"],
            [18091],
        )

    def test_targeted_socket_context_limits_units_to_that_port(self) -> None:
        values = self.policy.allowed_argument_values(
            evidence_items=[
                SimpleNamespace(
                    source_key="network_listeners",
                    payload_json={"systemd_unit": "redis-server.service"},
                ),
                SimpleNamespace(
                    source_key="socket_process_context",
                    payload_json={
                        "protocol": "tcp",
                        "port": 8000,
                        "listeners": [{"pid": 42, "systemd_unit": None}],
                    },
                ),
            ],
            user_input="核对 TCP/8000 的服务归属",
        )

        self.assertEqual(values["service_status.unit"], [])


if __name__ == "__main__":
    unittest.main()
