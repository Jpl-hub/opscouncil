from __future__ import annotations

from types import SimpleNamespace

from backend.app.investigation.evidence import bound_investigation_decision_claims
from backend.app.investigation.schemas import InvestigationDecision


def failed_service_evidence() -> SimpleNamespace:
    return SimpleNamespace(
        id=9,
        source_type="MCP",
        source_key="service_status",
        trust_level="SYSTEM_OBSERVATION",
        payload_json={
            "unit": "demo-lab.service",
            "active_state": "failed",
            "result": "exit-code",
            "exec_start_path": "/usr/bin/false",
            "exec_main_status": 1,
        },
    )


def intentional_failure_decision() -> InvestigationDecision:
    return InvestigationDecision.model_validate(
        {
            "decision": "CONCLUDE",
            "hypotheses": [
                {
                    "key": "intentional_failure",
                    "title": "测试服务按预期启动失败",
                    "rationale": "单元名称含 lab，因此属于人为构造的测试用例。",
                    "evidence_gap": "无缺口。",
                }
            ],
            "evidence_links": [
                {
                    "hypothesis_key": "intentional_failure",
                    "evidence_id": 9,
                    "relation": "SUPPORTS",
                    "rationale": "fixture 名称证明失败符合预期。",
                }
            ],
            "next_tool": None,
            "conclusion": {
                "conclusion": "该测试服务失败符合预期。",
                "root_cause": "人为构造的失败测试用例。",
                "risk_level": "R1",
                "reasoning_summary": ["单元名称与退出码一致。"],
                "counter_evidence": [],
                "recommended_actions": [
                    {
                        "title": "无需处理",
                        "rationale": "无需修复或重启。",
                        "safety_gate": "保持现状。",
                        "tool_name": None,
                    }
                ],
                "evidence_used": [],
                "residual_risk": "不构成系统稳定性或安全风险。",
            },
            "stop_reason": "fixture 命名证明该失败是预期行为。",
        }
    )


def test_unit_label_cannot_prove_desired_service_state() -> None:
    bounded = bound_investigation_decision_claims(
        intentional_failure_decision(),
        [failed_service_evidence()],
    )

    hypothesis = bounded.hypotheses[0]
    assert "预期运行状态待确认" in hypothesis.title
    assert "不能仅凭单元名称" in hypothesis.evidence_gap
    assert "不证明该失败符合预期" in hypothesis.rationale
    assert bounded.conclusion is not None
    assert "尚未确认" in bounded.conclusion.conclusion
    assert "确认服务期望状态" == bounded.conclusion.recommended_actions[0].title
    assert "期望状态仍需" in bounded.stop_reason
    assert "不证明该状态符合资产期望" in bounded.evidence_links[0].rationale


def approved_desired_state(unit: str = "demo-lab.service") -> SimpleNamespace:
    return SimpleNamespace(
        id=10,
        source_type="MCP",
        source_key="service_desired_state",
        trust_level="SYSTEM_OBSERVATION",
        payload_json={
            "unit": unit,
            "expected_active_state": "inactive",
            "service_owner": "platform",
            "criticality": "LOW",
            "environment": "TEST",
            "source_ref": "CMDB-TEST-1",
            "approved_by": "ops-admin",
            "version": 2,
            "record_status": "ACTIVE",
        },
    )


def approved_service_catalog() -> SimpleNamespace:
    return SimpleNamespace(
        id=20,
        source_type="MCP",
        source_key="service_catalog_snapshot",
        trust_level="SYSTEM_OBSERVATION",
        payload_json={
            "unit_name": "checkout-api.service",
            "service_owner": "交易平台组",
            "listener_expectations": [
                {
                    "protocol": "tcp",
                    "port": 8443,
                    "allowed_scope": "private",
                    "required": True,
                }
            ],
        },
    )


def catalog_decision(*, catalog_claim: bool) -> InvestigationDecision:
    title = (
        "TCP/8443 已纳入经审批服务目录"
        if catalog_claim
        else "TCP/8443 当前正在监听"
    )
    rationale = (
        "服务目录登记该端口属于 checkout-api.service。"
        if catalog_claim
        else "目录记录证明进程当前正在监听。"
    )
    return InvestigationDecision.model_validate(
        {
            "decision": "COLLECT",
            "hypotheses": [
                {
                    "key": "listener_catalog_state",
                    "title": title,
                    "rationale": rationale,
                    "evidence_gap": "仍需现场端口观测。",
                }
            ],
            "evidence_links": [
                {
                    "hypothesis_key": "listener_catalog_state",
                    "evidence_id": 20,
                    "relation": "SUPPORTS",
                    "rationale": rationale,
                }
            ],
            "next_tool": {
                "tool_name": "network_listeners",
                "arguments": {"limit": 80},
                "reason": "补充实时监听证据。",
            },
            "conclusion": None,
            "stop_reason": "继续核对现场状态。",
        }
    )


def test_catalog_cannot_support_a_live_listener_claim() -> None:
    bounded = bound_investigation_decision_claims(
        catalog_decision(catalog_claim=False),
        [approved_service_catalog()],
    )

    assert bounded.evidence_links[0].relation == "CONTEXT"
    assert "不证明实时监听状态" in bounded.evidence_links[0].rationale


def test_catalog_can_support_an_explicit_approval_scope_claim() -> None:
    bounded = bound_investigation_decision_claims(
        catalog_decision(catalog_claim=True),
        [approved_service_catalog()],
    )

    assert bounded.evidence_links[0].relation == "SUPPORTS"
    assert "允许监听范围" in bounded.evidence_links[0].rationale


def test_authoritative_desired_state_still_does_not_make_failed_equal_inactive() -> None:
    decision = intentional_failure_decision()
    decision = decision.model_copy(
        update={
            "evidence_links": [
                *decision.evidence_links,
                decision.evidence_links[0].model_copy(
                    update={
                        "evidence_id": 10,
                        "rationale": "TEST 环境证明该失败符合设计意图。",
                    }
                ),
            ]
        }
    )

    bounded = bound_investigation_decision_claims(
        decision,
        [failed_service_evidence(), approved_desired_state()],
    )

    assert bounded != decision
    assert bounded.conclusion is not None
    assert "期望状态为 inactive" in bounded.conclusion.conclusion
    assert bounded.conclusion.recommended_actions[0].title == "联系责任方清理失败状态"
    assert "经审批期望状态均已取得" in bounded.stop_reason
    assert "当前 failed 与停止态不相等" in bounded.evidence_links[1].rationale


def test_service_evidence_rationales_are_controller_bounded_even_when_worded_indirectly() -> None:
    decision = intentional_failure_decision().model_copy(
        update={
            "evidence_links": [
                intentional_failure_decision().evidence_links[0].model_copy(
                    update={"rationale": "当前状态与 lab-fixture 设计目标一致。"}
                )
            ]
        }
    )

    bounded = bound_investigation_decision_claims(
        decision,
        [failed_service_evidence()],
    )

    assert bounded.evidence_links[0].rationale.startswith("systemd 状态证据支持")
    assert "设计目标" not in bounded.evidence_links[0].rationale


def test_desired_state_for_another_unit_cannot_authorize_the_failed_unit() -> None:
    decision = intentional_failure_decision()
    decision = decision.model_copy(
        update={
            "evidence_links": [
                *decision.evidence_links,
                decision.evidence_links[0].model_copy(
                    update={
                        "evidence_id": 10,
                        "rationale": "另一服务的目录记录可以证明当前服务符合预期。",
                    }
                ),
            ]
        }
    )
    bounded = bound_investigation_decision_claims(
        decision,
        [failed_service_evidence(), approved_desired_state("another.service")],
    )

    assert bounded.conclusion is not None
    assert "尚未确认" in bounded.conclusion.conclusion
    assert bounded.conclusion.recommended_actions[0].title == "确认服务期望状态"
    assert "其他服务单元" in bounded.evidence_links[1].rationale
