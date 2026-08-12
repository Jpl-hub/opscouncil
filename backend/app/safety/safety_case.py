from __future__ import annotations

from copy import deepcopy
import socket
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.assets.service import ServiceExpectationService
from backend.app.audit.service import stable_hash
from backend.app.executor.verification import verification_tool_name
from backend.app.models.entities import (
    ActionProposal,
    ActionSafetyCase,
    ToolCall,
    utcnow,
)
from backend.app.safety.action_contract import (
    ActionContractIntegrityError,
    action_contract_digest,
    assert_bound_action_matches,
    build_bound_action,
    copy_bound_action,
)


POLICY_VERSION = "action-safety-case-v1"
SUPPORTED_ACTIONS = frozenset(
    {
        "safe_log_rotate",
        "restore_log_backup",
        "restart_managed_service",
        "restore_config_mode",
    }
)


class SafetyCaseIntegrityError(ValueError):
    pass


def action_fingerprint(proposal: ActionProposal) -> str:
    return action_contract_digest(build_bound_action(proposal))


class ActionSafetyCaseService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_for_proposal(self, proposal: ActionProposal) -> ActionSafetyCase:
        if proposal.id is None:
            raise ValueError("action proposal must be persisted before creating its safety case")
        existing = self.session.scalar(
            select(ActionSafetyCase).where(
                ActionSafetyCase.proposal_id == proposal.id
            )
        )
        if existing is not None:
            self._assert_integrity(existing, proposal)
            return existing
        if proposal.tool_name not in SUPPORTED_ACTIONS:
            raise ValueError(f"unsupported safety-case action: {proposal.tool_name}")
        dry_run = proposal.dry_run_result_json
        if not isinstance(dry_run, dict) or dry_run.get("status") != "ok":
            raise ValueError("action proposal lacks a successful dry-run result")

        bound_action = build_bound_action(proposal)
        contract = _build_contract(proposal)
        contract_evidence_refs: list[str] = []
        if proposal.tool_name == "restart_managed_service":
            contract_evidence_refs = _bind_restart_impact(
                self.session,
                proposal,
                contract,
            )
        approval_block = contract.pop("approval_block", None)
        evidence_refs = [
            f"proposal:{proposal.id}",
            *contract_evidence_refs,
            *[
                str(value)
                for value in dry_run.get("evidence_refs", [])
                if isinstance(value, str) and value
            ],
        ]
        safety_case = ActionSafetyCase(
            task_id=proposal.task_id,
            proposal_id=proposal.id,
            tool_name=proposal.tool_name,
            risk_level=proposal.risk_level,
            policy_version=POLICY_VERSION,
            status="BLOCKED" if approval_block else "READY",
            action_fingerprint=action_contract_digest(bound_action),
            bound_action_json=bound_action,
            scope_json=contract["scope"],
            preconditions_json=contract["preconditions"],
            postconditions_json=contract["postconditions"],
            verifier_tool=verification_tool_name(proposal.tool_name),
            rollback_strategy_json=contract["rollback_strategy"],
            evidence_refs_json=list(dict.fromkeys(evidence_refs)),
            result_json={
                "dry_run": {
                    "status": dry_run.get("status"),
                    "warnings": dry_run.get("warnings", []),
                    "actions_proposed": dry_run.get("actions_proposed", []),
                },
                **(
                    {"readiness": approval_block}
                    if isinstance(approval_block, dict)
                    else {}
                ),
            },
            case_hash="0" * 64,
        )
        self.session.add(safety_case)
        self.session.flush()
        self._seal(safety_case)
        return safety_case

    def bound_action(
        self,
        safety_case: ActionSafetyCase,
        proposal: ActionProposal,
    ) -> dict[str, Any]:
        self._assert_integrity(safety_case, proposal)
        return copy_bound_action(safety_case.bound_action_json)

    def get_for_proposal(self, proposal_id: int) -> ActionSafetyCase | None:
        return self.session.scalar(
            select(ActionSafetyCase).where(
                ActionSafetyCase.proposal_id == proposal_id
            )
        )

    def assert_ready(self, proposal: ActionProposal) -> ActionSafetyCase:
        safety_case = self.session.scalar(
            select(ActionSafetyCase)
            .where(ActionSafetyCase.proposal_id == proposal.id)
            .with_for_update()
        )
        if safety_case is None:
            raise SafetyCaseIntegrityError(
                "执行依据缺失，请重新生成处置方案后再审批。"
            )
        self._assert_integrity(safety_case, proposal)
        if safety_case.status != "READY":
            raise SafetyCaseIntegrityError(
                f"执行依据状态为 {safety_case.status}，不能重复或越级审批。"
            )
        return safety_case

    def record_approval(
        self,
        safety_case: ActionSafetyCase,
        *,
        operator: str,
        comment: str | None,
    ) -> None:
        result = deepcopy(safety_case.result_json)
        result["approval"] = {
            "operator": operator,
            "comment": comment,
        }
        safety_case.status = "APPROVED"
        safety_case.approved_by = operator
        safety_case.approved_at = utcnow()
        safety_case.result_json = result
        self._seal(safety_case)

    def record_precondition(
        self,
        safety_case: ActionSafetyCase,
        *,
        call_id: int | None,
        valid: bool,
        reason: str,
        details: dict[str, Any],
    ) -> None:
        result = deepcopy(safety_case.result_json)
        result["precondition"] = {
            "valid": valid,
            "reason": reason,
            "details": details,
        }
        safety_case.pre_verifier_call_id = call_id
        safety_case.status = "APPROVED" if valid else "BLOCKED"
        safety_case.result_json = result
        self._append_reference(safety_case, call_id, "tool_call")
        self._seal(safety_case)

    def record_execution_started(self, safety_case: ActionSafetyCase) -> None:
        safety_case.status = "EXECUTING"
        self._seal(safety_case)

    def record_execution(
        self,
        safety_case: ActionSafetyCase,
        *,
        call_id: int,
        outcome: str,
        output: dict[str, Any],
        reason: str | None = None,
    ) -> None:
        normalized_outcome = outcome.upper()
        if normalized_outcome not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
            raise ValueError(f"unsupported execution outcome: {outcome}")
        result = deepcopy(safety_case.result_json)
        result["execution"] = {
            "outcome": normalized_outcome,
            "succeeded": (
                True
                if normalized_outcome == "SUCCEEDED"
                else False
                if normalized_outcome == "FAILED"
                else None
            ),
            "status": output.get("status"),
            "artifacts": output.get("artifacts", []),
            "evidence_refs": output.get("evidence_refs", []),
            "reason": reason,
        }
        safety_case.execution_call_id = call_id
        safety_case.status = {
            "SUCCEEDED": "EXECUTING",
            "FAILED": "FAILED",
            "UNKNOWN": "NEEDS_OPERATOR",
        }[normalized_outcome]
        safety_case.result_json = result
        self._append_reference(safety_case, call_id, "tool_call")
        for value in output.get("evidence_refs", []):
            if isinstance(value, str) and value:
                self._append_reference_value(safety_case, value)
        self._seal(safety_case)

    def record_postcondition(
        self,
        safety_case: ActionSafetyCase,
        *,
        call_id: int | None,
        valid: bool,
        reason: str,
        details: dict[str, Any],
    ) -> None:
        result = deepcopy(safety_case.result_json)
        result["postcondition"] = {
            "valid": valid,
            "reason": reason,
            "details": details,
        }
        safety_case.post_verifier_call_id = call_id
        safety_case.status = "VERIFIED" if valid else "NEEDS_OPERATOR"
        safety_case.result_json = result
        self._append_reference(safety_case, call_id, "tool_call")
        self._seal(safety_case)

    def record_impact_verification(
        self,
        safety_case: ActionSafetyCase,
        *,
        call_id: int,
        verification: dict[str, Any],
    ) -> None:
        result = deepcopy(safety_case.result_json)
        result["impact_verification"] = deepcopy(verification)
        safety_case.result_json = result
        self._append_reference(safety_case, call_id, "tool_call")
        self._seal(safety_case)

    def record_impact_precondition(
        self,
        safety_case: ActionSafetyCase,
        *,
        call_id: int,
        verification: dict[str, Any],
    ) -> None:
        result = deepcopy(safety_case.result_json)
        result["impact_precondition"] = deepcopy(verification)
        safety_case.result_json = result
        self._append_reference(safety_case, call_id, "tool_call")
        self._seal(safety_case)

    def mark_blocked(
        self,
        safety_case: ActionSafetyCase,
        *,
        stage: str,
        reason: str,
    ) -> None:
        result = deepcopy(safety_case.result_json)
        result["blocked"] = {"stage": stage, "reason": reason}
        safety_case.status = "BLOCKED"
        safety_case.result_json = result
        self._seal(safety_case)

    def mark_rejected(
        self,
        safety_case: ActionSafetyCase,
        *,
        operator: str,
        comment: str | None,
    ) -> None:
        result = deepcopy(safety_case.result_json)
        result["rejection"] = {"operator": operator, "comment": comment}
        safety_case.status = "REJECTED"
        safety_case.result_json = result
        self._seal(safety_case)

    def _assert_integrity(
        self,
        safety_case: ActionSafetyCase,
        proposal: ActionProposal,
    ) -> None:
        expected_case_hash = _case_hash(safety_case)
        expected_action_fingerprint = action_fingerprint(proposal)
        if safety_case.case_hash != expected_case_hash:
            self._revoke(safety_case, "执行依据内容校验失败。")
            raise SafetyCaseIntegrityError(
                "执行依据完整性校验失败，处置方案已撤销。"
            )
        try:
            bound_action = copy_bound_action(safety_case.bound_action_json)
            assert_bound_action_matches(bound_action, proposal)
        except ActionContractIntegrityError:
            bound_action = {}
        if (
            safety_case.action_fingerprint != expected_action_fingerprint
            or (
                bound_action
                and safety_case.action_fingerprint
                != action_contract_digest(bound_action)
            )
            or not bound_action
            or safety_case.task_id != proposal.task_id
            or safety_case.tool_name != proposal.tool_name
            or safety_case.risk_level != proposal.risk_level
        ):
            self._revoke(safety_case, "处置方案在执行依据生成后发生变化。")
            raise SafetyCaseIntegrityError(
                "处置方案与执行依据不一致，已撤销并要求重新生成。"
            )
        self._assert_service_expectations(safety_case)

    def _assert_service_expectations(
        self,
        safety_case: ActionSafetyCase,
    ) -> None:
        if safety_case.tool_name != "restart_managed_service":
            return
        impact = safety_case.scope_json.get("change_impact")
        if not isinstance(impact, dict):
            self._revoke(safety_case, "服务影响范围缺失。")
            raise SafetyCaseIntegrityError(
                "服务影响范围缺失，已撤销并要求重新生成。"
            )
        catalog = ServiceExpectationService(self.session)
        host_key = socket.gethostname()
        for item in impact.get("predicted_units", []):
            if not isinstance(item, dict):
                continue
            unit = str(item.get("unit") or "").strip()
            if not unit:
                continue
            current = catalog.resolve(host_key=host_key, unit_name=unit)
            was_registered = item.get("registered") is True
            if was_registered != (current is not None):
                self._revoke(safety_case, f"服务 {unit} 的责任方登记状态已变化。")
                raise SafetyCaseIntegrityError(
                    "服务责任方或期望状态在审批前发生变化，"
                    "已撤销并要求重新生成。"
                )
            if current is None:
                continue
            frozen = (
                item.get("expectation_version"),
                item.get("expected_active_state"),
                item.get("service_owner"),
                item.get("criticality"),
                item.get("environment"),
            )
            observed = (
                current.version,
                current.expected_active_state,
                current.service_owner,
                current.criticality,
                current.environment,
            )
            if frozen != observed:
                self._revoke(safety_case, f"服务 {unit} 的期望状态版本已变化。")
                raise SafetyCaseIntegrityError(
                    "服务责任方或期望状态在审批前发生变化，"
                    "已撤销并要求重新生成。"
                )

    def _revoke(self, safety_case: ActionSafetyCase, reason: str) -> None:
        result = deepcopy(safety_case.result_json)
        result["revocation"] = {"reason": reason}
        safety_case.status = "REVOKED"
        safety_case.result_json = result
        self._seal(safety_case)

    def _append_reference(
        self,
        safety_case: ActionSafetyCase,
        value: int | None,
        prefix: str,
    ) -> None:
        if value is not None:
            self._append_reference_value(safety_case, f"{prefix}:{value}")

    @staticmethod
    def _append_reference_value(
        safety_case: ActionSafetyCase,
        reference: str,
    ) -> None:
        references = list(safety_case.evidence_refs_json)
        if reference not in references:
            references.append(reference)
            safety_case.evidence_refs_json = references

    def _seal(self, safety_case: ActionSafetyCase) -> None:
        safety_case.updated_at = utcnow()
        safety_case.case_hash = _case_hash(safety_case)
        self.session.flush()


def safety_case_to_dict(safety_case: ActionSafetyCase) -> dict[str, Any]:
    return {
        "id": safety_case.id,
        "proposal_id": safety_case.proposal_id,
        "tool_name": safety_case.tool_name,
        "risk_level": safety_case.risk_level,
        "policy_version": safety_case.policy_version,
        "status": safety_case.status,
        "action_fingerprint": safety_case.action_fingerprint,
        "bound_action": safety_case.bound_action_json,
        "scope": safety_case.scope_json,
        "preconditions": safety_case.preconditions_json,
        "postconditions": safety_case.postconditions_json,
        "verifier_tool": safety_case.verifier_tool,
        "rollback_strategy": safety_case.rollback_strategy_json,
        "evidence_refs": safety_case.evidence_refs_json,
        "result": safety_case.result_json,
        "case_hash": safety_case.case_hash,
        "approved_by": safety_case.approved_by,
        "approved_at": (
            safety_case.approved_at.isoformat()
            if safety_case.approved_at is not None
            else None
        ),
        "created_at": safety_case.created_at.isoformat(),
        "updated_at": safety_case.updated_at.isoformat(),
    }


def _case_hash(safety_case: ActionSafetyCase) -> str:
    return stable_hash(
        {
            "id": safety_case.id,
            "task_id": safety_case.task_id,
            "proposal_id": safety_case.proposal_id,
            "tool_name": safety_case.tool_name,
            "risk_level": safety_case.risk_level,
            "policy_version": safety_case.policy_version,
            "status": safety_case.status,
            "action_fingerprint": safety_case.action_fingerprint,
            "bound_action": safety_case.bound_action_json,
            "scope": safety_case.scope_json,
            "preconditions": safety_case.preconditions_json,
            "postconditions": safety_case.postconditions_json,
            "verifier_tool": safety_case.verifier_tool,
            "rollback_strategy": safety_case.rollback_strategy_json,
            "evidence_refs": safety_case.evidence_refs_json,
            "result": safety_case.result_json,
            "approved_by": safety_case.approved_by,
            "approved_at": (
                safety_case.approved_at.isoformat()
                if safety_case.approved_at is not None
                else None
            ),
            "pre_verifier_call_id": safety_case.pre_verifier_call_id,
            "execution_call_id": safety_case.execution_call_id,
            "post_verifier_call_id": safety_case.post_verifier_call_id,
        }
    )


def _build_contract(proposal: ActionProposal) -> dict[str, Any]:
    payload = proposal.input_json
    if proposal.tool_name == "safe_log_rotate":
        path = _required_text(payload, "path")
        return {
            "scope": {
                "resource_type": "file",
                "paths": [path],
                "operation": "backup_compress_then_truncate",
                "side_effects": ["create_backup", "truncate_source"],
            },
            "preconditions": [
                _condition("source_regular_file", "目标必须是允许范围内的普通日志文件。"),
                _condition("source_hash_complete", "执行前必须独立记录完整 SHA256 和大小。"),
            ],
            "postconditions": [
                _condition("source_truncated", "源日志大小必须变为 0。"),
                _condition("backup_hash_matches", "备份解压内容哈希必须与执行前源日志一致。"),
            ],
            "rollback_strategy": {
                "mode": "APPROVAL_REQUIRED",
                "tool_name": "restore_log_backup",
                "summary": "使用本次执行生成的备份产物恢复，恢复动作需再次审批。",
            },
        }
    if proposal.tool_name == "restore_log_backup":
        artifact_path = _required_text(payload, "artifact_path")
        restore_target = _required_text(payload, "restore_target")
        return {
            "scope": {
                "resource_type": "file",
                "paths": [artifact_path, restore_target],
                "operation": "restore_verified_backup",
                "side_effects": ["snapshot_current_target", "replace_target_content"],
            },
            "preconditions": [
                _condition("artifact_hash_complete", "备份内容必须形成完整独立哈希证据。"),
                _condition("target_hash_complete", "恢复目标当前内容必须先独立留证。"),
            ],
            "postconditions": [
                _condition("target_matches_artifact", "恢复后目标哈希必须与备份内容一致。"),
                _condition("previous_target_preserved", "恢复前内容必须由独立快照完整保留。"),
            ],
            "rollback_strategy": {
                "mode": "EVIDENCE_PRESERVING_MANUAL",
                "tool_name": None,
                "summary": "恢复前快照保留原内容；再次变更需由运维人员重新发起审批。",
            },
        }
    if proposal.tool_name == "restart_managed_service":
        unit = _required_text(payload, "unit")
        return {
            "scope": {
                "resource_type": "systemd_unit",
                "units": [unit],
                "operation": "single_restart",
                "side_effects": ["restart_unit_once"],
            },
            "preconditions": [
                _condition("unit_loaded", "目标服务必须已加载且已形成独立状态证据。"),
                _condition("unit_allowlisted", "目标服务必须命中精确重启白名单。"),
            ],
            "postconditions": [
                _condition("unit_active", "独立状态工具必须确认服务恢复为 active。"),
                _condition("no_automatic_retry", "失败后不得自动重复重启，必须转人工处理。"),
            ],
            "rollback_strategy": {
                "mode": "OPERATOR_TAKEOVER",
                "tool_name": None,
                "summary": "服务未恢复时停止自动重试，保留前后状态并转人工处置。",
            },
        }
    if proposal.tool_name == "restore_config_mode":
        path = _required_text(payload, "path")
        target_mode = _required_text(payload, "target_mode")
        expected_sha256 = _required_text(payload, "expected_sha256")
        return {
            "scope": {
                "resource_type": "configuration_file",
                "paths": [path],
                "operation": "restore_mode_only",
                "target_mode": target_mode,
                "expected_sha256": expected_sha256,
                "baseline_id": payload.get("baseline_id"),
                "baseline_check_id": payload.get("baseline_check_id"),
                "side_effects": ["change_permission_bits"],
            },
            "preconditions": [
                _condition("content_matches_baseline", "完整内容哈希必须与已确认基线一致。"),
                _condition("owner_unchanged", "UID、GID 必须与基线一致。"),
            ],
            "postconditions": [
                _condition("mode_restored", f"权限位必须恢复为 {target_mode}。"),
                _condition("content_owner_preserved", "内容哈希、UID 和 GID 必须保持不变。"),
            ],
            "rollback_strategy": {
                "mode": "OPERATOR_TAKEOVER",
                "tool_name": None,
                "summary": "仅修改权限位；验证失败时停止后续动作并转人工核对基线。",
            },
        }
    raise ValueError(f"unsupported safety-case action: {proposal.tool_name}")


def _bind_restart_impact(
    session: Session,
    proposal: ActionProposal,
    contract: dict[str, Any],
) -> list[str]:
    unit = _required_text(proposal.input_json, "unit")
    impact_call, impact_observation = _latest_tool_observation(
        session,
        proposal.task_id,
        "service_dependency_snapshot",
        predicate=lambda observation: _matches_change_impact(
            observation,
            unit=unit,
            action="restart",
        ),
    )
    if impact_call is None or impact_observation is None:
        raise ValueError("restart proposal lacks a persisted service change-impact assessment")
    impact = impact_observation.get("change_impact")
    if not isinstance(impact, dict) or impact.get("status") not in {
        "ASSESSED",
        "PARTIAL",
    }:
        raise ValueError("restart proposal change-impact assessment is unresolved")

    desired_call, desired_observation = _latest_tool_observation(
        session,
        proposal.task_id,
        "service_desired_state",
        predicate=lambda observation: observation.get("unit") == unit,
    )
    if (
        desired_call is None
        or desired_observation is None
        or desired_observation.get("expected_active_state") != "active"
    ):
        raise ValueError("restart proposal lacks an approved active service expectation")

    catalog = ServiceExpectationService(session)
    host_key = socket.gethostname()
    expectation_refs: list[str] = []
    predicted_units: list[dict[str, Any]] = []
    catalogued_count = 0
    for item in impact.get("predicted_units", []):
        if not isinstance(item, dict):
            continue
        predicted_unit = str(item.get("unit") or "")
        if not predicted_unit:
            continue
        record = catalog.resolve(host_key=host_key, unit_name=predicted_unit)
        expectation = (
            {
                "registered": True,
                "service_owner": record.service_owner,
                "criticality": record.criticality,
                "environment": record.environment,
                "expected_active_state": record.expected_active_state,
                "expectation_version": record.version,
            }
            if record is not None
            else {
                "registered": False,
                "service_owner": None,
                "criticality": None,
                "environment": None,
                "expected_active_state": None,
                "expectation_version": None,
            }
        )
        if record is not None:
            catalogued_count += 1
            expectation_refs.append(f"service-expectation:{record.id}:v{record.version}")
        predicted_units.append(
            {
                "unit": predicted_unit,
                "role": item.get("role"),
                "certainty": item.get("certainty"),
                "mechanism": item.get("mechanism"),
                "reason": item.get("reason"),
                "path": item.get("path", []),
                "load_state": item.get("load_state"),
                "active_state": item.get("active_state"),
                "sub_state": item.get("sub_state"),
                "invocation_id": item.get("invocation_id"),
                "main_pid": item.get("main_pid"),
                "active_enter_monotonic": item.get(
                    "active_enter_monotonic"
                ),
                "inactive_enter_monotonic": item.get(
                    "inactive_enter_monotonic"
                ),
                **expectation,
            }
        )

    scope = contract["scope"]
    scope["change_impact"] = {
        "status": impact.get("status"),
        "coverage": impact.get("coverage"),
        "action": impact.get("action"),
        "target_units": impact.get("target_units", []),
        "propagated_unit_count": impact.get("propagated_unit_count", 0),
        "possible_client_count": impact.get("possible_client_count", 0),
        "catalogued_unit_count": catalogued_count,
        "predicted_units": predicted_units,
        "predicted_clients": impact.get("predicted_clients", []),
        "mechanism_counts": impact.get("mechanism_counts", {}),
        "evidence_gaps": impact.get("evidence_gaps", []),
    }
    evidence_gaps = [
        item
        for item in impact.get("evidence_gaps", [])
        if isinstance(item, dict)
    ]
    uncatalogued_units = [
        item["unit"]
        for item in predicted_units
        if item.get("registered") is not True
    ]
    blockers: list[dict[str, Any]] = []
    if impact.get("status") != "ASSESSED" or impact.get("coverage") != "FULL":
        blockers.append(
            {
                "code": "IMPACT_COVERAGE_INCOMPLETE",
                "summary": "目标服务的传播关系或当前连接影响尚未完整闭合。",
            }
        )
    if evidence_gaps:
        blockers.append(
            {
                "code": "IMPACT_EVIDENCE_GAP",
                "summary": f"影响评估仍有 {len(evidence_gaps)} 项证据缺口。",
            }
        )
    if uncatalogued_units:
        blockers.append(
            {
                "code": "IMPACT_OWNER_UNRESOLVED",
                "summary": (
                    f"{len(uncatalogued_units)} 个受影响服务未登记责任方和期望状态。"
                ),
            }
        )
    if blockers:
        contract["approval_block"] = {
            "status": "BLOCKED",
            "reason": "影响范围未满足执行条件，预案仅供查看，不能进入审批。",
            "blockers": blockers,
            "uncatalogued_units": uncatalogued_units,
            "evidence_gaps": evidence_gaps,
        }
    contract["preconditions"].extend(
        [
            _condition(
                "service_expectation_active",
                "目标服务必须存在经审批的 active 期望状态和责任方记录。",
            ),
            _condition(
                "change_impact_assessed",
                "目标服务的 systemd 传播关系与当前连接影响必须已形成持久化证据。",
            ),
            _condition(
                "change_impact_complete",
                "传播范围、当前连接及所有受影响服务责任边界必须完整闭合。",
            ),
        ]
    )
    return list(
        dict.fromkeys(
            [
                f"tool_call:{impact_call.id}",
                f"tool_call:{desired_call.id}",
                *impact_call.output_json.get("evidence_refs", []),
                *desired_call.output_json.get("evidence_refs", []),
                *expectation_refs,
            ]
        )
    )


def _latest_tool_observation(
    session: Session,
    task_id: int,
    tool_name: str,
    *,
    predicate: Callable[[dict[str, Any]], bool],
) -> tuple[ToolCall | None, dict[str, Any] | None]:
    calls = session.scalars(
        select(ToolCall)
        .where(
            ToolCall.task_id == task_id,
            ToolCall.tool_name == tool_name,
        )
        .order_by(ToolCall.id.desc())
    )
    for call in calls:
        observations = call.output_json.get("observations", [])
        if not isinstance(observations, list):
            continue
        for observation in observations:
            if isinstance(observation, dict) and predicate(observation):
                return call, observation
    return None, None


def _matches_change_impact(
    observation: dict[str, Any],
    *,
    unit: str,
    action: str,
) -> bool:
    impact = observation.get("change_impact")
    if not isinstance(impact, dict) or impact.get("action") != action:
        return False
    target_units = impact.get("target_units", [])
    return isinstance(target_units, list) and unit in target_units


def _condition(code: str, statement: str) -> dict[str, str]:
    return {"code": code, "statement": statement}


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing safety-case field: {key}")
    return value.strip()
