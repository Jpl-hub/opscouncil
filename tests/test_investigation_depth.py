from __future__ import annotations

import unittest

from backend.app.investigation.depth import select_investigation_depth


class InvestigationDepthTest(unittest.TestCase):
    def test_direct_observation_request_does_not_start_iterative_rca(self) -> None:
        decision = select_investigation_depth(
            "network_exposure_analysis",
            "检查当前主机的监听端口和暴露风险",
        )

        self.assertEqual(decision.mode, "DIRECT_EVIDENCE")

    def test_explicit_root_cause_request_uses_iterative_rca(self) -> None:
        decision = select_investigation_depth(
            "process_health_analysis",
            "请调查动态基线偏离的根因并给出处置建议",
        )

        self.assertEqual(decision.mode, "ITERATIVE_RCA")

    def test_disk_source_localization_uses_iterative_rca(self) -> None:
        decision = select_investigation_depth(
            "disk_pressure_analysis",
            "分析磁盘空间，定位异常大日志并判断能否安全处置",
        )

        self.assertEqual(decision.mode, "ITERATIVE_RCA")

    def test_bounded_large_file_scan_uses_direct_evidence(self) -> None:
        decision = select_investigation_depth(
            "disk_pressure_analysis",
            (
                "定位 /tmp/opscouncil-lab/logs 中超过 10 MB 的日志；"
                "核验路径与大小后生成可逆轮转方案"
            ),
        )

        self.assertEqual(decision.mode, "DIRECT_EVIDENCE")
        self.assertIn("确定性系统观测", decision.reason)

    def test_plain_disk_usage_query_uses_direct_evidence(self) -> None:
        decision = select_investigation_depth(
            "disk_pressure_analysis",
            "查看当前磁盘使用率",
        )

        self.assertEqual(decision.mode, "DIRECT_EVIDENCE")

    def test_config_drift_uses_confirmed_baseline_instead_of_model_guessing(self) -> None:
        decision = select_investigation_depth(
            "config_integrity_analysis",
            "检查关键配置漂移并分析原因",
        )

        self.assertEqual(decision.mode, "DIRECT_EVIDENCE")

    def test_service_change_preview_uses_deterministic_impact_evidence(self) -> None:
        decision = select_investigation_depth(
            "log_analysis",
            (
                "请预演重启 opsbench-impact-root.service，评估影响范围、"
                "执行前条件和回滚方案，生成审批方案但不要自动执行。"
            ),
        )

        self.assertEqual(decision.mode, "DIRECT_EVIDENCE")
        self.assertIn("变更预演", decision.reason)

    def test_explicit_root_cause_still_overrides_service_change_preview(self) -> None:
        decision = select_investigation_depth(
            "log_analysis",
            (
                "先调查 opsbench-impact-root.service 异常根因，"
                "再预演重启并评估影响范围。"
            ),
        )

        self.assertEqual(decision.mode, "ITERATIVE_RCA")


if __name__ == "__main__":
    unittest.main()
