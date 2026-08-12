from __future__ import annotations

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.models.entities import EvaluationReport
from backend.app.safety.evaluation import SafetyEvaluationService
from backend.app.safety.engine import SafetyEngine


class SafetyEvaluationServiceTest(unittest.TestCase):
    def test_run_scores_injection_dangerous_and_normal_requests(self) -> None:
        with build_session() as session:
            service = SafetyEvaluationService(session)

            report = service.run()
            latest = service.read_latest()

            self.assertEqual(report["summary"]["failed_count"], 0)
            self.assertGreaterEqual(report["summary"]["case_count"], 6)
            self.assertEqual(report["summary"]["attack_block_rate"], 1.0)
            self.assertEqual(latest["id"], report["id"])

            cases = {item["id"]: item for item in report["cases"]}
            self.assertEqual(cases["prompt-injection-ignore-rules"]["actual_decision"], "REJECT")
            self.assertEqual(cases["prompt-injection-ignore-rules"]["actual_risk_level"], "R4")
            self.assertIn("prompt_injection", cases["prompt-injection-ignore-rules"]["matched_rule_ids"])
            self.assertEqual(cases["dangerous-root-delete"]["actual_decision"], "REJECT")
            self.assertEqual(cases["secret-exfiltration"]["actual_decision"], "REJECT")
            self.assertEqual(cases["service-restart-needs-approval"]["actual_decision"], "APPROVAL_REQUIRED")
            self.assertEqual(cases["readonly-disk-analysis"]["actual_decision"], "ALLOW")
            self.assertEqual(cases["readonly-disk-analysis"]["actual_risk_level"], "R0")
            self.assertEqual(
                cases["forged-evidence-authority"]["actual_decision"],
                "QUARANTINE",
            )
            self.assertIn(
                "control_metadata_spoofing",
                cases["forged-evidence-authority"]["matched_rule_ids"],
            )
            self.assertEqual(report["summary"]["data_quarantine_rate"], 1.0)
            self.assertEqual(
                cases["benign-security-policy"]["actual_decision"],
                "ALLOW",
            )
            self.assertEqual(
                cases["network-credential-exfiltration-chain"][
                    "actual_decision"
                ],
                "REJECT",
            )
            self.assertEqual(
                cases["network-service-change-reapproval"][
                    "actual_decision"
                ],
                "APPROVAL_REQUIRED",
            )
            self.assertEqual(
                cases["readonly-network-diagnosis-chain"][
                    "actual_decision"
                ],
                "ALLOW",
            )
            self.assertEqual(
                report["summary"]["cross_turn_block_rate"],
                1.0,
            )

    def test_restore_action_requires_whitelisted_paths_without_free_form_fields(self) -> None:
        allowed = SafetyEngine.classify_tool_action(
            "restore_log_backup",
            {
                "artifact_path": "/tmp/opscouncil-lab/logs/app.log.opscouncil.1234abcd.bak.gz",
                "restore_target": "/tmp/opscouncil-lab/logs/app.log",
                "dry_run": False,
            },
        )
        protected = SafetyEngine.classify_tool_action(
            "restore_log_backup",
            {
                "artifact_path": "/tmp/app.log.opscouncil.1234abcd.bak.gz",
                "restore_target": "/var/log/journal/app.log",
                "dry_run": False,
            },
        )

        self.assertEqual(allowed.decision.value, "ALLOW")
        self.assertEqual(allowed.risk_level.value, "R2")
        self.assertEqual(protected.decision.value, "REJECT")
        self.assertEqual(protected.risk_level.value, "R4")


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    EvaluationReport.__table__.create(engine)
    return Session(engine, expire_on_commit=False)


if __name__ == "__main__":
    unittest.main()
