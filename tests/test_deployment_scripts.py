from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DeploymentScriptTest(unittest.TestCase):
    def test_smoke_check_verifies_deployment_readiness_endpoint(self) -> None:
        script = (ROOT / "scripts" / "smoke_check.sh").read_text(encoding="utf-8")

        self.assertIn("/api/deployment/readiness", script)
        self.assertIn("OPSCOUNCIL_REQUIRE_DEPLOYMENT_READY", script)
        self.assertIn("deployment readiness check failed", script)

    def test_preflight_checks_os_observability_toolchain(self) -> None:
        script = (ROOT / "scripts" / "preflight.sh").read_text(encoding="utf-8")

        for command in ("journalctl", "systemctl", "ss", "ps"):
            self.assertIn(command, script)

        self.assertIn('node_major" -ge 20', script)
        self.assertIn("serving the verified bundled frontend", script)

    def test_package_uses_an_explicit_runtime_allowlist(self) -> None:
        script = (ROOT / "scripts" / "package.sh").read_text(encoding="utf-8")

        self.assertIn("frontend/dist/index.html", script)
        self.assertIn("frontend build artifact missing", script)
        self.assertIn("node version is too old", script)
        self.assertIn("package_entries=(", script)
        self.assertIn('staging_dir="$(mktemp -d)"', script)
        self.assertIn("find \"$staging_dir\" -type d -exec chmod 0755", script)
        self.assertIn("find \"$staging_dir\" -type f -exec chmod 0644", script)
        self.assertIn('chmod 0755 "$staging_dir/scripts/"*', script)
        for entry in (
            ".env.example",
            "alembic.ini",
            "backend",
            "config/feishu.env.example",
            "deploy/systemd",
            "docs/deployment/linux.md",
            "frontend/dist",
            "migrations",
            "requirements",
            "scripts/opscouncilctl.py",
            "scripts/policy_controller.py",
            "scripts/feishu_channel.py",
            "scripts/install_service.sh",
            "scripts/migrate.sh",
            "scripts/preflight.sh",
            "scripts/prepare.sh",
            "scripts/run.sh",
            "scripts/smoke_check.sh",
            "scripts/worker.py",
        ):
            self.assertIn(f'"{entry}"', script)

        self.assertNotIn('-czf "$PACKAGE_DIR/$PACKAGE_NAME" .', script)
        for excluded_entry in (
            "tests",
            "frontend/src",
            "docs/submission",
            "scripts/build_final_video.py",
            "scripts/record_vm_walkthrough.cjs",
            "scripts/generate_submission_docs.py",
        ):
            self.assertNotIn(f'"{excluded_entry}"', script)

    def test_prepare_uses_bundled_frontend_when_source_is_absent(self) -> None:
        script = (ROOT / "scripts" / "prepare.sh").read_text(encoding="utf-8")

        self.assertIn('if [ -f "$ROOT_DIR/frontend/package.json" ]', script)
        self.assertIn("using bundled frontend/dist", script)
        self.assertIn("frontend/dist/index.html", script)

    def test_prepare_installs_native_loongarch_document_parser_dependency(self) -> None:
        script = (ROOT / "scripts" / "prepare.sh").read_text(encoding="utf-8")

        self.assertIn('if [ "$ARCH" = "loongarch64" ]', script)
        self.assertIn("python3-lxml", script)
        self.assertIn("sudo dnf install -y", script)
        self.assertIn("lark_oapi", script)
        self.assertIn("python3-devel", script)

    def test_migration_script_transitions_existing_schema_then_upgrades_head(self) -> None:
        script = (ROOT / "scripts" / "migrate.sh").read_text(encoding="utf-8")

        self.assertIn("alembic_version", script)
        self.assertIn('"investigations" in tables', script)
        self.assertIn("unexpected-unversioned-investigation", script)
        self.assertIn("0001_existing_schema", script)
        self.assertIn("alembic stamp", script)
        self.assertIn("alembic upgrade head", script)
        self.assertIn("refusing to guess a migration revision", script)

    def test_service_installer_migrates_before_enabling_api_and_worker(self) -> None:
        script = (ROOT / "scripts" / "install_service.sh").read_text(encoding="utf-8")

        migrate_at = script.index("migrate.sh")
        api_install_at = script.index('sudo install -m 0644 "$api_unit"')
        worker_install_at = script.index('sudo install -m 0644 "$worker_unit"')
        self.assertLess(migrate_at, api_install_at)
        self.assertLess(migrate_at, worker_install_at)
        self.assertIn("opscouncil-worker", script)
        self.assertIn("scripts/worker.py", script)
        self.assertIn("opscouncil-policy-controller", script)
        self.assertIn("scripts/policy_controller.py", script)
        self.assertIn('sudo systemctl enable "$SERVICE_NAME" "$WORKER_SERVICE_NAME"', script)

    def test_service_installer_rejects_a_root_runtime_account(self) -> None:
        script = (ROOT / "scripts" / "install_service.sh").read_text(encoding="utf-8")

        self.assertIn('if [ "$RUN_USER" = "root" ]', script)
        self.assertIn("refusing to install services with a root runtime account", script)
        self.assertNotIn('if [ "$(id -u)" = "0" ]', script)

    def test_service_installer_adds_isolated_optional_feishu_unit(self) -> None:
        script = (ROOT / "scripts" / "install_service.sh").read_text(encoding="utf-8")

        self.assertIn("opscouncil-feishu", script)
        self.assertIn("scripts/feishu_channel.py", script)
        self.assertIn("ConditionPathExists=${FEISHU_ENV_FILE}", script)
        self.assertIn("EnvironmentFile=${FEISHU_ENV_FILE}", script)
        self.assertIn('sudo chmod 0600 "$FEISHU_ENV_FILE"', script)
        self.assertIn("NoNewPrivileges=true", script)

    def test_service_installer_can_add_bounded_failed_service_fixture(self) -> None:
        script = (ROOT / "scripts" / "install_service.sh").read_text(encoding="utf-8")
        unit = (
            ROOT / "deploy" / "systemd" / "opscouncil-lab-failed.service"
        ).read_text(encoding="utf-8")

        self.assertIn("OPSCOUNCIL_INSTALL_LAB_FIXTURES", script)
        self.assertIn("opscouncil-lab-failed", script)
        self.assertIn("LAB_FIXTURE_UNIT_SOURCE", script)
        self.assertIn("ExecStart=/usr/bin/false", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("CapabilityBoundingSet=", unit)
        self.assertIn('if [ "$INSTALL_LAB_FIXTURES" = "true" ]', script)
        self.assertNotIn('sudo systemctl enable "$LAB_FIXTURE_SERVICE_NAME"', script)

    def test_service_installer_adds_real_service_impact_fixture(self) -> None:
        script = (ROOT / "scripts" / "install_service.sh").read_text(encoding="utf-8")
        root_unit = (
            ROOT / "deploy" / "systemd" / "opsbench-impact-root.service"
        ).read_text(encoding="utf-8")
        propagated_unit = (
            ROOT / "deploy" / "systemd" / "opsbench-impact-part.service"
        ).read_text(encoding="utf-8")
        ordered_unit = (
            ROOT / "deploy" / "systemd" / "opsbench-impact-ordered.service"
        ).read_text(encoding="utf-8")

        self.assertIn("LAB_IMPACT_FIXTURE_UNITS", script)
        self.assertIn(
            "Wants=opsbench-impact-part.service "
            "opsbench-impact-ordered.service",
            root_unit,
        )
        self.assertIn("PartOf=opsbench-impact-root.service", propagated_unit)
        self.assertIn("After=opsbench-impact-root.service", ordered_unit)
        self.assertNotIn("PartOf=", ordered_unit)

    def test_service_installer_generates_exact_managed_restart_polkit_rule(self) -> None:
        script = (ROOT / "scripts" / "install_service.sh").read_text(encoding="utf-8")

        self.assertIn("OPSCOUNCIL_RESTARTABLE_UNITS", script)
        self.assertIn("managed-restart", script)
        self.assertIn("org.freedesktop.systemd1.manage-units", script)
        self.assertIn('action.lookup("verb") === "restart"', script)
        self.assertIn('action.lookup("unit")', script)
        self.assertIn("refusing protected restart unit", script)
        self.assertNotIn("NOPASSWD", script)

    def test_service_installer_passes_exact_config_repair_boundary(self) -> None:
        script = (ROOT / "scripts" / "install_service.sh").read_text(encoding="utf-8")

        self.assertIn("OPSCOUNCIL_REPAIRABLE_CONFIG_PATHS", script)
        self.assertGreaterEqual(script.count('Environment="OPSCOUNCIL_REPAIRABLE_CONFIG_PATHS='), 2)
        self.assertNotIn("chmod -R", script)

    def test_smoke_check_requires_live_feishu_connection_when_enabled(self) -> None:
        script = (ROOT / "scripts" / "smoke_check.sh").read_text(encoding="utf-8")

        self.assertIn("OPSCOUNCIL_REQUIRE_FEISHU", script)
        self.assertIn("/api/channels/feishu/status", script)
        self.assertIn("long connection is not ready", script)
        self.assertIn("must exist with mode 0600", script)
        self.assertIn("sudo -n stat -c '%u:%a'", script)

    def test_smoke_check_can_require_worker_service(self) -> None:
        script = (ROOT / "scripts" / "smoke_check.sh").read_text(encoding="utf-8")

        self.assertIn("OPSCOUNCIL_REQUIRE_WORKER", script)
        self.assertIn("systemctl is-active", script)
        self.assertIn("worker service check failed", script)
        self.assertIn("/api/runtime/worker", script)
        self.assertIn("worker heartbeat check failed", script)

    def test_smoke_check_can_require_policy_controller_service(self) -> None:
        script = (ROOT / "scripts" / "smoke_check.sh").read_text(encoding="utf-8")

        self.assertIn("OPSCOUNCIL_REQUIRE_POLICY_CONTROLLER", script)
        self.assertIn("opscouncil-policy-controller", script)
        self.assertIn("policy controller check failed", script)

    def test_smoke_check_can_require_bounded_lab_fixture(self) -> None:
        script = (ROOT / "scripts" / "smoke_check.sh").read_text(encoding="utf-8")

        self.assertIn("OPSCOUNCIL_REQUIRE_LAB_FIXTURES", script)
        self.assertIn("/api/lab/scenarios", script)
        self.assertIn("lab fixture check failed", script)


if __name__ == "__main__":
    unittest.main()
