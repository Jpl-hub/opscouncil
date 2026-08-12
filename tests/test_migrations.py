from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from backend.app.core.database import assert_schema_current


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class MigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.database_path = Path(self.temp_dir.name) / "migration-test.db"
        self.database_url = f"sqlite+pysqlite:///{self.database_path}"
        self.config = Config(str(PROJECT_ROOT / "alembic.ini"))
        self.config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
        self.config.set_main_option("sqlalchemy.url", self.database_url)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_empty_database_upgrades_to_complete_runtime_schema(self) -> None:
        command.upgrade(self.config, "head")

        engine = create_engine(self.database_url, future=True)
        tables = set(inspect(engine).get_table_names())

        self.assertIn("tasks", tables)
        self.assertIn("conversation_turns", tables)
        self.assertIn("knowledge_chunks", tables)
        self.assertIn("task_jobs", tables)
        self.assertIn("investigations", tables)
        self.assertIn("investigation_steps", tables)
        self.assertIn("evidence_items", tables)
        self.assertIn("hypotheses", tables)
        self.assertIn("hypothesis_evidence", tables)
        self.assertIn("patrol_policies", tables)
        self.assertIn("patrol_runs", tables)
        self.assertIn("findings", tables)
        self.assertIn("incidents", tables)
        self.assertIn("operational_memories", tables)
        self.assertIn("operational_memory_relations", tables)
        self.assertIn("operator_feedback", tables)
        self.assertIn("operator_preference_profiles", tables)
        self.assertIn("operators", tables)
        self.assertIn("operator_external_identities", tables)
        self.assertIn("channel_inbound_events", tables)
        self.assertIn("task_channel_bindings", tables)
        self.assertIn("channel_instances", tables)
        self.assertIn("notification_outbox", tables)
        self.assertIn("notification_deliveries", tables)
        self.assertIn("approval_decision_tokens", tables)
        self.assertIn("approval_decision_jobs", tables)
        self.assertIn("model_invocations", tables)
        self.assertIn("worker_instances", tables)
        self.assertIn("evaluation_reports", tables)
        self.assertIn("platform_capability_snapshots", tables)
        self.assertIn("risk_chain_assessments", tables)
        self.assertIn("action_safety_cases", tables)
        self.assertIn("service_expectations", tables)
        self.assertIn("incident_collaborations", tables)
        self.assertIn("agent_work_items", tables)
        self.assertIn("collaboration_events", tables)
        self.assertIn("alembic_version", tables)
        knowledge_document_columns = {
            column["name"] for column in inspect(engine).get_columns("knowledge_documents")
        }
        knowledge_chunk_columns = {
            column["name"] for column in inspect(engine).get_columns("knowledge_chunks")
        }
        evaluation_report_columns = {
            column["name"] for column in inspect(engine).get_columns("evaluation_reports")
        }
        config_baseline_columns = {
            column["name"] for column in inspect(engine).get_columns("config_baselines")
        }
        operational_memory_columns = {
            column["name"] for column in inspect(engine).get_columns("operational_memories")
        }
        platform_capability_columns = {
            column["name"]
            for column in inspect(engine).get_columns(
                "platform_capability_snapshots"
            )
        }
        action_safety_case_columns = {
            column["name"]
            for column in inspect(engine).get_columns("action_safety_cases")
        }
        safety_review_columns = {
            column["name"]
            for column in inspect(engine).get_columns("safety_reviews")
        }
        service_expectation_columns = {
            column["name"]
            for column in inspect(engine).get_columns("service_expectations")
        }
        incident_collaboration_columns = {
            column["name"]
            for column in inspect(engine).get_columns("incident_collaborations")
        }
        agent_work_item_columns = {
            column["name"]
            for column in inspect(engine).get_columns("agent_work_items")
        }
        collaboration_event_columns = {
            column["name"]
            for column in inspect(engine).get_columns("collaboration_events")
        }
        self.assertIn("version", knowledge_document_columns)
        self.assertIn("status", knowledge_document_columns)
        self.assertIn("search_text", knowledge_chunk_columns)
        self.assertIn("chunk_kind", knowledge_chunk_columns)
        self.assertIn("scope_key", evaluation_report_columns)
        self.assertIn("scope", config_baseline_columns)
        self.assertIn("memory_kind", operational_memory_columns)
        self.assertIn("symptom_fingerprint", operational_memory_columns)
        self.assertIn("valid_until", operational_memory_columns)
        self.assertIn("forgotten_at", operational_memory_columns)
        self.assertIn("qualification_status", operational_memory_columns)
        self.assertIn("qualification_report_json", operational_memory_columns)
        self.assertIn("qualified_at", operational_memory_columns)
        self.assertIn("content_hash", operational_memory_columns)
        self.assertIn("parent_content_hash", operational_memory_columns)
        self.assertIn("task_id", platform_capability_columns)
        self.assertIn("bound_action_json", action_safety_case_columns)
        self.assertIn("policy_version", safety_review_columns)
        self.assertIn("policy_digest", safety_review_columns)
        self.assertIn("subject_json", safety_review_columns)
        self.assertIn("expected_active_state", service_expectation_columns)
        self.assertIn("service_owner", service_expectation_columns)
        self.assertIn("source_ref", service_expectation_columns)
        self.assertIn("version", service_expectation_columns)
        self.assertIn("listener_expectations_json", service_expectation_columns)
        self.assertIn("evidence_gate_status", incident_collaboration_columns)
        self.assertIn("action_contract_hash", incident_collaboration_columns)
        self.assertIn("evidence_refs_json", agent_work_item_columns)
        self.assertIn("event_hash", collaboration_event_columns)
        self.assertIn("prev_hash", collaboration_event_columns)
        with engine.connect() as connection:
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        self.assertEqual(revision, "0027_agent_collaboration")

    def test_existing_lab_baselines_are_isolated_during_scope_upgrade(self) -> None:
        command.upgrade(self.config, "0013_scenario_eval_scope")
        engine = create_engine(self.database_url, future=True)
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO config_baselines (
                        name, paths_json, snapshot_json, warnings_json, created_by, created_at
                    ) VALUES
                    (
                        '生产基线', '["/etc/hosts"]', '[]', '[]',
                        'admin', CURRENT_TIMESTAMP
                    ),
                    (
                        '评测基线', '["/tmp/opscouncil-lab/etc/managed-agent.conf"]',
                        '[]', '[]', 'opsbench', CURRENT_TIMESTAMP
                    )
                    """
                )
            )

        command.upgrade(self.config, "head")

        with engine.connect() as connection:
            rows = connection.execute(
                text("SELECT name, scope FROM config_baselines ORDER BY id")
            ).all()
        self.assertEqual(rows, [("生产基线", "LIVE"), ("评测基线", "LAB")])

    def test_existing_knowledge_is_backfilled_during_hybrid_index_upgrade(self) -> None:
        command.upgrade(self.config, "0004_patrol_incidents")
        engine = create_engine(self.database_url, future=True)
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO knowledge_documents (
                        title, source_type, source_uri, trust_level, content_hash, created_at
                    ) VALUES (
                        '数据库日志规范', 'runbook', 'manual://database-log', 'verified',
                        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', CURRENT_TIMESTAMP
                    )
                    """
                )
            )
            document_id = connection.execute(
                text("SELECT id FROM knowledge_documents WHERE title='数据库日志规范'")
            ).scalar_one()
            connection.execute(
                text(
                    """
                    INSERT INTO knowledge_chunks (
                        document_id, chunk_index, content, vector_id, embedding,
                        metadata_json, content_hash
                    ) VALUES (
                        :document_id, 0, '数据库 WAL 日志不得直接删除。', NULL, NULL,
                        '{}', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                    )
                    """
                ),
                {"document_id": document_id},
            )

        command.upgrade(self.config, "head")

        with engine.connect() as connection:
            document = connection.execute(
                text("SELECT version, status FROM knowledge_documents WHERE id=:id"),
                {"id": document_id},
            ).one()
            chunk = connection.execute(
                text("SELECT search_text, chunk_kind FROM knowledge_chunks WHERE document_id=:id"),
                {"id": document_id},
            ).one()
        self.assertEqual(tuple(document), (1, "ACTIVE"))
        self.assertIn("数据库", chunk.search_text.split())
        self.assertEqual(chunk.chunk_kind, "content")

    def test_existing_baseline_data_survives_async_runtime_upgrade(self) -> None:
        command.upgrade(self.config, "0001_existing_schema")
        engine = create_engine(self.database_url, future=True)
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO tasks (
                        trace_id, user_input, intent, status, risk_level,
                        created_at, updated_at
                    ) VALUES (
                        'trace-before-v3', '检查磁盘', 'disk_pressure_analysis',
                        'SEALED', 'R1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                    )
                    """
                )
            )

        command.upgrade(self.config, "head")

        with engine.connect() as connection:
            task = connection.execute(
                text("SELECT trace_id, user_input, status FROM tasks WHERE trace_id='trace-before-v3'")
            ).one()
            job_count = connection.execute(text("SELECT COUNT(*) FROM task_jobs")).scalar_one()
        self.assertEqual(tuple(task), ("trace-before-v3", "检查磁盘", "SEALED"))
        self.assertEqual(job_count, 0)

    def test_existing_async_runtime_data_survives_investigation_graph_upgrade(self) -> None:
        command.upgrade(self.config, "0002_async_task_runtime")
        engine = create_engine(self.database_url, future=True)
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO tasks (
                        trace_id, user_input, intent, status, risk_level,
                        created_at, updated_at
                    ) VALUES (
                        'trace-before-investigation', '检查服务状态', 'log_analysis',
                        'SEALED', 'R1', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                    )
                    """
                )
            )

        command.upgrade(self.config, "head")

        with engine.connect() as connection:
            task = connection.execute(
                text(
                    "SELECT trace_id, user_input, status FROM tasks "
                    "WHERE trace_id='trace-before-investigation'"
                )
            ).one()
            investigation_count = connection.execute(
                text("SELECT COUNT(*) FROM investigations")
            ).scalar_one()
        self.assertEqual(tuple(task), ("trace-before-investigation", "检查服务状态", "SEALED"))
        self.assertEqual(investigation_count, 0)

    def test_runtime_schema_check_fails_closed_on_old_revision(self) -> None:
        command.upgrade(self.config, "0001_existing_schema")
        engine = create_engine(self.database_url, future=True)

        with self.assertRaisesRegex(RuntimeError, "database schema is not current"):
            assert_schema_current(engine, script_location=PROJECT_ROOT / "migrations")

        command.upgrade(self.config, "head")
        assert_schema_current(engine, script_location=PROJECT_ROOT / "migrations")


if __name__ == "__main__":
    unittest.main()
