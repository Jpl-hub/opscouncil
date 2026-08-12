from __future__ import annotations

from backend.app.channels.feishu.redaction import (
    NotificationPayloadRejectedError,
    assert_safe_notification_payload,
    redact_text,
)


def test_redaction_removes_credentials_paths_and_multiline_log_content() -> None:
    raw = (
        "sshd failed reading /etc/ssh/sshd_config\n"
        "password=fixture-only-password token: sk-fixture-only Authorization: Bearer abc.def"
    )

    redacted = redact_text(raw)

    assert "/etc/ssh" not in redacted
    assert "fixture-only-password" not in redacted
    assert "sk-fixture-only" not in redacted
    assert "abc.def" not in redacted
    assert "\n" not in redacted
    assert "[受保护路径]" in redacted
    assert "[已脱敏]" in redacted


def test_payload_guard_rejects_prohibited_fields_at_any_depth() -> None:
    assert_safe_notification_payload(
        {
            "schema_version": 1,
            "title": "调查完成",
            "summary": "服务恢复正常。",
            "task_id": 7,
        }
    )

    try:
        assert_safe_notification_payload(
            {
                "title": "bad",
                "nested": {"tool_output": {"observations": ["raw"]}},
            }
        )
    except NotificationPayloadRejectedError as exc:
        assert "tool_output" in str(exc)
    else:
        raise AssertionError("raw tool output must never enter notification payloads")
