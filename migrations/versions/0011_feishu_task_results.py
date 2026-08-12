"""publish terminal Feishu task results

Revision ID: 0011_feishu_task_results
Revises: 0010_incident_hysteresis
Create Date: 2026-07-14 01:05:00.000000
"""
from typing import Sequence, Union

from alembic import op


revision: str = "0011_feishu_task_results"
down_revision: Union[str, Sequence[str], None] = "0010_incident_hysteresis"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


KINDS_WITH_TASK_RESULT = (
    "kind IN ('TASK_ACCEPTED', 'TASK_RESULT', 'INCIDENT', 'INVESTIGATION', "
    "'APPROVAL_REQUEST', 'EXECUTION', 'VERIFICATION', 'ROLLBACK', 'CHANNEL_NOTICE')"
)
KINDS_BEFORE_TASK_RESULT = (
    "kind IN ('TASK_ACCEPTED', 'INCIDENT', 'INVESTIGATION', 'APPROVAL_REQUEST', "
    "'EXECUTION', 'VERIFICATION', 'ROLLBACK', 'CHANNEL_NOTICE')"
)


def upgrade() -> None:
    with op.batch_alter_table("notification_outbox") as batch_op:
        batch_op.drop_constraint("ck_notification_outbox_kind", type_="check")
        batch_op.create_check_constraint("ck_notification_outbox_kind", KINDS_WITH_TASK_RESULT)


def downgrade() -> None:
    with op.batch_alter_table("notification_outbox") as batch_op:
        batch_op.drop_constraint("ck_notification_outbox_kind", type_="check")
        batch_op.create_check_constraint("ck_notification_outbox_kind", KINDS_BEFORE_TASK_RESULT)
