"""add audit_logs table

Revision ID: 002
Revises: 001
Create Date: 2026-05-26
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if "audit_logs" in inspect(bind).get_table_names():
        return

    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("username", sa.String(100), nullable=True),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("path", sa.String(2048), nullable=False),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("extra", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), index=True),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
