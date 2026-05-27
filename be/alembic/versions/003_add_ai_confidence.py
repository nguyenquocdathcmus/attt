"""add ai_confidence to findings

Revision ID: 003
Revises: 002
Create Date: 2026-05-26
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect, text

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(bind, table: str, column: str) -> bool:
    cols = [c["name"] for c in inspect(bind).get_columns(table)]
    return column in cols


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "findings", "ai_confidence"):
        op.add_column("findings", sa.Column("ai_confidence", sa.Float, nullable=True))
    if not _has_column(bind, "findings", "ai_confidence_tier"):
        op.add_column("findings", sa.Column("ai_confidence_tier", sa.String(10), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "ai_confidence_tier")
    op.drop_column("findings", "ai_confidence")
