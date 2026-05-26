"""add users table

Revision ID: 001
Revises:
Create Date: 2026-05-26
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    existing_tables = inspector.get_table_names()

    if "users" not in existing_tables:
        op.create_table(
            "users",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                      server_default=sa.text("gen_random_uuid()")),
            sa.Column("username", sa.String(100), nullable=False),
            sa.Column("hashed_password", sa.String(255), nullable=False),
            sa.Column("roles", postgresql.ARRAY(sa.String(50)), nullable=False,
                      server_default="{}"),
            sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now()),
        )

    existing_indexes = [idx["name"] for idx in inspector.get_indexes("users")] if "users" in existing_tables else []
    if "ix_users_username" not in existing_indexes:
        op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
