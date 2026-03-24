"""Drop legacy tag columns removed from the ORM."""

from __future__ import annotations

from alembic import op


revision = "20260324_0003"
down_revision = "20260324_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_functions_tags_gin", table_name="functions")
    op.drop_column("functions", "tags")
    op.drop_column("modules", "tags")


def downgrade() -> None:
    raise NotImplementedError("Downgrade is not supported for dropped tag columns.")
