"""Add targets table and scope analysis tables to targets."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260324_0002"
down_revision = "20260324_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slug", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255)),
        sa.Column("binary_path", sa.Text()),
        sa.Column("binary_sha256", sa.String(length=64)),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("slug", name="uq_targets_slug"),
    )

    op.execute(
        """
        INSERT INTO targets (id, slug, display_name)
        VALUES (1, 'legacy-default', 'Legacy Default Target')
        """
    )

    op.add_column("functions", sa.Column("target_id", sa.Integer(), nullable=True))
    op.execute("UPDATE functions SET target_id = 1")
    op.alter_column("functions", "target_id", nullable=False)
    op.create_foreign_key(
        "fk_functions_target_id_targets",
        "functions",
        "targets",
        ["target_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_unique_constraint(
        "uq_functions_id_target", "functions", ["id", "target_id"]
    )
    op.drop_constraint("uq_functions_address", "functions", type_="unique")
    op.create_unique_constraint(
        "uq_functions_target_address", "functions", ["target_id", "address"]
    )
    op.drop_index("ix_functions_proposed_name", table_name="functions")
    op.drop_index("ix_functions_original_symbol_name", table_name="functions")
    op.create_index(
        "ix_functions_target_proposed_name", "functions", ["target_id", "proposed_name"]
    )
    op.create_index(
        "ix_functions_target_original_symbol_name",
        "functions",
        ["target_id", "original_symbol_name"],
    )

    op.alter_column("annotations", "target_type", new_column_name="subject_type")
    op.alter_column("annotations", "target_id", new_column_name="subject_id")
    op.add_column("annotations", sa.Column("target_id", sa.Integer(), nullable=True))
    op.execute("UPDATE annotations SET target_id = 1")
    op.alter_column("annotations", "target_id", nullable=False)
    op.create_foreign_key(
        "fk_annotations_target_id_targets",
        "annotations",
        "targets",
        ["target_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_index("ix_annotations_target", table_name="annotations")
    op.drop_index("ix_annotations_agent_target", table_name="annotations")
    op.create_index(
        "ix_annotations_subject", "annotations", ["subject_type", "subject_id"]
    )
    op.create_index(
        "ix_annotations_target_subject",
        "annotations",
        ["target_id", "subject_type", "subject_id"],
    )
    op.create_index(
        "ix_annotations_agent_target_subject",
        "annotations",
        ["agent_id", "target_id", "subject_type", "subject_id"],
    )

    op.add_column("modules", sa.Column("target_id", sa.Integer(), nullable=True))
    op.execute("UPDATE modules SET target_id = 1")
    op.alter_column("modules", "target_id", nullable=False)
    op.create_foreign_key(
        "fk_modules_target_id_targets",
        "modules",
        "targets",
        ["target_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint("uq_modules_name", "modules", type_="unique")
    op.create_unique_constraint(
        "uq_modules_target_name", "modules", ["target_id", "name"]
    )

    op.add_column("data_types", sa.Column("target_id", sa.Integer(), nullable=True))
    op.execute("UPDATE data_types SET target_id = 1")
    op.alter_column("data_types", "target_id", nullable=False)
    op.create_foreign_key(
        "fk_data_types_target_id_targets",
        "data_types",
        "targets",
        ["target_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_index("ix_data_types_kind_name", table_name="data_types")
    op.create_index(
        "ix_data_types_target_kind_name", "data_types", ["target_id", "kind", "name"]
    )

    op.add_column(
        "call_graph_edges", sa.Column("target_id", sa.Integer(), nullable=True)
    )
    op.execute(
        """
        UPDATE call_graph_edges cge
        SET target_id = f.target_id
        FROM functions f
        WHERE cge.caller_function_id = f.id
        """
    )
    op.alter_column("call_graph_edges", "target_id", nullable=False)
    op.create_foreign_key(
        "fk_call_graph_edges_target_id_targets",
        "call_graph_edges",
        "targets",
        ["target_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint(
        "call_graph_edges_caller_function_id_fkey",
        "call_graph_edges",
        type_="foreignkey",
    )
    op.drop_constraint(
        "call_graph_edges_callee_function_id_fkey",
        "call_graph_edges",
        type_="foreignkey",
    )
    op.create_foreign_key(
        "fk_call_graph_edges_caller_target",
        "call_graph_edges",
        "functions",
        ["caller_function_id", "target_id"],
        ["id", "target_id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_call_graph_edges_callee_target",
        "call_graph_edges",
        "functions",
        ["callee_function_id", "target_id"],
        ["id", "target_id"],
        ondelete="CASCADE",
    )
    op.drop_constraint("uq_call_graph_edge_site", "call_graph_edges", type_="unique")
    op.create_unique_constraint(
        "uq_call_graph_edge_target_site",
        "call_graph_edges",
        ["target_id", "caller_function_id", "callee_function_id", "call_site_address"],
    )
    op.drop_index("ix_call_graph_edges_caller", table_name="call_graph_edges")
    op.drop_index("ix_call_graph_edges_callee", table_name="call_graph_edges")
    op.drop_index("ix_call_graph_edges_caller_callee", table_name="call_graph_edges")
    op.create_index(
        "ix_call_graph_edges_target_caller",
        "call_graph_edges",
        ["target_id", "caller_function_id"],
    )
    op.create_index(
        "ix_call_graph_edges_target_callee",
        "call_graph_edges",
        ["target_id", "callee_function_id"],
    )
    op.create_index(
        "ix_call_graph_edges_target_caller_callee",
        "call_graph_edges",
        ["target_id", "caller_function_id", "callee_function_id"],
    )

    op.execute(
        "SELECT setval(pg_get_serial_sequence('targets', 'id'), (SELECT MAX(id) FROM targets))"
    )


def downgrade() -> None:
    op.drop_index(
        "ix_call_graph_edges_target_caller_callee", table_name="call_graph_edges"
    )
    op.drop_index("ix_call_graph_edges_target_callee", table_name="call_graph_edges")
    op.drop_index("ix_call_graph_edges_target_caller", table_name="call_graph_edges")
    op.drop_constraint(
        "uq_call_graph_edge_target_site", "call_graph_edges", type_="unique"
    )
    op.drop_constraint(
        "fk_call_graph_edges_callee_target", "call_graph_edges", type_="foreignkey"
    )
    op.drop_constraint(
        "fk_call_graph_edges_caller_target", "call_graph_edges", type_="foreignkey"
    )
    op.drop_constraint(
        "fk_call_graph_edges_target_id_targets", "call_graph_edges", type_="foreignkey"
    )
    op.create_foreign_key(
        "call_graph_edges_caller_function_id_fkey",
        "call_graph_edges",
        "functions",
        ["caller_function_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "call_graph_edges_callee_function_id_fkey",
        "call_graph_edges",
        "functions",
        ["callee_function_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_unique_constraint(
        "uq_call_graph_edge_site",
        "call_graph_edges",
        ["caller_function_id", "callee_function_id", "call_site_address"],
    )
    op.create_index(
        "ix_call_graph_edges_caller", "call_graph_edges", ["caller_function_id"]
    )
    op.create_index(
        "ix_call_graph_edges_callee", "call_graph_edges", ["callee_function_id"]
    )
    op.create_index(
        "ix_call_graph_edges_caller_callee",
        "call_graph_edges",
        ["caller_function_id", "callee_function_id"],
    )
    op.drop_column("call_graph_edges", "target_id")

    op.drop_index("ix_data_types_target_kind_name", table_name="data_types")
    op.drop_constraint(
        "fk_data_types_target_id_targets", "data_types", type_="foreignkey"
    )
    op.create_index("ix_data_types_kind_name", "data_types", ["kind", "name"])
    op.drop_column("data_types", "target_id")

    op.drop_constraint("uq_modules_target_name", "modules", type_="unique")
    op.drop_constraint("fk_modules_target_id_targets", "modules", type_="foreignkey")
    op.create_unique_constraint("uq_modules_name", "modules", ["name"])
    op.drop_column("modules", "target_id")

    op.drop_index("ix_annotations_agent_target_subject", table_name="annotations")
    op.drop_index("ix_annotations_target_subject", table_name="annotations")
    op.drop_index("ix_annotations_subject", table_name="annotations")
    op.drop_constraint(
        "fk_annotations_target_id_targets", "annotations", type_="foreignkey"
    )
    op.drop_column("annotations", "target_id")
    op.alter_column("annotations", "subject_id", new_column_name="target_id")
    op.alter_column("annotations", "subject_type", new_column_name="target_type")
    op.create_index(
        "ix_annotations_target", "annotations", ["target_type", "target_id"]
    )
    op.create_index(
        "ix_annotations_agent_target",
        "annotations",
        ["agent_id", "target_type", "target_id"],
    )

    op.drop_index("ix_functions_target_original_symbol_name", table_name="functions")
    op.drop_index("ix_functions_target_proposed_name", table_name="functions")
    op.drop_constraint("uq_functions_target_address", "functions", type_="unique")
    op.drop_constraint("uq_functions_id_target", "functions", type_="unique")
    op.drop_constraint(
        "fk_functions_target_id_targets", "functions", type_="foreignkey"
    )
    op.create_unique_constraint("uq_functions_address", "functions", ["address"])
    op.create_index("ix_functions_proposed_name", "functions", ["proposed_name"])
    op.create_index(
        "ix_functions_original_symbol_name", "functions", ["original_symbol_name"]
    )
    op.drop_column("functions", "target_id")

    op.drop_table("targets")
