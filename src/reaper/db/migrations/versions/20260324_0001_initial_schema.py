"""Initial database schema for reverse engineering analysis."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql


revision = "20260324_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "functions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("address", sa.BigInteger(), nullable=False),
        sa.Column("proposed_name", sa.String(length=255)),
        sa.Column("original_symbol_name", sa.String(length=255)),
        sa.Column("reconstructed_signature", sa.Text()),
        sa.Column("calling_convention", sa.String(length=64)),
        sa.Column("decompiled_pseudocode", sa.Text()),
        sa.Column("ai_generated_summary", sa.Text()),
        sa.Column("complexity_score", sa.Numeric(10, 4)),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column("code_embedding", Vector(dim=1024)),
        sa.Column("summary_embedding", Vector(dim=1024)),
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
        sa.UniqueConstraint("address", name="uq_functions_address"),
    )
    op.create_index(
        "ix_functions_original_symbol_name", "functions", ["original_symbol_name"]
    )
    op.create_index("ix_functions_proposed_name", "functions", ["proposed_name"])
    op.create_index(
        "ix_functions_tags_gin", "functions", ["tags"], postgresql_using="gin"
    )
    op.execute(
        "CREATE INDEX ix_functions_code_embedding_hnsw "
        "ON functions USING hnsw (code_embedding vector_cosine_ops)"
    )
    op.execute(
        "CREATE INDEX ix_functions_summary_embedding_hnsw "
        "ON functions USING hnsw (summary_embedding vector_cosine_ops)"
    )

    op.create_table(
        "annotations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_type", sa.String(length=50), nullable=False),
        sa.Column("target_id", sa.String(length=255), nullable=False),
        sa.Column("agent_id", sa.String(length=255), nullable=False),
        sa.Column("confidence", sa.Numeric(3, 2), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "supersedes_id",
            sa.Integer(),
            sa.ForeignKey("annotations.id", ondelete="SET NULL"),
        ),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text())),
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
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0", name="ck_annotations_confidence"
        ),
        sa.CheckConstraint("version >= 1", name="ck_annotations_version"),
    )
    op.create_index(
        "ix_annotations_agent_target",
        "annotations",
        ["agent_id", "target_type", "target_id"],
    )
    op.create_index(
        "ix_annotations_target", "annotations", ["target_type", "target_id"]
    )

    op.create_table(
        "call_graph_edges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "caller_function_id",
            sa.Integer(),
            sa.ForeignKey("functions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "callee_function_id",
            sa.Integer(),
            sa.ForeignKey("functions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("call_site_address", sa.BigInteger()),
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
        sa.UniqueConstraint(
            "caller_function_id",
            "callee_function_id",
            "call_site_address",
            name="uq_call_graph_edge_site",
        ),
    )
    op.create_index(
        "ix_call_graph_edges_callee", "call_graph_edges", ["callee_function_id"]
    )
    op.create_index(
        "ix_call_graph_edges_caller", "call_graph_edges", ["caller_function_id"]
    )
    op.create_index(
        "ix_call_graph_edges_caller_callee",
        "call_graph_edges",
        ["caller_function_id", "callee_function_id"],
    )

    op.create_table(
        "modules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("agent_id", sa.String(length=255)),
        sa.Column("confidence", sa.Numeric(3, 2)),
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
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
        sa.CheckConstraint(
            "confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)",
            name="ck_modules_confidence",
        ),
        sa.UniqueConstraint("name", name="uq_modules_name"),
    )

    op.create_table(
        "data_types",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column(
            "definition", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column("source_agent_id", sa.String(length=255)),
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
        sa.CheckConstraint(
            "kind IN ('struct', 'enum', 'typedef')", name="ck_data_types_kind"
        ),
    )
    op.create_index("ix_data_types_kind_name", "data_types", ["kind", "name"])


def downgrade() -> None:
    op.drop_index("ix_data_types_kind_name", table_name="data_types")
    op.drop_table("data_types")

    op.drop_table("modules")

    op.drop_index("ix_call_graph_edges_caller_callee", table_name="call_graph_edges")
    op.drop_index("ix_call_graph_edges_caller", table_name="call_graph_edges")
    op.drop_index("ix_call_graph_edges_callee", table_name="call_graph_edges")
    op.drop_table("call_graph_edges")

    op.drop_index("ix_annotations_target", table_name="annotations")
    op.drop_index("ix_annotations_agent_target", table_name="annotations")
    op.drop_table("annotations")

    op.drop_index("ix_functions_tags_gin", table_name="functions")
    op.drop_index("ix_functions_proposed_name", table_name="functions")
    op.drop_index("ix_functions_original_symbol_name", table_name="functions")
    op.execute("DROP INDEX IF EXISTS ix_functions_summary_embedding_hnsw")
    op.execute("DROP INDEX IF EXISTS ix_functions_code_embedding_hnsw")
    op.drop_table("functions")
