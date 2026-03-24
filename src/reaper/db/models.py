from __future__ import annotations

from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from reaper.db.base import Base


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Target(TimestampMixin, Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("slug", name="uq_targets_slug"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    binary_path: Mapped[str | None] = mapped_column(Text)
    binary_sha256: Mapped[str | None] = mapped_column(String(64))
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    functions: Mapped[list["Function"]] = relationship(back_populates="target")
    annotations: Mapped[list["Annotation"]] = relationship(back_populates="target")
    call_graph_edges: Mapped[list["CallGraphEdge"]] = relationship(
        back_populates="target"
    )
    modules: Mapped[list["Module"]] = relationship(back_populates="target")
    data_types: Mapped[list["DataType"]] = relationship(back_populates="target")


class Function(TimestampMixin, Base):
    __tablename__ = "functions"
    __table_args__ = (
        UniqueConstraint("target_id", "address", name="uq_functions_target_address"),
        UniqueConstraint("id", "target_id", name="uq_functions_id_target"),
        Index("ix_functions_target_proposed_name", "target_id", "proposed_name"),
        Index(
            "ix_functions_target_original_symbol_name",
            "target_id",
            "original_symbol_name",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[int] = mapped_column(BigInteger, nullable=False)
    proposed_name: Mapped[str | None] = mapped_column(String(255))
    original_symbol_name: Mapped[str | None] = mapped_column(String(255))
    reconstructed_signature: Mapped[str | None] = mapped_column(Text)
    calling_convention: Mapped[str | None] = mapped_column(String(64))
    decompiled_pseudocode: Mapped[str | None] = mapped_column(Text)
    ai_generated_summary: Mapped[str | None] = mapped_column(Text)
    complexity_score: Mapped[float | None] = mapped_column(Numeric(10, 4))
    code_embedding: Mapped[list[float] | None] = mapped_column(Vector(1024))
    summary_embedding: Mapped[list[float] | None] = mapped_column(Vector(1024))

    target: Mapped[Target] = relationship(back_populates="functions")
    outgoing_edges: Mapped[list["CallGraphEdge"]] = relationship(
        back_populates="caller",
        foreign_keys="CallGraphEdge.caller_function_id",
        cascade="all, delete-orphan",
    )
    incoming_edges: Mapped[list["CallGraphEdge"]] = relationship(
        back_populates="callee",
        foreign_keys="CallGraphEdge.callee_function_id",
    )


class Annotation(TimestampMixin, Base):
    __tablename__ = "annotations"
    __table_args__ = (
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0", name="ck_annotations_confidence"
        ),
        CheckConstraint("version >= 1", name="ck_annotations_version"),
        Index("ix_annotations_subject", "subject_type", "subject_id"),
        Index(
            "ix_annotations_target_subject", "target_id", "subject_type", "subject_id"
        ),
        Index(
            "ix_annotations_agent_target_subject",
            "agent_id",
            "target_id",
            "subject_type",
            "subject_id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    subject_type: Mapped[str] = mapped_column(String(50), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Numeric(3, 2), nullable=False)
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    supersedes_id: Mapped[int | None] = mapped_column(
        ForeignKey("annotations.id", ondelete="SET NULL")
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    target: Mapped[Target] = relationship(back_populates="annotations")
    supersedes: Mapped["Annotation | None"] = relationship(
        remote_side="Annotation.id",
        back_populates="superseded_by",
        foreign_keys=[supersedes_id],
    )
    superseded_by: Mapped[list["Annotation"]] = relationship(
        back_populates="supersedes"
    )


class CallGraphEdge(TimestampMixin, Base):
    __tablename__ = "call_graph_edges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["caller_function_id", "target_id"],
            ["functions.id", "functions.target_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["callee_function_id", "target_id"],
            ["functions.id", "functions.target_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "target_id",
            "caller_function_id",
            "callee_function_id",
            "call_site_address",
            name="uq_call_graph_edge_target_site",
        ),
        Index("ix_call_graph_edges_target_caller", "target_id", "caller_function_id"),
        Index("ix_call_graph_edges_target_callee", "target_id", "callee_function_id"),
        Index(
            "ix_call_graph_edges_target_caller_callee",
            "target_id",
            "caller_function_id",
            "callee_function_id",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    caller_function_id: Mapped[int] = mapped_column(Integer, nullable=False)
    callee_function_id: Mapped[int] = mapped_column(Integer, nullable=False)
    call_site_address: Mapped[int | None] = mapped_column(BigInteger)

    target: Mapped[Target] = relationship(back_populates="call_graph_edges")
    caller: Mapped[Function] = relationship(
        back_populates="outgoing_edges",
        foreign_keys=[caller_function_id],
    )
    callee: Mapped[Function] = relationship(
        back_populates="incoming_edges",
        foreign_keys=[callee_function_id],
    )


class Module(TimestampMixin, Base):
    __tablename__ = "modules"
    __table_args__ = (
        UniqueConstraint("target_id", "name", name="uq_modules_target_name"),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)",
            name="ck_modules_confidence",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    agent_id: Mapped[str | None] = mapped_column(String(255))
    confidence: Mapped[float | None] = mapped_column(Numeric(3, 2))
    provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    target: Mapped[Target] = relationship(back_populates="modules")


class DataType(TimestampMixin, Base):
    __tablename__ = "data_types"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('struct', 'enum', 'typedef')",
            name="ck_data_types_kind",
        ),
        Index("ix_data_types_target_kind_name", "target_id", "kind", "name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    source_agent_id: Mapped[str | None] = mapped_column(String(255))
    target: Mapped[Target] = relationship(back_populates="data_types")
