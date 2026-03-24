from __future__ import annotations

from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
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


class Function(TimestampMixin, Base):
    __tablename__ = "functions"
    __table_args__ = (
        UniqueConstraint("address", name="uq_functions_address"),
        Index("ix_functions_proposed_name", "proposed_name"),
        Index("ix_functions_original_symbol_name", "original_symbol_name"),
        Index("ix_functions_tags_gin", "tags", postgresql_using="gin"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    address: Mapped[int] = mapped_column(BigInteger, nullable=False)
    proposed_name: Mapped[str | None] = mapped_column(String(255))
    original_symbol_name: Mapped[str | None] = mapped_column(String(255))
    reconstructed_signature: Mapped[str | None] = mapped_column(Text)
    calling_convention: Mapped[str | None] = mapped_column(String(64))
    decompiled_pseudocode: Mapped[str | None] = mapped_column(Text)
    ai_generated_summary: Mapped[str | None] = mapped_column(Text)
    complexity_score: Mapped[float | None] = mapped_column(Numeric(10, 4))
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list, server_default=text("'{}'::text[]")
    )
    code_embedding: Mapped[list[float] | None] = mapped_column(Vector(1024))
    summary_embedding: Mapped[list[float] | None] = mapped_column(Vector(1024))

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
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_annotations_confidence"),
        CheckConstraint("version >= 1", name="ck_annotations_version"),
        Index("ix_annotations_target", "target_type", "target_id"),
        Index("ix_annotations_agent_target", "agent_id", "target_type", "target_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Numeric(3, 2), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    supersedes_id: Mapped[int | None] = mapped_column(ForeignKey("annotations.id", ondelete="SET NULL"))
    body: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    supersedes: Mapped["Annotation | None"] = relationship(
        remote_side="Annotation.id",
        back_populates="superseded_by",
        foreign_keys=[supersedes_id],
    )
    superseded_by: Mapped[list["Annotation"]] = relationship(back_populates="supersedes")


class CallGraphEdge(TimestampMixin, Base):
    __tablename__ = "call_graph_edges"
    __table_args__ = (
        UniqueConstraint(
            "caller_function_id",
            "callee_function_id",
            "call_site_address",
            name="uq_call_graph_edge_site",
        ),
        Index("ix_call_graph_edges_caller", "caller_function_id"),
        Index("ix_call_graph_edges_callee", "callee_function_id"),
        Index("ix_call_graph_edges_caller_callee", "caller_function_id", "callee_function_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    caller_function_id: Mapped[int] = mapped_column(
        ForeignKey("functions.id", ondelete="CASCADE"), nullable=False
    )
    callee_function_id: Mapped[int] = mapped_column(
        ForeignKey("functions.id", ondelete="CASCADE"), nullable=False
    )
    call_site_address: Mapped[int | None] = mapped_column(BigInteger)

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
        UniqueConstraint("name", name="uq_modules_name"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)", name="ck_modules_confidence"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    agent_id: Mapped[str | None] = mapped_column(String(255))
    confidence: Mapped[float | None] = mapped_column(Numeric(3, 2))
    provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list, server_default=text("'{}'::text[]")
    )


class DataType(TimestampMixin, Base):
    __tablename__ = "data_types"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('struct', 'enum', 'typedef')",
            name="ck_data_types_kind",
        ),
        Index("ix_data_types_kind_name", "kind", "name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    source_agent_id: Mapped[str | None] = mapped_column(String(255))
