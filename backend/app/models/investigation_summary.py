import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class InvestigationSummaryStatus(
    str,
    enum.Enum,
):
    generating = "generating"
    pending_review = "pending_review"
    approved = "approved"
    rejected = "rejected"
    failed = "failed"


class InvestigationSummarySource(
    str,
    enum.Enum,
):
    deterministic = "deterministic"
    local_ai = "local_ai"
    hosted_ai = "hosted_ai"
    analyst = "analyst"


class InvestigationSummary(Base):
    __tablename__ = "investigation_summaries"

    __table_args__ = (
        UniqueConstraint(
            "case_id",
            "version_number",
            name=(
                "uq_investigation_summaries_"
                "case_version"
            ),
        ),
        CheckConstraint(
            "version_number >= 1",
            name=(
                "ck_investigation_summaries_"
                "version_positive"
            ),
        ),
        CheckConstraint(
            "confidence_score >= 0 "
            "AND confidence_score <= 100",
            name=(
                "ck_investigation_summaries_"
                "confidence"
            ),
        ),
        Index(
            "ix_investigation_summaries_"
            "case_created_at",
            "case_id",
            "created_at",
        ),
        Index(
            "ix_investigation_summaries_"
            "case_status",
            "case_id",
            "status",
        ),
        Index(
            "ix_investigation_summaries_"
            "case_version",
            "case_id",
            "version_number",
        ),
        Index(
            "ix_investigation_summaries_"
            "provider_model",
            "provider_name",
            "model_name",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "cases.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    parent_summary_id: Mapped[
        uuid.UUID | None
    ] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "investigation_summaries.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    version_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    status: Mapped[
        InvestigationSummaryStatus
    ] = mapped_column(
        Enum(
            InvestigationSummaryStatus,
            name="investigationsummarystatus",
        ),
        default=(
            InvestigationSummaryStatus
            .generating
        ),
        nullable=False,
        index=True,
    )

    generation_source: Mapped[
        InvestigationSummarySource
    ] = mapped_column(
        Enum(
            InvestigationSummarySource,
            name="investigationsummarysource",
        ),
        default=(
            InvestigationSummarySource
            .deterministic
        ),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        default="Investigation Summary",
        nullable=False,
    )

    executive_summary: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    technical_narrative: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    technical_findings: Mapped[
        list[dict[str, Any]]
    ] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    incident_scope: Mapped[
        dict[str, Any]
    ] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    mitre_coverage: Mapped[
        dict[str, Any]
    ] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    evidence_references: Mapped[
        list[dict[str, Any]]
    ] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    recommended_actions: Mapped[
        list[dict[str, Any]]
    ] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    verified_facts: Mapped[
        list[dict[str, Any]]
    ] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    assumptions: Mapped[
        list[dict[str, Any]]
    ] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    limitations: Mapped[
        list[str]
    ] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    confidence_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        index=True,
    )

    provider_name: Mapped[str] = mapped_column(
        String(100),
        default="deterministic",
        nullable=False,
        index=True,
    )

    model_name: Mapped[str] = mapped_column(
        String(150),
        default="",
        nullable=False,
        index=True,
    )

    prompt_template_version: Mapped[str] = (
        mapped_column(
            String(50),
            default="1.0.0",
            nullable=False,
        )
    )

    generation_parameters: Mapped[
        dict[str, Any]
    ] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    source_snapshot: Mapped[
        dict[str, Any]
    ] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    source_snapshot_sha256: Mapped[str] = (
        mapped_column(
            String(64),
            default="",
            nullable=False,
            index=True,
        )
    )

    output_sha256: Mapped[str] = mapped_column(
        String(64),
        default="",
        nullable=False,
        index=True,
    )

    requested_by_user_id: Mapped[
        uuid.UUID | None
    ] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    reviewed_by_user_id: Mapped[
        uuid.UUID | None
    ] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    review_notes: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    generation_error: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    generation_started_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    generation_completed_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    reviewed_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(
            timezone.utc
        ),
        nullable=False,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(
            timezone.utc
        ),
        onupdate=lambda: datetime.now(
            timezone.utc
        ),
        nullable=False,
    )