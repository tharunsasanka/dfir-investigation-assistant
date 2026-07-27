import uuid
from datetime import (
    datetime,
    timezone,
)
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from app.db.session import Base


class InvestigationSummaryTraceabilityReport(
    Base,
):
    __tablename__ = (
        "investigation_summary_"
        "traceability_reports"
    )

    __table_args__ = (
        UniqueConstraint(
            "investigation_summary_id",
            name=(
                "uq_investigation_summary_"
                "traceability_summary"
            ),
        ),
        CheckConstraint(
            "total_claim_count >= 0 "
            "AND supported_claim_count >= 0 "
            "AND unsupported_claim_count >= 0 "
            "AND direct_support_count >= 0 "
            "AND derived_support_count >= 0 "
            "AND contextual_support_count >= 0 "
            "AND citation_count >= 0",
            name=(
                "ck_investigation_summary_"
                "traceability_counts_nonnegative"
            ),
        ),
        CheckConstraint(
            "supported_claim_count + "
            "unsupported_claim_count = "
            "total_claim_count",
            name=(
                "ck_investigation_summary_"
                "traceability_claim_totals"
            ),
        ),
        CheckConstraint(
            "direct_support_count + "
            "derived_support_count + "
            "contextual_support_count = "
            "supported_claim_count",
            name=(
                "ck_investigation_summary_"
                "traceability_support_totals"
            ),
        ),
        CheckConstraint(
            "char_length("
            "source_summary_output_sha256"
            ") = 64 "
            "AND char_length("
            "report_sha256"
            ") = 64",
            name=(
                "ck_investigation_summary_"
                "traceability_hash_lengths"
            ),
        ),
        Index(
            "ix_investigation_summary_"
            "traceability_case_created_at",
            "case_id",
            "created_at",
        ),
        Index(
            "ix_investigation_summary_"
            "traceability_case_generated_at",
            "case_id",
            "generated_at",
        ),
    )

    id: Mapped[
        uuid.UUID
    ] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    investigation_summary_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "investigation_summaries.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    case_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "cases.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    schema_version: Mapped[
        str
    ] = mapped_column(
        String(50),
        default="1.0.0",
        nullable=False,
    )

    claims: Mapped[
        list[dict[str, Any]]
    ] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )

    total_claim_count: Mapped[
        int
    ] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    supported_claim_count: Mapped[
        int
    ] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    unsupported_claim_count: Mapped[
        int
    ] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    direct_support_count: Mapped[
        int
    ] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    derived_support_count: Mapped[
        int
    ] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    contextual_support_count: Mapped[
        int
    ] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    citation_count: Mapped[
        int
    ] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    source_summary_output_sha256: Mapped[
        str
    ] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    report_sha256: Mapped[
        str
    ] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    generated_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    created_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(
            timezone.utc
        ),
        nullable=False,
        index=True,
    )