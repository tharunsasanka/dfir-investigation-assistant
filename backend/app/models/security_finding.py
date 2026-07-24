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
from app.models.log_ingestion import (
    LogEventSeverity,
)


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    __table_args__ = (
        UniqueConstraint(
            "ingestion_job_id",
            "rule_id",
            "event_index",
            name=(
                "uq_security_findings_"
                "job_rule_event"
            ),
        ),
        CheckConstraint(
            "confidence >= 0 "
            "AND confidence <= 100",
            name=(
                "ck_security_findings_"
                "confidence"
            ),
        ),
        Index(
            "ix_security_findings_"
            "case_created_at",
            "case_id",
            "created_at",
        ),
        Index(
            "ix_security_findings_"
            "case_severity",
            "case_id",
            "severity",
        ),
        Index(
            "ix_security_findings_"
            "job_rule",
            "ingestion_job_id",
            "rule_id",
        ),
        Index(
            "ix_security_findings_"
            "evidence_created_at",
            "evidence_id",
            "created_at",
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

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "evidence.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    ingestion_job_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "log_ingestion_jobs.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    parsed_event_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "parsed_log_events.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    event_index: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    severity: Mapped[
        LogEventSeverity
    ] = mapped_column(
        Enum(
            LogEventSeverity,
            name="logeventseverity",
            create_type=False,
        ),
        default=LogEventSeverity.unknown,
        nullable=False,
        index=True,
    )

    confidence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        index=True,
    )

    event_time: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    event_code: Mapped[str] = mapped_column(
        String(100),
        default="",
        nullable=False,
        index=True,
    )

    source_type: Mapped[str] = mapped_column(
        String(100),
        default="unknown",
        nullable=False,
        index=True,
    )

    mitre_tactic: Mapped[str] = mapped_column(
        String(100),
        default="",
        nullable=False,
        index=True,
    )

    mitre_technique_id: Mapped[
        str
    ] = mapped_column(
        String(50),
        default="",
        nullable=False,
        index=True,
    )

    mitre_technique_name: Mapped[
        str
    ] = mapped_column(
        String(255),
        default="",
        nullable=False,
    )

    indicators: Mapped[
        dict[str, Any]
    ] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
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