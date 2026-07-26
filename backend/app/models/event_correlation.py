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
from app.models.log_ingestion import (
    LogEventSeverity,
)


class EventCorrelationType(
    str,
    enum.Enum,
):
    shared_identity = "shared_identity"
    shared_network = "shared_network"
    shared_host = "shared_host"
    shared_process = "shared_process"
    authentication_sequence = (
        "authentication_sequence"
    )
    mitre_technique = "mitre_technique"
    temporal_cluster = "temporal_cluster"
    multi_indicator = "multi_indicator"


class EventCorrelation(Base):
    __tablename__ = "event_correlations"

    __table_args__ = (
        UniqueConstraint(
            "case_id",
            "correlation_signature",
            name=(
                "uq_event_correlations_"
                "case_signature"
            ),
        ),
        CheckConstraint(
            "confidence >= 0 "
            "AND confidence <= 100",
            name=(
                "ck_event_correlations_"
                "confidence"
            ),
        ),
        CheckConstraint(
            "event_count >= 2",
            name=(
                "ck_event_correlations_"
                "event_count"
            ),
        ),
        CheckConstraint(
            "evidence_count >= 1",
            name=(
                "ck_event_correlations_"
                "evidence_count"
            ),
        ),
        CheckConstraint(
            "window_end IS NULL "
            "OR window_start IS NULL "
            "OR window_end >= window_start",
            name=(
                "ck_event_correlations_"
                "window_order"
            ),
        ),
        Index(
            "ix_event_correlations_"
            "case_created_at",
            "case_id",
            "created_at",
        ),
        Index(
            "ix_event_correlations_"
            "case_severity",
            "case_id",
            "severity",
        ),
        Index(
            "ix_event_correlations_"
            "case_type",
            "case_id",
            "correlation_type",
        ),
        Index(
            "ix_event_correlations_"
            "case_window",
            "case_id",
            "window_start",
            "window_end",
        ),
        Index(
            "ix_event_correlations_"
            "case_rule",
            "case_id",
            "rule_id",
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

    correlation_type: Mapped[
        EventCorrelationType
    ] = mapped_column(
        Enum(
            EventCorrelationType,
            name="eventcorrelationtype",
        ),
        nullable=False,
        index=True,
    )

    correlation_signature: Mapped[
        str
    ] = mapped_column(
        String(64),
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
        default=0,
        nullable=False,
        index=True,
    )

    window_start: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    window_end: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    event_count: Mapped[int] = mapped_column(
        Integer,
        default=2,
        nullable=False,
    )

    evidence_count: Mapped[
        int
    ] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )

    correlation_key: Mapped[str] = mapped_column(
        String(500),
        default="",
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

    matched_fields: Mapped[
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

    updated_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(
            timezone.utc
        ),
        onupdate=lambda: datetime.now(
            timezone.utc
        ),
        nullable=False,
    )


class EventCorrelationMember(Base):
    __tablename__ = (
        "event_correlation_members"
    )

    __table_args__ = (
        UniqueConstraint(
            "correlation_id",
            "parsed_event_id",
            name=(
                "uq_event_correlation_"
                "members_event"
            ),
        ),
        CheckConstraint(
            "position >= 0",
            name=(
                "ck_event_correlation_"
                "members_position"
            ),
        ),
        Index(
            "ix_event_correlation_"
            "members_correlation_position",
            "correlation_id",
            "position",
        ),
        Index(
            "ix_event_correlation_"
            "members_case_event_time",
            "case_id",
            "event_time",
        ),
        Index(
            "ix_event_correlation_"
            "members_evidence_event_time",
            "evidence_id",
            "event_time",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    correlation_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "event_correlations.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
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

    evidence_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "evidence.id",
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

    event_time: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    position: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    relationship: Mapped[
        str
    ] = mapped_column(
        String(100),
        default="related_event",
        nullable=False,
        index=True,
    )

    matched_values: Mapped[
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