import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class LogFormat(str, enum.Enum):
    auto = "auto"
    json = "json"
    json_lines = "json_lines"
    csv = "csv"
    syslog = "syslog"
    plain_text = "plain_text"


class LogIngestionStatus(str, enum.Enum):
    pending = "pending"
    processing = "processing"
    completed = "completed"
    completed_with_errors = "completed_with_errors"
    failed = "failed"


class LogEventSeverity(str, enum.Enum):
    unknown = "unknown"
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class LogIngestionJob(Base):
    __tablename__ = "log_ingestion_jobs"

    __table_args__ = (
        Index(
            "ix_log_ingestion_jobs_case_created_at",
            "case_id",
            "created_at",
        ),
        Index(
            "ix_log_ingestion_jobs_evidence_created_at",
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

    requested_format: Mapped[LogFormat] = mapped_column(
        Enum(
            LogFormat,
            name="logformat",
        ),
        default=LogFormat.auto,
        nullable=False,
    )

    detected_format: Mapped[LogFormat | None] = mapped_column(
        Enum(
            LogFormat,
            name="logformat",
            create_type=False,
        ),
        nullable=True,
    )

    status: Mapped[LogIngestionStatus] = mapped_column(
        Enum(
            LogIngestionStatus,
            name="logingestionstatus",
        ),
        default=LogIngestionStatus.pending,
        nullable=False,
        index=True,
    )

    parser_name: Mapped[str] = mapped_column(
        String(100),
        default="dfir-log-parser",
        nullable=False,
    )

    parser_version: Mapped[str] = mapped_column(
        String(50),
        default="1.0.0",
        nullable=False,
    )

    total_records: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    parsed_records: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    failed_records: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    processed_bytes: Mapped[int] = mapped_column(
        BigInteger,
        default=0,
        nullable=False,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class ParsedLogEvent(Base):
    __tablename__ = "parsed_log_events"

    __table_args__ = (
        Index(
            "ix_parsed_log_events_case_event_time",
            "case_id",
            "event_time",
        ),
        Index(
            "ix_parsed_log_events_evidence_index",
            "evidence_id",
            "event_index",
        ),
        Index(
            "ix_parsed_log_events_job_index",
            "ingestion_job_id",
            "event_index",
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

    ingestion_job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "log_ingestion_jobs.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    event_index: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    event_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    source_type: Mapped[str] = mapped_column(
        String(100),
        default="unknown",
        nullable=False,
        index=True,
    )

    event_code: Mapped[str] = mapped_column(
        String(100),
        default="",
        nullable=False,
        index=True,
    )

    severity: Mapped[LogEventSeverity] = mapped_column(
        Enum(
            LogEventSeverity,
            name="logeventseverity",
        ),
        default=LogEventSeverity.unknown,
        nullable=False,
        index=True,
    )

    host: Mapped[str] = mapped_column(
        String(255),
        default="",
        nullable=False,
        index=True,
    )

    username: Mapped[str] = mapped_column(
        String(255),
        default="",
        nullable=False,
        index=True,
    )

    process_name: Mapped[str] = mapped_column(
        String(500),
        default="",
        nullable=False,
        index=True,
    )

    source_ip: Mapped[str] = mapped_column(
        String(64),
        default="",
        nullable=False,
        index=True,
    )

    destination_ip: Mapped[str] = mapped_column(
        String(64),
        default="",
        nullable=False,
        index=True,
    )

    message: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    raw_event: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    normalized_event: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    parse_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )