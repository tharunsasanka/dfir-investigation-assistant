import enum
import uuid
from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    Field,
)

from app.models.log_ingestion import (
    LogEventSeverity,
)


class ForensicTimelineEntryType(
    str,
    enum.Enum,
):
    log_event = "log_event"
    security_finding = "security_finding"
    event_correlation = "event_correlation"
    case_audit = "case_audit"
    evidence_custody = "evidence_custody"


class ForensicTimelineSortOrder(
    str,
    enum.Enum,
):
    ascending = "ascending"
    descending = "descending"


class ForensicTimelineEntry(
    BaseModel,
):
    id: str
    case_id: uuid.UUID

    entry_type: ForensicTimelineEntryType

    occurred_at: datetime
    recorded_at: datetime

    title: str
    description: str

    severity: LogEventSeverity
    confidence: int | None = Field(
        default=None,
        ge=0,
        le=100,
    )

    source_id: uuid.UUID
    source_type: str

    evidence_id: uuid.UUID | None = None
    ingestion_job_id: uuid.UUID | None = None
    parsed_event_id: uuid.UUID | None = None
    security_finding_id: uuid.UUID | None = None
    correlation_id: uuid.UUID | None = None
    custody_event_id: uuid.UUID | None = None
    audit_event_id: uuid.UUID | None = None

    event_code: str
    rule_id: str

    host: str
    username: str
    process_name: str
    source_ip: str
    destination_ip: str

    actor_user_id: uuid.UUID | None = None
    actor_email: str
    actor_full_name: str

    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str

    correlation_type: str
    correlation_key: str

    details: dict[
        str,
        Any,
    ]


class ForensicTimelineTypeCount(
    BaseModel,
):
    entry_type: ForensicTimelineEntryType
    count: int = Field(
        ge=0,
    )


class ForensicTimelineSeverityCount(
    BaseModel,
):
    severity: LogEventSeverity
    count: int = Field(
        ge=0,
    )


class ForensicTimelineSummary(
    BaseModel,
):
    total_entries: int = Field(
        ge=0,
    )

    first_event_at: datetime | None
    last_event_at: datetime | None

    log_event_count: int = Field(
        ge=0,
    )

    security_finding_count: int = Field(
        ge=0,
    )

    event_correlation_count: int = Field(
        ge=0,
    )

    case_audit_count: int = Field(
        ge=0,
    )

    evidence_custody_count: int = Field(
        ge=0,
    )

    critical_count: int = Field(
        ge=0,
    )

    high_count: int = Field(
        ge=0,
    )

    evidence_count: int = Field(
        ge=0,
    )

    type_counts: list[
        ForensicTimelineTypeCount
    ]

    severity_counts: list[
        ForensicTimelineSeverityCount
    ]


class ForensicTimelineResponse(
    BaseModel,
):
    items: list[
        ForensicTimelineEntry
    ]

    summary: ForensicTimelineSummary

    total: int = Field(
        ge=0,
    )

    page: int = Field(
        ge=1,
    )

    page_size: int = Field(
        ge=1,
    )

    pages: int = Field(
        ge=0,
    )

    sort_order: ForensicTimelineSortOrder