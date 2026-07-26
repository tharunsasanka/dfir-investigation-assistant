import uuid
from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from app.models.event_correlation import (
    EventCorrelationType,
)
from app.models.log_ingestion import (
    LogEventSeverity,
)


class EventCorrelationRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    case_id: uuid.UUID

    correlation_type: EventCorrelationType
    correlation_signature: str

    rule_id: str
    title: str
    description: str

    severity: LogEventSeverity
    confidence: int

    window_start: datetime | None
    window_end: datetime | None

    event_count: int
    evidence_count: int

    correlation_key: str

    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str

    matched_fields: dict[
        str,
        Any,
    ]

    created_at: datetime
    updated_at: datetime


class EventCorrelationMemberRead(
    BaseModel,
):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    correlation_id: uuid.UUID
    case_id: uuid.UUID
    evidence_id: uuid.UUID
    parsed_event_id: uuid.UUID

    event_time: datetime | None
    position: int
    relationship: str

    matched_values: dict[
        str,
        Any,
    ]

    created_at: datetime


class EventCorrelationMemberEventRead(
    BaseModel,
):
    membership_id: uuid.UUID
    parsed_event_id: uuid.UUID
    evidence_id: uuid.UUID

    event_time: datetime | None
    position: int
    relationship: str

    source_type: str
    event_code: str
    severity: LogEventSeverity

    host: str
    username: str
    process_name: str

    source_ip: str
    destination_ip: str

    message: str

    matched_values: dict[
        str,
        Any,
    ]


class EventCorrelationDetailRead(
    EventCorrelationRead,
):
    members: list[
        EventCorrelationMemberEventRead
    ]


class EventCorrelationListResponse(
    BaseModel,
):
    items: list[
        EventCorrelationRead
    ]

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


class EventCorrelationRunResponse(
    BaseModel,
):
    case_id: uuid.UUID

    correlations_created: int = Field(
        ge=0,
    )

    correlations_updated: int = Field(
        ge=0,
    )

    correlations_deleted: int = Field(
        ge=0,
    )

    events_analyzed: int = Field(
        ge=0,
    )

    evidence_analyzed: int = Field(
        ge=0,
    )