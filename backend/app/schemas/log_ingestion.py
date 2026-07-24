import uuid
from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from app.models.log_ingestion import (
    LogEventSeverity,
    LogFormat,
    LogIngestionStatus,
)


class LogIngestionRequest(BaseModel):
    log_format: LogFormat = LogFormat.auto


class LogIngestionJobRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    case_id: uuid.UUID
    evidence_id: uuid.UUID

    requested_format: LogFormat
    detected_format: LogFormat | None
    status: LogIngestionStatus

    parser_name: str
    parser_version: str

    total_records: int
    parsed_records: int
    failed_records: int
    processed_bytes: int

    error_message: str | None
    requested_by_user_id: uuid.UUID | None

    started_at: datetime | None
    completed_at: datetime | None

    created_at: datetime
    updated_at: datetime


class LogIngestionJobHistoryItem(
    LogIngestionJobRead,
):
    evidence_filename: str
    requested_by_email: str | None = None


class LogIngestionJobListResponse(BaseModel):
    items: list[
        LogIngestionJobHistoryItem
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


class ParsedLogEventRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    case_id: uuid.UUID
    evidence_id: uuid.UUID
    ingestion_job_id: uuid.UUID

    event_index: int
    event_time: datetime | None

    source_type: str
    event_code: str
    severity: LogEventSeverity

    host: str
    username: str
    process_name: str

    source_ip: str
    destination_ip: str

    message: str

    raw_event: dict[str, Any]
    normalized_event: dict[
        str,
        Any,
    ]

    parse_error: str | None
    created_at: datetime


class ParsedLogEventListResponse(BaseModel):
    items: list[
        ParsedLogEventRead
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