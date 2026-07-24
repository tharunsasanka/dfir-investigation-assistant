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
)


class SecurityFindingRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: uuid.UUID

    case_id: uuid.UUID
    evidence_id: uuid.UUID
    ingestion_job_id: uuid.UUID
    parsed_event_id: uuid.UUID

    event_index: int

    rule_id: str
    title: str
    description: str

    severity: LogEventSeverity

    confidence: int = Field(
        ge=0,
        le=100,
    )

    event_time: datetime | None

    event_code: str
    source_type: str

    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str

    indicators: dict[str, Any]

    created_at: datetime


class SecurityFindingListResponse(
    BaseModel
):
    items: list[SecurityFindingRead]

    total: int = Field(
        ge=0
    )

    page: int = Field(
        ge=1
    )

    page_size: int = Field(
        ge=1
    )

    pages: int = Field(
        ge=0
    )