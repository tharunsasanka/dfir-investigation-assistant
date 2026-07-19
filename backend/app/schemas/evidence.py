import uuid
from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from app.models.evidence import (
    EvidenceCustodyEventType,
    EvidenceType,
)


class EvidenceRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    case_id: uuid.UUID

    original_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    evidence_type: EvidenceType

    description: str
    source: str
    collected_at: datetime | None

    uploaded_by_user_id: uuid.UUID | None

    created_at: datetime
    updated_at: datetime


class EvidenceListResponse(BaseModel):
    items: list[EvidenceRead]

    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)


class EvidenceCustodyEventRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    evidence_id: uuid.UUID
    event_type: EvidenceCustodyEventType

    actor_user_id: uuid.UUID | None
    actor_email: str
    actor_full_name: str

    details: dict[str, Any]

    ip_address: str | None
    user_agent: str | None
    created_at: datetime


class EvidenceCustodyEventListResponse(
    BaseModel
):
    items: list[EvidenceCustodyEventRead]

    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)


class EvidenceIntegrityResponse(BaseModel):
    evidence_id: uuid.UUID

    matches: bool

    expected_sha256: str
    actual_sha256: str

    expected_size_bytes: int
    actual_size_bytes: int

    checked_at: datetime