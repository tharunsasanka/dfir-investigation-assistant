import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.case_audit import CaseAuditEventType


class CaseAuditEventRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    case_id: uuid.UUID
    event_type: CaseAuditEventType

    actor_user_id: uuid.UUID | None
    actor_email: str
    actor_full_name: str

    changes: dict[str, Any]

    ip_address: str | None
    user_agent: str | None
    created_at: datetime


class CaseAuditEventListResponse(BaseModel):
    items: list[CaseAuditEventRead]

    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)