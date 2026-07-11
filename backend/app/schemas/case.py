import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from app.models.case import CaseSeverity, CaseStatus


class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=5000)
    severity: CaseSeverity = CaseSeverity.medium


class CaseRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    description: str
    severity: CaseSeverity
    status: CaseStatus
    created_at: datetime
    updated_at: datetime
