import uuid
from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from app.models.case import (
    CaseSeverity,
    CaseStatus,
)


class CaseCreate(BaseModel):
    title: str = Field(
        min_length=3,
        max_length=160,
    )
    description: str = Field(
        default="",
        max_length=5000,
    )
    severity: CaseSeverity = CaseSeverity.medium


class CaseUpdate(BaseModel):
    title: str | None = Field(
        default=None,
        min_length=3,
        max_length=160,
    )
    description: str | None = Field(
        default=None,
        max_length=5000,
    )
    severity: CaseSeverity | None = None
    status: CaseStatus | None = None

    @model_validator(mode="after")
    def validate_update_fields(
        self,
    ) -> "CaseUpdate":
        if not self.model_fields_set:
            raise ValueError(
                "At least one case field must be provided."
            )

        return self


class CaseRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    title: str
    description: str
    severity: CaseSeverity
    status: CaseStatus
    created_at: datetime
    updated_at: datetime


class CaseListResponse(BaseModel):
    items: list[CaseRead]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)