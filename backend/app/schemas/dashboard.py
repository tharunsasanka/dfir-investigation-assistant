from datetime import datetime

from pydantic import BaseModel, Field


class DashboardCaseSummary(BaseModel):
    total_cases: int = Field(ge=0)
    active_cases: int = Field(ge=0)
    critical_active_cases: int = Field(ge=0)
    review_cases: int = Field(ge=0)
    closed_cases: int = Field(ge=0)
    latest_case_updated_at: datetime | None = None