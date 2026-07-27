import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.summary_traceability import SummaryTraceabilityReport


class InvestigationSummaryTraceabilityResponse(
    SummaryTraceabilityReport
):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    investigation_summary_id: uuid.UUID
    case_id: uuid.UUID
    source_summary_output_sha256: str = Field(
        min_length=64,
        max_length=64,
    )
    created_at: datetime


class SummaryTraceabilityIntegrityResponse(BaseModel):
    report_id: uuid.UUID
    investigation_summary_id: uuid.UUID
    source_summary_output_sha256: str = Field(
        min_length=64,
        max_length=64,
    )
    stored_report_sha256: str = Field(
        min_length=64,
        max_length=64,
    )
    reconstructed_report_sha256: str = Field(
        min_length=64,
        max_length=64,
    )
    source_hash_matches: bool
    report_hash_matches: bool
    integrity_verified: bool
    verified_at: datetime