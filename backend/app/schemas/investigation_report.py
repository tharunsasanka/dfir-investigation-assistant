import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import (
    BaseModel,
    Field,
    field_validator,
)

from app.schemas.investigation_summary import (
    InvestigationSummaryResponse,
)
from app.schemas.summary_traceability_response import (
    InvestigationSummaryTraceabilityResponse,
    SummaryTraceabilityIntegrityResponse,
)


class InvestigationReportFormat(
    str,
    Enum,
):
    pdf = "pdf"
    json = "json"


class InvestigationReportStatus(
    str,
    Enum,
):
    preparing = "preparing"
    completed = "completed"
    failed = "failed"


class InvestigationReportGenerationRequest(
    BaseModel,
):
    summary_id: uuid.UUID
    format: InvestigationReportFormat = (
        InvestigationReportFormat.pdf
    )
    include_traceability: bool = True
    include_integrity_verification: bool = True
    include_evidence_hashes: bool = True
    include_recommendations: bool = True
    include_assumptions: bool = True
    include_limitations: bool = True


class InvestigationReportCaseOverview(
    BaseModel,
):
    case_id: uuid.UUID
    title: str = Field(
        min_length=1,
        max_length=255,
    )
    description: str = Field(
        default="",
        max_length=20000,
    )
    severity: str = Field(
        min_length=1,
        max_length=50,
    )
    status: str = Field(
        min_length=1,
        max_length=50,
    )
    created_at: datetime
    updated_at: datetime

    @field_validator(
        "title",
        "severity",
        "status",
    )
    @classmethod
    def normalize_required_text(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Report case fields cannot be empty."
            )

        return normalized

    @field_validator(
        "description",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str,
    ) -> str:
        return value.strip()


class InvestigationReportAnalystReview(
    BaseModel,
):
    review_status: str = Field(
        min_length=1,
        max_length=50,
    )
    reviewed_by_user_id: uuid.UUID | None = None
    review_notes: str = Field(
        default="",
        max_length=20000,
    )
    reviewed_at: datetime | None = None
    analyst_approval_required: bool = True

    @field_validator(
        "review_status",
    )
    @classmethod
    def normalize_review_status(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Review status cannot be empty."
            )

        return normalized

    @field_validator(
        "review_notes",
    )
    @classmethod
    def normalize_review_notes(
        cls,
        value: str,
    ) -> str:
        return value.strip()


class InvestigationReportGenerationAudit(
    BaseModel,
):
    generation_source: str = Field(
        min_length=1,
        max_length=50,
    )
    provider_name: str = Field(
        min_length=1,
        max_length=100,
    )
    model_name: str = Field(
        default="",
        max_length=150,
    )
    prompt_template_version: str = Field(
        min_length=1,
        max_length=50,
    )
    source_snapshot_sha256: str = Field(
        min_length=64,
        max_length=64,
    )
    summary_output_sha256: str = Field(
        min_length=64,
        max_length=64,
    )
    generation_parameters: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict,
    )
    generation_started_at: datetime | None = None
    generation_completed_at: datetime | None = None


class InvestigationReportDocument(
    BaseModel,
):
    schema_version: str = Field(
        default="1.0.0",
        min_length=1,
        max_length=50,
    )
    report_id: uuid.UUID
    case: InvestigationReportCaseOverview
    summary: InvestigationSummaryResponse
    analyst_review: InvestigationReportAnalystReview
    generation_audit: InvestigationReportGenerationAudit
    traceability: (
        InvestigationSummaryTraceabilityResponse
        | None
    ) = None
    integrity: (
        SummaryTraceabilityIntegrityResponse
        | None
    ) = None
    generated_by_user_id: uuid.UUID | None = None
    generated_at: datetime
    report_sha256: str = Field(
        min_length=64,
        max_length=64,
    )


class InvestigationReportExportResult(
    BaseModel,
):
    report_id: uuid.UUID
    case_id: uuid.UUID
    summary_id: uuid.UUID
    format: InvestigationReportFormat
    status: InvestigationReportStatus
    filename: str = Field(
        min_length=1,
        max_length=255,
    )
    media_type: str = Field(
        min_length=1,
        max_length=100,
    )
    size_bytes: int = Field(
        ge=0,
    )
    document_sha256: str = Field(
        min_length=64,
        max_length=64,
    )
    generated_at: datetime