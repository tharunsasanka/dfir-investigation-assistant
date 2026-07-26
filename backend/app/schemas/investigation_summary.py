import enum
import uuid
from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from app.models.investigation_summary import (
    InvestigationSummarySource,
    InvestigationSummaryStatus,
)
from app.models.log_ingestion import (
    LogEventSeverity,
)


class InvestigationSummaryReviewDecision(
    str,
    enum.Enum,
):
    approved = "approved"
    rejected = "rejected"


class InvestigationActionPriority(
    str,
    enum.Enum,
):
    immediate = "immediate"
    short_term = "short_term"
    long_term = "long_term"


class InvestigationSummaryFinding(
    BaseModel,
):
    title: str = Field(
        min_length=1,
        max_length=255,
    )

    description: str = Field(
        min_length=1,
    )

    severity: LogEventSeverity

    confidence: int = Field(
        ge=0,
        le=100,
    )

    rule_id: str = Field(
        default="",
        max_length=100,
    )

    event_time: datetime | None = None

    evidence_id: uuid.UUID | None = None
    parsed_event_id: uuid.UUID | None = None
    security_finding_id: uuid.UUID | None = None
    correlation_id: uuid.UUID | None = None

    event_code: str = Field(
        default="",
        max_length=100,
    )

    source_type: str = Field(
        default="unknown",
        max_length=100,
    )

    mitre_tactic: str = Field(
        default="",
        max_length=100,
    )

    mitre_technique_id: str = Field(
        default="",
        max_length=50,
    )

    mitre_technique_name: str = Field(
        default="",
        max_length=255,
    )

    indicators: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict,
    )


class InvestigationIncidentScope(
    BaseModel,
):
    total_timeline_entries: int = Field(
        default=0,
        ge=0,
    )

    log_event_count: int = Field(
        default=0,
        ge=0,
    )

    security_finding_count: int = Field(
        default=0,
        ge=0,
    )

    event_correlation_count: int = Field(
        default=0,
        ge=0,
    )

    case_audit_count: int = Field(
        default=0,
        ge=0,
    )

    evidence_custody_count: int = Field(
        default=0,
        ge=0,
    )

    evidence_count: int = Field(
        default=0,
        ge=0,
    )

    critical_count: int = Field(
        default=0,
        ge=0,
    )

    high_count: int = Field(
        default=0,
        ge=0,
    )

    first_activity_at: datetime | None = None
    last_activity_at: datetime | None = None

    affected_hosts: list[str] = Field(
        default_factory=list,
    )

    affected_usernames: list[str] = Field(
        default_factory=list,
    )

    observed_source_ips: list[str] = Field(
        default_factory=list,
    )

    observed_destination_ips: list[str] = Field(
        default_factory=list,
    )

    observed_processes: list[str] = Field(
        default_factory=list,
    )

    evidence_ids: list[
        uuid.UUID
    ] = Field(
        default_factory=list,
    )


class InvestigationMitreTechnique(
    BaseModel,
):
    tactic: str = Field(
        default="",
        max_length=100,
    )

    technique_id: str = Field(
        min_length=1,
        max_length=50,
    )

    technique_name: str = Field(
        default="",
        max_length=255,
    )

    finding_count: int = Field(
        default=0,
        ge=0,
    )

    correlation_count: int = Field(
        default=0,
        ge=0,
    )

    related_rule_ids: list[str] = Field(
        default_factory=list,
    )


class InvestigationMitreCoverage(
    BaseModel,
):
    tactic_count: int = Field(
        default=0,
        ge=0,
    )

    technique_count: int = Field(
        default=0,
        ge=0,
    )

    tactics: list[str] = Field(
        default_factory=list,
    )

    techniques: list[
        InvestigationMitreTechnique
    ] = Field(
        default_factory=list,
    )


class InvestigationEvidenceReference(
    BaseModel,
):
    evidence_id: uuid.UUID

    original_filename: str = Field(
        min_length=1,
        max_length=255,
    )

    evidence_type: str = Field(
        default="other",
        max_length=100,
    )

    sha256: str = Field(
        default="",
        max_length=64,
    )

    size_bytes: int = Field(
        default=0,
        ge=0,
    )

    source: str = Field(
        default="",
        max_length=500,
    )

    collected_at: datetime | None = None
    created_at: datetime | None = None

    related_event_count: int = Field(
        default=0,
        ge=0,
    )

    related_finding_count: int = Field(
        default=0,
        ge=0,
    )

    related_correlation_count: int = Field(
        default=0,
        ge=0,
    )


class InvestigationRecommendedAction(
    BaseModel,
):
    priority: InvestigationActionPriority

    title: str = Field(
        min_length=1,
        max_length=255,
    )

    description: str = Field(
        min_length=1,
    )

    rationale: str = Field(
        default="",
    )

    related_rule_ids: list[str] = Field(
        default_factory=list,
    )

    related_mitre_technique_ids: list[
        str
    ] = Field(
        default_factory=list,
    )

    related_evidence_ids: list[
        uuid.UUID
    ] = Field(
        default_factory=list,
    )


class InvestigationVerifiedFact(
    BaseModel,
):
    statement: str = Field(
        min_length=1,
    )

    source_type: str = Field(
        min_length=1,
        max_length=100,
    )

    source_ids: list[str] = Field(
        default_factory=list,
    )

    confidence: int = Field(
        default=100,
        ge=0,
        le=100,
    )


class InvestigationAssumption(
    BaseModel,
):
    statement: str = Field(
        min_length=1,
    )

    reason: str = Field(
        min_length=1,
    )

    confidence: int = Field(
        default=0,
        ge=0,
        le=100,
    )


class InvestigationSummaryGenerateRequest(
    BaseModel,
):
    generation_source: InvestigationSummarySource = (
        InvestigationSummarySource.deterministic
    )

    provider_name: str = Field(
        default="deterministic",
        min_length=1,
        max_length=100,
    )

    model_name: str = Field(
        default="",
        max_length=150,
    )

    prompt_template_version: str = Field(
        default="1.0.0",
        min_length=1,
        max_length=50,
    )

    generation_parameters: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict,
    )


class InvestigationSummaryReviewRequest(
    BaseModel,
):
    decision: InvestigationSummaryReviewDecision

    review_notes: str = Field(
        default="",
        max_length=5000,
    )


class InvestigationSummaryRevisionRequest(
    BaseModel,
):
    title: str = Field(
        min_length=1,
        max_length=255,
    )

    executive_summary: str = Field(
        min_length=1,
    )

    technical_narrative: str = Field(
        min_length=1,
    )

    technical_findings: list[
        InvestigationSummaryFinding
    ] = Field(
        default_factory=list,
    )

    incident_scope: InvestigationIncidentScope

    mitre_coverage: InvestigationMitreCoverage

    evidence_references: list[
        InvestigationEvidenceReference
    ] = Field(
        default_factory=list,
    )

    recommended_actions: list[
        InvestigationRecommendedAction
    ] = Field(
        default_factory=list,
    )

    verified_facts: list[
        InvestigationVerifiedFact
    ] = Field(
        default_factory=list,
    )

    assumptions: list[
        InvestigationAssumption
    ] = Field(
        default_factory=list,
    )

    limitations: list[str] = Field(
        default_factory=list,
    )

    confidence_score: int = Field(
        ge=0,
        le=100,
    )


class InvestigationSummaryResponse(
    BaseModel,
):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    case_id: uuid.UUID
    parent_summary_id: uuid.UUID | None

    version_number: int
    status: InvestigationSummaryStatus
    generation_source: InvestigationSummarySource

    title: str
    executive_summary: str
    technical_narrative: str

    technical_findings: list[
        InvestigationSummaryFinding
    ]

    incident_scope: InvestigationIncidentScope

    mitre_coverage: InvestigationMitreCoverage

    evidence_references: list[
        InvestigationEvidenceReference
    ]

    recommended_actions: list[
        InvestigationRecommendedAction
    ]

    verified_facts: list[
        InvestigationVerifiedFact
    ]

    assumptions: list[
        InvestigationAssumption
    ]

    limitations: list[str]

    confidence_score: int

    provider_name: str
    model_name: str
    prompt_template_version: str

    generation_parameters: dict[
        str,
        Any,
    ]

    source_snapshot: dict[
        str,
        Any,
    ]

    source_snapshot_sha256: str
    output_sha256: str

    requested_by_user_id: uuid.UUID | None
    reviewed_by_user_id: uuid.UUID | None

    review_notes: str
    generation_error: str

    generation_started_at: datetime | None
    generation_completed_at: datetime | None
    reviewed_at: datetime | None

    created_at: datetime
    updated_at: datetime


class InvestigationSummaryListResponse(
    BaseModel,
):
    items: list[
        InvestigationSummaryResponse
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