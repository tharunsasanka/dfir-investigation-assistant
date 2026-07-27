from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import (
    BaseModel,
    Field,
    field_validator,
)


class SummaryClaimSection(
    str,
    Enum,
):
    executive_summary = (
        "executive_summary"
    )

    technical_narrative = (
        "technical_narrative"
    )

    technical_finding = (
        "technical_finding"
    )

    incident_scope = (
        "incident_scope"
    )

    mitre_coverage = (
        "mitre_coverage"
    )

    recommended_action = (
        "recommended_action"
    )

    verified_fact = (
        "verified_fact"
    )

    assumption = "assumption"

    limitation = "limitation"


class SummaryCitationSourceType(
    str,
    Enum,
):
    case = "case"

    evidence = "evidence"

    parsed_log_event = (
        "parsed_log_event"
    )

    security_finding = (
        "security_finding"
    )

    event_correlation = (
        "event_correlation"
    )

    case_audit_event = (
        "case_audit_event"
    )

    evidence_custody_event = (
        "evidence_custody_event"
    )

    incident_scope = (
        "incident_scope"
    )

    mitre_mapping = (
        "mitre_mapping"
    )

    deterministic_rule = (
        "deterministic_rule"
    )

    analyst = "analyst"


class SummaryClaimSupportLevel(
    str,
    Enum,
):
    direct = "direct"
    derived = "derived"
    contextual = "contextual"
    unsupported = "unsupported"


class SummaryClaimCitation(
    BaseModel,
):
    citation_id: str = Field(
        min_length=1,
        max_length=100,
    )

    source_type: SummaryCitationSourceType

    source_id: str | None = Field(
        default=None,
        max_length=100,
    )

    evidence_id: str | None = Field(
        default=None,
        max_length=100,
    )

    label: str = Field(
        min_length=1,
        max_length=500,
    )

    relationship: str = Field(
        min_length=1,
        max_length=200,
    )

    event_time: datetime | None = (
        None
    )

    integrity_sha256: str | None = (
        Field(
            default=None,
            min_length=64,
            max_length=64,
        )
    )

    metadata: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict,
    )

    @field_validator(
        "citation_id",
        "label",
        "relationship",
    )
    @classmethod
    def normalize_required_text(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Citation text fields "
                "cannot be empty."
            )

        return normalized

    @field_validator(
        "source_id",
        "evidence_id",
        "integrity_sha256",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()

        return normalized or None


class SummaryTraceableClaim(
    BaseModel,
):
    claim_id: str = Field(
        min_length=1,
        max_length=100,
    )

    section: SummaryClaimSection

    ordinal: int = Field(
        ge=0,
    )

    text: str = Field(
        min_length=1,
        max_length=20000,
    )

    support_level: SummaryClaimSupportLevel

    supported: bool

    citations: list[
        SummaryClaimCitation
    ] = Field(
        default_factory=list,
        max_length=100,
    )

    unsupported_reason: str = Field(
        default="",
        max_length=2000,
    )

    @field_validator(
        "claim_id",
        "text",
    )
    @classmethod
    def normalize_claim_text(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Claim text fields cannot "
                "be empty."
            )

        return normalized

    @field_validator(
        "unsupported_reason",
    )
    @classmethod
    def normalize_reason(
        cls,
        value: str,
    ) -> str:
        return value.strip()


class SummaryTraceabilityReport(
    BaseModel,
):
    schema_version: str = Field(
        default="1.0.0",
        min_length=1,
        max_length=50,
    )

    claims: list[
        SummaryTraceableClaim
    ] = Field(
        default_factory=list,
        max_length=1000,
    )

    total_claim_count: int = Field(
        ge=0,
    )

    supported_claim_count: int = (
        Field(
            ge=0,
        )
    )

    unsupported_claim_count: int = (
        Field(
            ge=0,
        )
    )

    direct_support_count: int = (
        Field(
            ge=0,
        )
    )

    derived_support_count: int = (
        Field(
            ge=0,
        )
    )

    contextual_support_count: int = (
        Field(
            ge=0,
        )
    )

    citation_count: int = Field(
        ge=0,
    )

    generated_at: datetime

    report_sha256: str = Field(
        min_length=64,
        max_length=64,
    )