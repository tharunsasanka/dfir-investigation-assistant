import re
import uuid
from datetime import (
    datetime,
    timezone,
)

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.investigation_summary import (
    InvestigationSummary,
)
from app.models.summary_traceability import (
    InvestigationSummaryTraceabilityReport,
)
from app.schemas.investigation_summary import (
    InvestigationAssumption,
    InvestigationEvidenceReference,
    InvestigationIncidentScope,
    InvestigationMitreCoverage,
    InvestigationRecommendedAction,
    InvestigationSummaryFinding,
    InvestigationVerifiedFact,
)
from app.schemas.summary_traceability import (
    SummaryTraceabilityReport,
)
from app.services.summary_traceability_service import (
    build_summary_traceability_report,
)


SHA256_PATTERN = re.compile(
    r"^[a-fA-F0-9]{64}$"
)


class SummaryTraceabilityPersistenceError(
    Exception,
):
    pass


class SummaryTraceabilityIntegrityError(
    SummaryTraceabilityPersistenceError,
):
    pass


class SummaryTraceabilityCaseMismatchError(
    SummaryTraceabilityPersistenceError,
):
    pass


def utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def normalize_sha256(
    value: str,
) -> str:
    normalized = value.strip().lower()

    if not SHA256_PATTERN.fullmatch(
        normalized
    ):
        raise SummaryTraceabilityIntegrityError(
            "The investigation summary "
            "output hash is not a valid "
            "SHA-256 value."
        )

    return normalized


def resolve_report_timestamp(
    summary: InvestigationSummary,
) -> datetime:
    return (
        summary.generation_completed_at
        or summary.updated_at
        or summary.created_at
        or utc_now()
    )


def build_traceability_report_from_summary(
    summary: InvestigationSummary,
    investigation_case: Case,
) -> SummaryTraceabilityReport:
    if (
        summary.case_id
        != investigation_case.id
    ):
        raise (
            SummaryTraceabilityCaseMismatchError(
                "The investigation summary "
                "does not belong to the "
                "provided case."
            )
        )

    findings = [
        InvestigationSummaryFinding
        .model_validate(item)
        for item
        in summary.technical_findings
    ]

    scope = (
        InvestigationIncidentScope
        .model_validate(
            summary.incident_scope
        )
    )

    mitre_coverage = (
        InvestigationMitreCoverage
        .model_validate(
            summary.mitre_coverage
        )
    )

    evidence_references = [
        InvestigationEvidenceReference
        .model_validate(item)
        for item
        in summary.evidence_references
    ]

    recommended_actions = [
        InvestigationRecommendedAction
        .model_validate(item)
        for item
        in summary.recommended_actions
    ]

    verified_facts = [
        InvestigationVerifiedFact
        .model_validate(item)
        for item
        in summary.verified_facts
    ]

    assumptions = [
        InvestigationAssumption
        .model_validate(item)
        for item
        in summary.assumptions
    ]

    limitations = [
        str(item).strip()
        for item
        in summary.limitations
        if str(item).strip()
    ]

    return build_summary_traceability_report(
        investigation_case=(
            investigation_case
        ),
        executive_summary=(
            summary.executive_summary
        ),
        technical_narrative=(
            summary.technical_narrative
        ),
        findings=findings,
        scope=scope,
        mitre_coverage=(
            mitre_coverage
        ),
        evidence_references=(
            evidence_references
        ),
        recommended_actions=(
            recommended_actions
        ),
        verified_facts=(
            verified_facts
        ),
        assumptions=assumptions,
        limitations=limitations,
        generated_at=(
            resolve_report_timestamp(
                summary
            )
        ),
    )


def get_traceability_report_record(
    db: Session,
    investigation_summary_id:
        uuid.UUID,
) -> (
    InvestigationSummaryTraceabilityReport
    | None
):
    return db.scalar(
        select(
            InvestigationSummaryTraceabilityReport
        ).where(
            InvestigationSummaryTraceabilityReport
            .investigation_summary_id
            == investigation_summary_id
        )
    )


def verify_existing_report_integrity(
    existing:
        InvestigationSummaryTraceabilityReport,
    source_summary_output_sha256: str,
    generated_report:
        SummaryTraceabilityReport,
) -> None:
    existing_source_hash = (
        existing
        .source_summary_output_sha256
        .strip()
        .lower()
    )

    existing_report_hash = (
        existing.report_sha256
        .strip()
        .lower()
    )

    if (
        existing_source_hash
        != source_summary_output_sha256
    ):
        raise SummaryTraceabilityIntegrityError(
            "The existing traceability "
            "report references a different "
            "summary output hash."
        )

    if (
        existing_report_hash
        != generated_report
        .report_sha256
        .lower()
    ):
        raise SummaryTraceabilityIntegrityError(
            "The existing traceability "
            "report does not match the "
            "deterministically reconstructed "
            "report."
        )


def persist_summary_traceability_report(
    db: Session,
    summary: InvestigationSummary,
    investigation_case: Case,
) -> (
    InvestigationSummaryTraceabilityReport
):
    source_summary_output_sha256 = (
        normalize_sha256(
            summary.output_sha256
        )
    )

    generated_report = (
        build_traceability_report_from_summary(
            summary,
            investigation_case,
        )
    )

    existing = (
        get_traceability_report_record(
            db,
            summary.id,
        )
    )

    if existing is not None:
        verify_existing_report_integrity(
            existing=existing,
            source_summary_output_sha256=(
                source_summary_output_sha256
            ),
            generated_report=(
                generated_report
            ),
        )

        return existing

    record = (
        InvestigationSummaryTraceabilityReport(
            investigation_summary_id=(
                summary.id
            ),
            case_id=summary.case_id,
            schema_version=(
                generated_report
                .schema_version
            ),
            claims=[
                claim.model_dump(
                    mode="json"
                )
                for claim
                in generated_report.claims
            ],
            total_claim_count=(
                generated_report
                .total_claim_count
            ),
            supported_claim_count=(
                generated_report
                .supported_claim_count
            ),
            unsupported_claim_count=(
                generated_report
                .unsupported_claim_count
            ),
            direct_support_count=(
                generated_report
                .direct_support_count
            ),
            derived_support_count=(
                generated_report
                .derived_support_count
            ),
            contextual_support_count=(
                generated_report
                .contextual_support_count
            ),
            citation_count=(
                generated_report
                .citation_count
            ),
            source_summary_output_sha256=(
                source_summary_output_sha256
            ),
            report_sha256=(
                generated_report
                .report_sha256
                .lower()
            ),
            generated_at=(
                generated_report
                .generated_at
            ),
        )
    )

    db.add(record)
    db.flush()

    return record