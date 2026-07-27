import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.investigation_summary import InvestigationSummary
from app.models.summary_traceability import (
    InvestigationSummaryTraceabilityReport,
)
from app.schemas.summary_traceability_response import (
    SummaryTraceabilityIntegrityResponse,
)
from app.services.summary_traceability_persistence_service import (
    build_traceability_report_from_summary,
    normalize_sha256,
)


class SummaryTraceabilityQueryError(Exception):
    pass


class InvestigationSummaryNotFoundError(
    SummaryTraceabilityQueryError
):
    pass


class SummaryTraceabilityReportNotFoundError(
    SummaryTraceabilityQueryError
):
    pass


class SummaryTraceabilityCaseNotFoundError(
    SummaryTraceabilityQueryError
):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_investigation_summary_or_raise(
    db: Session,
    investigation_summary_id: uuid.UUID,
) -> InvestigationSummary:
    summary = db.scalar(
        select(InvestigationSummary).where(
            InvestigationSummary.id
            == investigation_summary_id
        )
    )

    if summary is None:
        raise InvestigationSummaryNotFoundError(
            "Investigation summary was not found."
        )

    return summary


def get_summary_traceability_report_or_raise(
    db: Session,
    investigation_summary_id: uuid.UUID,
) -> InvestigationSummaryTraceabilityReport:
    report = db.scalar(
        select(
            InvestigationSummaryTraceabilityReport
        ).where(
            InvestigationSummaryTraceabilityReport
            .investigation_summary_id
            == investigation_summary_id
        )
    )

    if report is None:
        raise SummaryTraceabilityReportNotFoundError(
            "Traceability report was not found."
        )

    return report


def get_traceability_case_or_raise(
    db: Session,
    case_id: uuid.UUID,
) -> Case:
    investigation_case = db.scalar(
        select(Case).where(
            Case.id == case_id
        )
    )

    if investigation_case is None:
        raise SummaryTraceabilityCaseNotFoundError(
            "Investigation case was not found."
        )

    return investigation_case


def get_summary_traceability_report(
    db: Session,
    investigation_summary_id: uuid.UUID,
) -> InvestigationSummaryTraceabilityReport:
    summary = get_investigation_summary_or_raise(
        db,
        investigation_summary_id,
    )

    report = (
        get_summary_traceability_report_or_raise(
            db,
            investigation_summary_id,
        )
    )

    if report.case_id != summary.case_id:
        raise SummaryTraceabilityQueryError(
            "Traceability report case reference "
            "does not match the investigation summary."
        )

    return report


def verify_summary_traceability_integrity(
    db: Session,
    investigation_summary_id: uuid.UUID,
) -> SummaryTraceabilityIntegrityResponse:
    summary = get_investigation_summary_or_raise(
        db,
        investigation_summary_id,
    )

    report = (
        get_summary_traceability_report_or_raise(
            db,
            investigation_summary_id,
        )
    )

    investigation_case = (
        get_traceability_case_or_raise(
            db,
            summary.case_id,
        )
    )

    reconstructed_report = (
        build_traceability_report_from_summary(
            summary,
            investigation_case,
        )
    )

    summary_output_sha256 = normalize_sha256(
        summary.output_sha256
    )

    stored_source_sha256 = normalize_sha256(
        report.source_summary_output_sha256
    )

    stored_report_sha256 = normalize_sha256(
        report.report_sha256
    )

    reconstructed_report_sha256 = (
        normalize_sha256(
            reconstructed_report.report_sha256
        )
    )

    source_hash_matches = (
        stored_source_sha256
        == summary_output_sha256
    )

    report_hash_matches = (
        stored_report_sha256
        == reconstructed_report_sha256
    )

    return SummaryTraceabilityIntegrityResponse(
        report_id=report.id,
        investigation_summary_id=summary.id,
        source_summary_output_sha256=(
            stored_source_sha256
        ),
        stored_report_sha256=(
            stored_report_sha256
        ),
        reconstructed_report_sha256=(
            reconstructed_report_sha256
        ),
        source_hash_matches=(
            source_hash_matches
        ),
        report_hash_matches=(
            report_hash_matches
        ),
        integrity_verified=(
            source_hash_matches
            and report_hash_matches
        ),
        verified_at=utc_now(),
    )