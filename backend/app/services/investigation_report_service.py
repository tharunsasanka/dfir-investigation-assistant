import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.investigation_summary import InvestigationSummary
from app.schemas.investigation_report import (
    InvestigationReportAnalystReview,
    InvestigationReportCaseOverview,
    InvestigationReportDocument,
    InvestigationReportGenerationAudit,
    InvestigationReportGenerationRequest,
)
from app.schemas.investigation_summary import (
    InvestigationSummaryResponse,
)
from app.schemas.summary_traceability_response import (
    InvestigationSummaryTraceabilityResponse,
)
from app.services.summary_traceability_query_service import (
    get_investigation_summary_or_raise,
    get_summary_traceability_report_or_raise,
    get_traceability_case_or_raise,
    verify_summary_traceability_integrity,
)


class InvestigationReportError(Exception):
    pass


class InvestigationReportCaseMismatchError(
    InvestigationReportError
):
    pass


class InvestigationReportIntegrityError(
    InvestigationReportError
):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def enum_value(value: Any) -> str:
    if isinstance(value, Enum):
        return str(value.value)

    return str(value)


def calculate_sha256(value: Any) -> str:
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def normalize_sha256(
    value: str,
    field_name: str,
) -> str:
    normalized = value.strip().lower()

    if len(normalized) != 64:
        raise InvestigationReportIntegrityError(
            f"{field_name} must contain a valid SHA-256 hash."
        )

    try:
        int(normalized, 16)
    except ValueError as error:
        raise InvestigationReportIntegrityError(
            f"{field_name} must contain a valid SHA-256 hash."
        ) from error

    return normalized


def build_case_overview(
    investigation_case: Case,
) -> InvestigationReportCaseOverview:
    return InvestigationReportCaseOverview(
        case_id=investigation_case.id,
        title=investigation_case.title,
        description=investigation_case.description or "",
        severity=enum_value(
            investigation_case.severity
        ),
        status=enum_value(
            investigation_case.status
        ),
        created_at=investigation_case.created_at,
        updated_at=investigation_case.updated_at,
    )


def build_analyst_review(
    summary: InvestigationSummary,
) -> InvestigationReportAnalystReview:
    return InvestigationReportAnalystReview(
        review_status=enum_value(summary.status),
        reviewed_by_user_id=(
            summary.reviewed_by_user_id
        ),
        review_notes=summary.review_notes or "",
        reviewed_at=summary.reviewed_at,
        analyst_approval_required=True,
    )


def build_generation_audit(
    summary: InvestigationSummary,
) -> InvestigationReportGenerationAudit:
    return InvestigationReportGenerationAudit(
        generation_source=enum_value(
            summary.generation_source
        ),
        provider_name=summary.provider_name,
        model_name=summary.model_name or "",
        prompt_template_version=(
            summary.prompt_template_version
        ),
        source_snapshot_sha256=normalize_sha256(
            summary.source_snapshot_sha256,
            "Source snapshot hash",
        ),
        summary_output_sha256=normalize_sha256(
            summary.output_sha256,
            "Summary output hash",
        ),
        generation_parameters=(
            summary.generation_parameters or {}
        ),
        generation_started_at=(
            summary.generation_started_at
        ),
        generation_completed_at=(
            summary.generation_completed_at
        ),
    )


def build_report_hash_payload(
    report_id: uuid.UUID,
    case_overview: InvestigationReportCaseOverview,
    summary_response: InvestigationSummaryResponse,
    analyst_review: InvestigationReportAnalystReview,
    generation_audit: InvestigationReportGenerationAudit,
    traceability: (
        InvestigationSummaryTraceabilityResponse
        | None
    ),
    integrity: Any,
    generated_by_user_id: uuid.UUID | None,
    generated_at: datetime,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "report_id": str(report_id),
        "case": case_overview.model_dump(
            mode="json"
        ),
        "summary": summary_response.model_dump(
            mode="json"
        ),
        "analyst_review": analyst_review.model_dump(
            mode="json"
        ),
        "generation_audit": generation_audit.model_dump(
            mode="json"
        ),
        "traceability": (
            traceability.model_dump(mode="json")
            if traceability is not None
            else None
        ),
        "integrity": (
            integrity.model_dump(mode="json")
            if integrity is not None
            else None
        ),
        "generated_by_user_id": (
            str(generated_by_user_id)
            if generated_by_user_id is not None
            else None
        ),
        "generated_at": generated_at.isoformat(),
    }


def build_investigation_report_document(
    db: Session,
    request: InvestigationReportGenerationRequest,
    generated_by_user_id: uuid.UUID | None,
    generated_at: datetime | None = None,
) -> InvestigationReportDocument:
    summary = get_investigation_summary_or_raise(
        db,
        request.summary_id,
    )

    investigation_case = get_traceability_case_or_raise(
        db,
        summary.case_id,
    )

    if summary.case_id != investigation_case.id:
        raise InvestigationReportCaseMismatchError(
            "The selected investigation summary "
            "does not belong to the loaded case."
        )

    traceability = None

    if request.include_traceability:
        traceability_record = (
            get_summary_traceability_report_or_raise(
                db,
                summary.id,
            )
        )

        if (
            traceability_record.case_id
            != summary.case_id
        ):
            raise InvestigationReportCaseMismatchError(
                "The traceability report does not "
                "belong to the selected case."
            )

        traceability = (
            InvestigationSummaryTraceabilityResponse
            .model_validate(
                traceability_record
            )
        )

    integrity = None

    if request.include_integrity_verification:
        integrity = (
            verify_summary_traceability_integrity(
                db,
                summary.id,
            )
        )

    report_id = uuid.uuid4()
    timestamp = generated_at or utc_now()

    case_overview = build_case_overview(
        investigation_case
    )

    summary_response = (
        InvestigationSummaryResponse.model_validate(
            summary
        )
    )

    analyst_review = build_analyst_review(
        summary
    )

    generation_audit = build_generation_audit(
        summary
    )

    hash_payload = build_report_hash_payload(
        report_id=report_id,
        case_overview=case_overview,
        summary_response=summary_response,
        analyst_review=analyst_review,
        generation_audit=generation_audit,
        traceability=traceability,
        integrity=integrity,
        generated_by_user_id=(
            generated_by_user_id
        ),
        generated_at=timestamp,
    )

    return InvestigationReportDocument(
        schema_version="1.0.0",
        report_id=report_id,
        case=case_overview,
        summary=summary_response,
        analyst_review=analyst_review,
        generation_audit=generation_audit,
        traceability=traceability,
        integrity=integrity,
        generated_by_user_id=(
            generated_by_user_id
        ),
        generated_at=timestamp,
        report_sha256=calculate_sha256(
            hash_payload
        ),
    )