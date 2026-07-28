import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy.orm import Session
from unittest.mock import MagicMock

from app.schemas.investigation_report import (
    InvestigationReportGenerationRequest,
)
from app.schemas.investigation_summary import (
    InvestigationSummaryResponse,
)
from app.schemas.summary_traceability_response import (
    InvestigationSummaryTraceabilityResponse,
    SummaryTraceabilityIntegrityResponse,
)
from app.services.investigation_report_service import (
    InvestigationReportCaseMismatchError,
    InvestigationReportIntegrityError,
    build_case_overview,
    build_generation_audit,
    build_investigation_report_document,
    calculate_sha256,
    normalize_sha256,
)


BASE_TIME = datetime(
    2026,
    7,
    27,
    10,
    0,
    tzinfo=timezone.utc,
)

CASE_ID = uuid.uuid4()
SUMMARY_ID = uuid.uuid4()
TRACEABILITY_ID = uuid.uuid4()
REPORT_ID = uuid.uuid4()
USER_ID = uuid.uuid4()


def make_case(
    case_id=CASE_ID,
):
    return SimpleNamespace(
        id=case_id,
        title="Suspicious endpoint activity",
        description=(
            "Investigation of suspicious "
            "endpoint behaviour."
        ),
        severity="high",
        status="investigating",
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )


def make_summary(
    case_id=CASE_ID,
):
    return SimpleNamespace(
        id=SUMMARY_ID,
        case_id=case_id,
        status="pending_review",
        generation_source="local_ai",
        provider_name="ollama",
        model_name="llama3.2",
        prompt_template_version="1.0.0",
        generation_parameters={
            "validation_passed": True,
            "fallback_applied": False,
        },
        source_snapshot_sha256="A" * 64,
        output_sha256="B" * 64,
        reviewed_by_user_id=None,
        review_notes="",
        reviewed_at=None,
        generation_started_at=BASE_TIME,
        generation_completed_at=BASE_TIME,
    )


def make_summary_response():
    return (
        InvestigationSummaryResponse
        .model_construct(
            id=SUMMARY_ID,
            case_id=CASE_ID,
            version_number=1,
            title="Investigation Summary",
        )
    )


def make_traceability_record(
    case_id=CASE_ID,
):
    return SimpleNamespace(
        id=TRACEABILITY_ID,
        investigation_summary_id=SUMMARY_ID,
        case_id=case_id,
    )


def make_traceability_response():
    return (
        InvestigationSummaryTraceabilityResponse
        .model_construct(
            id=TRACEABILITY_ID,
            investigation_summary_id=SUMMARY_ID,
            case_id=CASE_ID,
            schema_version="1.0.0",
            claims=[],
            total_claim_count=0,
            supported_claim_count=0,
            unsupported_claim_count=0,
            direct_support_count=0,
            derived_support_count=0,
            contextual_support_count=0,
            citation_count=0,
            generated_at=BASE_TIME,
            report_sha256="c" * 64,
            source_summary_output_sha256="b" * 64,
            created_at=BASE_TIME,
        )
    )


def make_integrity_response():
    return SummaryTraceabilityIntegrityResponse(
        report_id=TRACEABILITY_ID,
        investigation_summary_id=SUMMARY_ID,
        source_summary_output_sha256="b" * 64,
        stored_report_sha256="c" * 64,
        reconstructed_report_sha256="c" * 64,
        source_hash_matches=True,
        report_hash_matches=True,
        integrity_verified=True,
        verified_at=BASE_TIME,
    )


def test_calculate_sha256_is_deterministic():
    first_hash = calculate_sha256(
        {
            "case_id": str(CASE_ID),
            "summary_id": str(SUMMARY_ID),
        }
    )

    second_hash = calculate_sha256(
        {
            "summary_id": str(SUMMARY_ID),
            "case_id": str(CASE_ID),
        }
    )

    assert first_hash == second_hash
    assert len(first_hash) == 64


def test_normalize_sha256_lowercases_hash():
    result = normalize_sha256(
        "A" * 64,
        "Test hash",
    )

    assert result == "a" * 64


@pytest.mark.parametrize(
    "value",
    [
        "",
        "invalid",
        "g" * 64,
        "a" * 63,
        "a" * 65,
    ],
)
def test_normalize_sha256_rejects_invalid_values(
    value,
):
    with pytest.raises(
        InvestigationReportIntegrityError,
        match="valid SHA-256",
    ):
        normalize_sha256(
            value,
            "Test hash",
        )


def test_build_case_overview_maps_case_fields():
    overview = build_case_overview(
        make_case()
    )

    assert overview.case_id == CASE_ID
    assert (
        overview.title
        == "Suspicious endpoint activity"
    )
    assert overview.severity == "high"
    assert overview.status == "investigating"
    assert overview.created_at == BASE_TIME


def test_build_generation_audit_normalizes_hashes():
    audit = build_generation_audit(
        make_summary()
    )

    assert (
        audit.source_snapshot_sha256
        == "a" * 64
    )

    assert (
        audit.summary_output_sha256
        == "b" * 64
    )

    assert audit.provider_name == "ollama"
    assert audit.model_name == "llama3.2"


def test_build_report_document_includes_traceability():
    db = MagicMock(
        spec=Session
    )

    summary = make_summary()
    investigation_case = make_case()
    traceability_record = (
        make_traceability_record()
    )
    summary_response = (
        make_summary_response()
    )
    traceability_response = (
        make_traceability_response()
    )
    integrity_response = (
        make_integrity_response()
    )

    request = (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
            include_traceability=True,
            include_integrity_verification=True,
        )
    )

    with (
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_investigation_summary_or_raise"
            ),
            return_value=summary,
        ),
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_traceability_case_or_raise"
            ),
            return_value=investigation_case,
        ),
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_summary_traceability_"
                "report_or_raise"
            ),
            return_value=traceability_record,
        ),
        patch(
            (
                "app.services."
                "investigation_report_service."
                "verify_summary_traceability_"
                "integrity"
            ),
            return_value=integrity_response,
        ),
        patch.object(
            InvestigationSummaryResponse,
            "model_validate",
            return_value=summary_response,
        ),
        patch.object(
            InvestigationSummaryTraceabilityResponse,
            "model_validate",
            return_value=traceability_response,
        ),
        patch(
            (
                "app.services."
                "investigation_report_service."
                "uuid.uuid4"
            ),
            return_value=REPORT_ID,
        ),
    ):
        report = (
            build_investigation_report_document(
                db=db,
                request=request,
                generated_by_user_id=USER_ID,
                generated_at=BASE_TIME,
            )
        )

    assert report.report_id == REPORT_ID
    assert report.case.case_id == CASE_ID
    assert report.summary is summary_response
    assert (
        report.traceability
        is traceability_response
    )
    assert (
        report.integrity
        is integrity_response
    )
    assert (
        report.generated_by_user_id
        == USER_ID
    )
    assert report.generated_at == BASE_TIME
    assert len(report.report_sha256) == 64


def test_build_report_document_supports_optional_exclusions():
    db = MagicMock(
        spec=Session
    )

    summary = make_summary()
    investigation_case = make_case()
    summary_response = (
        make_summary_response()
    )

    request = (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
            include_traceability=False,
            include_integrity_verification=False,
        )
    )

    with (
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_investigation_summary_or_raise"
            ),
            return_value=summary,
        ),
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_traceability_case_or_raise"
            ),
            return_value=investigation_case,
        ),
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_summary_traceability_"
                "report_or_raise"
            )
        ) as traceability_mock,
        patch(
            (
                "app.services."
                "investigation_report_service."
                "verify_summary_traceability_"
                "integrity"
            )
        ) as integrity_mock,
        patch.object(
            InvestigationSummaryResponse,
            "model_validate",
            return_value=summary_response,
        ),
    ):
        report = (
            build_investigation_report_document(
                db=db,
                request=request,
                generated_by_user_id=None,
                generated_at=BASE_TIME,
            )
        )

    traceability_mock.assert_not_called()
    integrity_mock.assert_not_called()

    assert report.traceability is None
    assert report.integrity is None
    assert (
        report.generated_by_user_id
        is None
    )


def test_build_report_rejects_case_mismatch():
    db = MagicMock(
        spec=Session
    )

    summary = make_summary()
    investigation_case = make_case(
        uuid.uuid4()
    )

    request = (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
        )
    )

    with (
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_investigation_summary_or_raise"
            ),
            return_value=summary,
        ),
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_traceability_case_or_raise"
            ),
            return_value=investigation_case,
        ),
    ):
        with pytest.raises(
            InvestigationReportCaseMismatchError,
            match="does not belong",
        ):
            build_investigation_report_document(
                db=db,
                request=request,
                generated_by_user_id=USER_ID,
                generated_at=BASE_TIME,
            )


def test_build_report_rejects_traceability_case_mismatch():
    db = MagicMock(
        spec=Session
    )

    summary = make_summary()
    investigation_case = make_case()

    request = (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
            include_traceability=True,
            include_integrity_verification=False,
        )
    )

    with (
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_investigation_summary_or_raise"
            ),
            return_value=summary,
        ),
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_traceability_case_or_raise"
            ),
            return_value=investigation_case,
        ),
        patch(
            (
                "app.services."
                "investigation_report_service."
                "get_summary_traceability_"
                "report_or_raise"
            ),
            return_value=(
                make_traceability_record(
                    uuid.uuid4()
                )
            ),
        ),
    ):
        with pytest.raises(
            InvestigationReportCaseMismatchError,
            match="traceability report",
        ):
            build_investigation_report_document(
                db=db,
                request=request,
                generated_by_user_id=USER_ID,
                generated_at=BASE_TIME,
            )