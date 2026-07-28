import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.schemas.investigation_report import (
    InvestigationReportAnalystReview,
    InvestigationReportCaseOverview,
    InvestigationReportDocument,
    InvestigationReportFormat,
    InvestigationReportGenerationAudit,
    InvestigationReportGenerationRequest,
)
from app.schemas.investigation_summary import (
    InvestigationSummaryResponse,
)
from app.schemas.summary_traceability_response import (
    InvestigationSummaryTraceabilityResponse,
    SummaryTraceabilityIntegrityResponse,
)
from app.services.investigation_report_export_service import (
    InvestigationReportFormatError,
    build_report_export_payload,
    build_report_filename,
    calculate_bytes_sha256,
    export_investigation_report_json,
    safe_filename_component,
    serialize_report_json,
)


BASE_TIME = datetime(
    2026,
    7,
    27,
    11,
    0,
    tzinfo=timezone.utc,
)

CASE_ID = uuid.uuid4()
SUMMARY_ID = uuid.uuid4()
REPORT_ID = uuid.uuid4()
TRACEABILITY_ID = uuid.uuid4()
USER_ID = uuid.uuid4()
EVIDENCE_ID = uuid.uuid4()


def make_summary_response():
    return InvestigationSummaryResponse(
        id=SUMMARY_ID,
        case_id=CASE_ID,
        parent_summary_id=None,
        version_number=3,
        status="approved",
        generation_source="deterministic",
        title="Investigation Summary",
        executive_summary=(
            "Suspicious activity was "
            "identified."
        ),
        technical_narrative=(
            "The investigation requires "
            "analyst validation."
        ),
        technical_findings=[],
        incident_scope={},
        mitre_coverage={},
        evidence_references=[
            {
                "evidence_id":
                    EVIDENCE_ID,
                "original_filename":
                    "windows-events.json",
                "sha256":
                    "a" * 64,
            }
        ],
        recommended_actions=[
            {
                "priority":
                    "short_term",
                "title":
                    "Review activity",
                "description":
                    "Review the recorded activity against the original evidence.",
                "rationale":
                    "The activity requires analyst validation.",
                "related_rule_ids":
                    [],
                "related_mitre_technique_ids":
                    [],
                "related_evidence_ids":
                    [
                        EVIDENCE_ID,
                    ],
            }
        ],
        verified_facts=[],
        assumptions=[
            {
                "statement":
                    "Timestamp is valid.",
                "reason":
                    "The source timestamp requires analyst validation.",
                "confidence":
                    80,
            }
        ],
        limitations=[
            "Additional evidence may be required."
        ],
        confidence_score=85,
        provider_name="deterministic",
        model_name="",
        prompt_template_version="1.0.0",
        generation_parameters={},
        source_snapshot={},
        source_snapshot_sha256=(
            "d" * 64
        ),
        output_sha256=(
            "c" * 64
        ),
        requested_by_user_id=(
            USER_ID
        ),
        reviewed_by_user_id=None,
        review_notes="",
        generation_error="",
        generation_started_at=(
            BASE_TIME
        ),
        generation_completed_at=(
            BASE_TIME
        ),
        reviewed_at=None,
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )

def make_traceability_response():
    return InvestigationSummaryTraceabilityResponse(
        id=TRACEABILITY_ID,
        investigation_summary_id=(
            SUMMARY_ID
        ),
        case_id=CASE_ID,
        schema_version="1.0.0",
        claims=[
            {
                "claim_id":
                    "claim-001",
                "section":
                    "technical_finding",
                "ordinal":
                    0,
                "text":
                    "Suspicious activity was identified.",
                "support_level":
                    "direct",
                "supported":
                    True,
                "citations": [
                    {
                        "citation_id":
                            "citation-001",
                        "source_type":
                            "evidence",
                        "source_id":
                            str(
                                EVIDENCE_ID
                            ),
                        "evidence_id":
                            str(
                                EVIDENCE_ID
                            ),
                        "label":
                            "windows-events.json",
                        "relationship":
                            "Supports the claim",
                        "event_time":
                            BASE_TIME,
                        "integrity_sha256":
                            "a" * 64,
                        "metadata":
                            {},
                    }
                ],
                "unsupported_reason":
                    "",
            }
        ],
        total_claim_count=1,
        supported_claim_count=1,
        unsupported_claim_count=0,
        direct_support_count=1,
        derived_support_count=0,
        contextual_support_count=0,
        citation_count=1,
        generated_at=BASE_TIME,
        report_sha256="b" * 64,
        source_summary_output_sha256=(
            "c" * 64
        ),
        created_at=BASE_TIME,
    )

def make_integrity_response():
    return SummaryTraceabilityIntegrityResponse(
        report_id=TRACEABILITY_ID,
        investigation_summary_id=SUMMARY_ID,
        source_summary_output_sha256=(
            "c" * 64
        ),
        stored_report_sha256=(
            "b" * 64
        ),
        reconstructed_report_sha256=(
            "b" * 64
        ),
        source_hash_matches=True,
        report_hash_matches=True,
        integrity_verified=True,
        verified_at=BASE_TIME,
    )


def make_document():
    return InvestigationReportDocument(
        schema_version="1.0.0",
        report_id=REPORT_ID,
        case=InvestigationReportCaseOverview(
            case_id=CASE_ID,
            title=(
                "Suspicious Endpoint Activity"
            ),
            description=(
                "Endpoint investigation."
            ),
            severity="high",
            status="investigating",
            created_at=BASE_TIME,
            updated_at=BASE_TIME,
        ),
        summary=make_summary_response(),
        analyst_review=(
            InvestigationReportAnalystReview(
                review_status=(
                    "pending_review"
                ),
                reviewed_by_user_id=None,
                review_notes="",
                reviewed_at=None,
                analyst_approval_required=True,
            )
        ),
        generation_audit=(
            InvestigationReportGenerationAudit(
                generation_source=(
                    "local_ai"
                ),
                provider_name="ollama",
                model_name="llama3.2",
                prompt_template_version=(
                    "1.0.0"
                ),
                source_snapshot_sha256=(
                    "d" * 64
                ),
                summary_output_sha256=(
                    "c" * 64
                ),
                generation_parameters={
                    "validation_passed":
                        True,
                },
                generation_started_at=(
                    BASE_TIME
                ),
                generation_completed_at=(
                    BASE_TIME
                ),
            )
        ),
        traceability=(
            make_traceability_response()
        ),
        integrity=(
            make_integrity_response()
        ),
        generated_by_user_id=USER_ID,
        generated_at=BASE_TIME,
        report_sha256="e" * 64,
    )


def test_calculate_bytes_sha256_is_deterministic():
    first_hash = calculate_bytes_sha256(
        b"investigation-report"
    )

    second_hash = calculate_bytes_sha256(
        b"investigation-report"
    )

    assert first_hash == second_hash
    assert len(first_hash) == 64


def test_safe_filename_component_sanitizes_text():
    result = safe_filename_component(
        " Suspicious Case: 01 / Windows "
    )

    assert result == (
        "Suspicious-Case-01-Windows"
    )


def test_safe_filename_component_uses_fallback():
    assert (
        safe_filename_component(
            "///"
        )
        == "investigation"
    )


def test_build_export_payload_applies_exclusions():
    request = (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
            format=(
                InvestigationReportFormat
                .json
            ),
            include_traceability=False,
            include_integrity_verification=False,
            include_evidence_hashes=False,
            include_recommendations=False,
            include_assumptions=False,
            include_limitations=False,
        )
    )

    payload = build_report_export_payload(
        document=make_document(),
        request=request,
    )

    assert payload["traceability"] is None
    assert payload["integrity"] is None

    assert (
        payload["summary"]
        ["recommended_actions"]
        == []
    )

    assert (
        payload["summary"]
        ["assumptions"]
        == []
    )

    assert (
        payload["summary"]
        ["limitations"]
        == []
    )

    evidence_reference = (
        payload["summary"]
        ["evidence_references"][0]
    )

    assert (
        "sha256"
        not in evidence_reference
    )


def test_build_export_payload_preserves_enabled_data():
    request = (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
            format=(
                InvestigationReportFormat
                .json
            ),
        )
    )

    payload = build_report_export_payload(
        document=make_document(),
        request=request,
    )

    assert payload["traceability"] is not None
    assert payload["integrity"] is not None

    assert (
        payload["summary"]
        ["evidence_references"][0]
        ["sha256"]
        == "a" * 64
    )

    citation = (
        payload["traceability"]
        ["claims"][0]
        ["citations"][0]
    )

    assert (
        citation["integrity_sha256"]
        == "a" * 64
    )


def test_serialize_report_json_returns_valid_bytes():
    content = serialize_report_json(
        {
            "report_id":
                str(REPORT_ID),
            "status":
                "completed",
        }
    )

    decoded = json.loads(
        content.decode("utf-8")
    )

    assert (
        decoded["report_id"]
        == str(REPORT_ID)
    )

    assert (
        decoded["status"]
        == "completed"
    )


def test_build_report_filename_uses_case_and_version():
    filename = build_report_filename(
        make_document()
    )

    assert filename.startswith(
        (
            "Suspicious-Endpoint-Activity-"
            "summary-v3-"
        )
    )

    assert filename.endswith(
        ".json"
    )


def test_json_export_rejects_pdf_format():
    db = MagicMock(
        spec=Session
    )

    request = (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
            format=(
                InvestigationReportFormat
                .pdf
            ),
        )
    )

    with pytest.raises(
        InvestigationReportFormatError,
        match="JSON exporter",
    ):
        export_investigation_report_json(
            db=db,
            request=request,
            generated_by_user_id=USER_ID,
            generated_at=BASE_TIME,
        )


def test_json_export_returns_artifact_and_metadata():
    db = MagicMock(
        spec=Session
    )

    document = make_document()

    request = (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
            format=(
                InvestigationReportFormat
                .json
            ),
        )
    )

    with patch(
        (
            "app.services."
            "investigation_report_export_service."
            "build_investigation_report_document"
        ),
        return_value=document,
    ) as build_mock:
        artifact = (
            export_investigation_report_json(
                db=db,
                request=request,
                generated_by_user_id=(
                    USER_ID
                ),
                generated_at=BASE_TIME,
            )
        )

    build_mock.assert_called_once_with(
        db=db,
        request=request,
        generated_by_user_id=(
            USER_ID
        ),
        generated_at=BASE_TIME,
    )

    assert artifact.content
    assert (
        artifact.result.report_id
        == REPORT_ID
    )

    assert (
        artifact.result.case_id
        == CASE_ID
    )

    assert (
        artifact.result.summary_id
        == SUMMARY_ID
    )

    assert (
        artifact.result.format
        == InvestigationReportFormat
        .json
    )

    assert (
        artifact.result.media_type
        == "application/json"
    )

    assert (
        artifact.result.size_bytes
        == len(artifact.content)
    )

    assert (
        artifact.result.document_sha256
        == calculate_bytes_sha256(
            artifact.content
        )
    )