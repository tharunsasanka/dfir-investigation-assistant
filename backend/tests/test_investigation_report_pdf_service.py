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
from app.services.investigation_report_export_service import (
    InvestigationReportFormatError,
    calculate_bytes_sha256,
)
from app.services.investigation_report_pdf_service import (
    build_pdf_report_filename,
    export_investigation_report_pdf,
    format_datetime,
    format_identifier,
    normalize_text,
    render_investigation_report_pdf,
)


BASE_TIME = datetime(
    2026,
    7,
    27,
    12,
    0,
    tzinfo=timezone.utc,
)

CASE_ID = uuid.uuid4()
SUMMARY_ID = uuid.uuid4()
REPORT_ID = uuid.uuid4()
USER_ID = uuid.uuid4()
EVIDENCE_ID = uuid.uuid4()


def make_summary_response():
    return InvestigationSummaryResponse(
        id=SUMMARY_ID,
        case_id=CASE_ID,
        parent_summary_id=None,
        version_number=2,
        status="approved",
        generation_source="local_ai",
        title="Investigation Summary",
        executive_summary=(
            "Suspicious PowerShell activity "
            "was identified."
        ),
        technical_narrative=(
            "Windows event 4688 recorded a "
            "PowerShell process requiring "
            "analyst review."
        ),
        technical_findings=[
            {
                "title":
                    "Suspicious PowerShell activity",
                "description":
                    "A PowerShell process was recorded.",
                "severity":
                    "high",
                "confidence":
                    90,
                "rule_id":
                    "WINDOWS-POWERSHELL-001",
                "event_time":
                    BASE_TIME.isoformat(),
                "evidence_id":
                    str(EVIDENCE_ID),
                "parsed_event_id":
                    str(uuid.uuid4()),
                "security_finding_id":
                    str(uuid.uuid4()),
                "correlation_id":
                    str(uuid.uuid4()),
                "event_code":
                    "4688",
                "source_type":
                    "windows_event",
                "mitre_tactic":
                    "Execution",
                "mitre_technique_id":
                    "T1059.001",
                "mitre_technique_name":
                    "PowerShell",
                "indicators":
                    {},
            }
        ],
        incident_scope={
            "total_timeline_entries":
                12,
            "log_event_count":
                7,
            "security_finding_count":
                1,
            "event_correlation_count":
                1,
            "case_audit_count":
                1,
            "evidence_custody_count":
                1,
            "evidence_count":
                1,
            "critical_count":
                0,
            "high_count":
                1,
            "first_activity_at":
                BASE_TIME.isoformat(),
            "last_activity_at":
                BASE_TIME.isoformat(),
            "affected_hosts":
                ["WORKSTATION-01"],
            "affected_usernames":
                ["analyst@example.com"],
            "observed_source_ips":
                ["203.0.113.50"],
            "observed_destination_ips":
                ["192.0.2.20"],
            "observed_processes":
                ["powershell.exe"],
            "evidence_ids":
                [str(EVIDENCE_ID)],
        },
        mitre_coverage={
            "tactic_count":
                1,
            "technique_count":
                1,
            "tactics":
                ["Execution"],
            "techniques": [
                {
                    "tactic":
                        "Execution",
                    "technique_id":
                        "T1059.001",
                    "technique_name":
                        "PowerShell",
                    "finding_count":
                        1,
                    "correlation_count":
                        1,
                    "related_rule_ids": [
                        "WINDOWS-POWERSHELL-001"
                    ],
                }
            ],
        },
        evidence_references=[
            {
                "evidence_id":
                    str(EVIDENCE_ID),
                "original_filename":
                    "windows-events.json",
                "evidence_type":
                    "windows_event_log",
                "sha256":
                    "a" * 64,
                "size_bytes":
                    4096,
                "source":
                    "analyst_upload",
                "collected_at":
                    BASE_TIME.isoformat(),
                "created_at":
                    BASE_TIME.isoformat(),
                "related_event_count":
                    7,
                "related_finding_count":
                    1,
                "related_correlation_count":
                    1,
            }
        ],
        recommended_actions=[
            {
                "priority":
                    "immediate",
                "title":
                    "Review PowerShell activity",
                "description":
                    "Validate the recorded process.",
                "rationale":
                    "A high-severity finding exists.",
                "related_rule_ids": [
                    "WINDOWS-POWERSHELL-001"
                ],
                "related_mitre_technique_ids": [
                    "T1059.001"
                ],
                "related_evidence_ids": [
                    str(EVIDENCE_ID)
                ],
            }
        ],
        verified_facts=[
            {
                "statement":
                    "Event 4688 was recorded.",
                "source_type":
                    "parsed_log_event",
                "source_ids":
                    [str(uuid.uuid4())],
                "confidence":
                    100,
            }
        ],
        assumptions=[
            {
                "statement":
                    "The timestamp represents "
                    "observed activity.",
                "reason":
                    "No separate timestamp was "
                    "available.",
                "confidence":
                    80,
            }
        ],
        limitations=[
            "Automated findings require analyst validation."
        ],
        confidence_score=90,
        provider_name="ollama",
        model_name="llama3.2",
        prompt_template_version="1.0.0",
        generation_parameters={
            "validation_passed":
                True,
            "fallback_applied":
                False,
        },
        source_snapshot={},
        source_snapshot_sha256="b" * 64,
        output_sha256="c" * 64,
        requested_by_user_id=USER_ID,
        reviewed_by_user_id=USER_ID,
        review_notes="Validated by analyst.",
        generation_error="",
        generation_started_at=BASE_TIME,
        generation_completed_at=BASE_TIME,
        reviewed_at=BASE_TIME,
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )


def make_document():
    return InvestigationReportDocument(
        schema_version="1.0.0",
        report_id=REPORT_ID,
        case=InvestigationReportCaseOverview(
            case_id=CASE_ID,
            title="Suspicious PowerShell Activity",
            description=(
                "Investigation of suspicious "
                "endpoint activity."
            ),
            severity="high",
            status="investigating",
            created_at=BASE_TIME,
            updated_at=BASE_TIME,
        ),
        summary=make_summary_response(),
        analyst_review=(
            InvestigationReportAnalystReview(
                review_status="approved",
                reviewed_by_user_id=USER_ID,
                review_notes=(
                    "Validated by analyst."
                ),
                reviewed_at=BASE_TIME,
                analyst_approval_required=True,
            )
        ),
        generation_audit=(
            InvestigationReportGenerationAudit(
                generation_source="local_ai",
                provider_name="ollama",
                model_name="llama3.2",
                prompt_template_version="1.0.0",
                source_snapshot_sha256="b" * 64,
                summary_output_sha256="c" * 64,
                generation_parameters={
                    "validation_passed":
                        True,
                    "fallback_applied":
                        False,
                },
                generation_started_at=BASE_TIME,
                generation_completed_at=BASE_TIME,
            )
        ),
        traceability=None,
        integrity=None,
        generated_by_user_id=USER_ID,
        generated_at=BASE_TIME,
        report_sha256="d" * 64,
    )


def make_pdf_request():
    return InvestigationReportGenerationRequest(
        summary_id=SUMMARY_ID,
        format=InvestigationReportFormat.pdf,
        include_traceability=False,
        include_integrity_verification=False,
    )


def test_normalize_text_handles_common_values():
    assert normalize_text(None, "fallback") == "fallback"
    assert normalize_text(True) == "Yes"
    assert normalize_text(False) == "No"
    assert normalize_text(" test ") == "test"


def test_format_datetime_formats_iso_timestamp():
    result = format_datetime(
        BASE_TIME.isoformat()
    )

    assert result.startswith(
        "2026-07-27 12:00:00"
    )


def test_format_datetime_handles_missing_value():
    assert (
        format_datetime(None)
        == "Not recorded"
    )


def test_format_identifier_shortens_long_value():
    value = "a" * 64

    result = format_identifier(value)

    assert result.startswith("a" * 16)
    assert result.endswith("a" * 16)
    assert "..." in result


def test_build_pdf_report_filename():
    filename = build_pdf_report_filename(
        case_title=(
            "Suspicious PowerShell Activity"
        ),
        version_number=2,
        report_id=REPORT_ID,
    )

    assert filename.startswith(
        (
            "Suspicious-PowerShell-Activity-"
            "summary-v2-"
        )
    )

    assert filename.endswith(".pdf")


def test_render_pdf_returns_valid_pdf_bytes():
    document = make_document()

    payload = document.model_dump(
        mode="json"
    )

    content = render_investigation_report_pdf(
        payload
    )

    assert content.startswith(b"%PDF")
    assert b"%%EOF" in content[-2048:]
    assert len(content) > 1000


def test_render_pdf_supports_excluded_sections():
    document = make_document()

    payload = document.model_dump(
        mode="json"
    )

    payload["traceability"] = None
    payload["integrity"] = None

    payload["summary"][
        "recommended_actions"
    ] = []

    payload["summary"][
        "assumptions"
    ] = []

    payload["summary"][
        "limitations"
    ] = []

    content = render_investigation_report_pdf(
        payload
    )

    assert content.startswith(b"%PDF")
    assert len(content) > 1000


def test_pdf_export_rejects_json_format():
    db = MagicMock(spec=Session)

    request = (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
            format=(
                InvestigationReportFormat.json
            ),
        )
    )

    with pytest.raises(
        InvestigationReportFormatError,
        match="PDF exporter",
    ):
        export_investigation_report_pdf(
            db=db,
            request=request,
            generated_by_user_id=USER_ID,
            generated_at=BASE_TIME,
        )


def test_pdf_export_returns_artifact():
    db = MagicMock(spec=Session)

    document = make_document()
    pdf_content = (
        b"%PDF-1.4\n"
        b"test-report\n"
        b"%%EOF"
    )

    with (
        patch(
            (
                "app.services."
                "investigation_report_pdf_service."
                "build_investigation_report_document"
            ),
            return_value=document,
        ) as build_mock,
        patch(
            (
                "app.services."
                "investigation_report_pdf_service."
                "render_investigation_report_pdf"
            ),
            return_value=pdf_content,
        ) as render_mock,
    ):
        artifact = (
            export_investigation_report_pdf(
                db=db,
                request=make_pdf_request(),
                generated_by_user_id=USER_ID,
                generated_at=BASE_TIME,
            )
        )

    build_mock.assert_called_once()

    render_mock.assert_called_once()

    assert artifact.content == pdf_content

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
        == InvestigationReportFormat.pdf
    )

    assert (
        artifact.result.media_type
        == "application/pdf"
    )

    assert (
        artifact.result.size_bytes
        == len(pdf_content)
    )

    assert (
        artifact.result.document_sha256
        == calculate_bytes_sha256(
            pdf_content
        )
    )

    assert artifact.result.filename.endswith(
        ".pdf"
    )