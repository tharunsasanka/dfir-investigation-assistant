import uuid
from datetime import (
    datetime,
    timezone,
)
from types import SimpleNamespace
from unittest.mock import (
    MagicMock,
    patch,
)

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.api.v1.investigation_reports import (
    export_investigation_report,
    raise_report_http_error,
)
from app.schemas.investigation_report import (
    InvestigationReportExportResult,
    InvestigationReportFormat,
    InvestigationReportGenerationRequest,
    InvestigationReportStatus,
)
from app.services.investigation_report_export_service import (
    InvestigationReportArtifact,
    InvestigationReportFormatError,
)
from app.services.investigation_report_service import (
    InvestigationReportCaseMismatchError,
    InvestigationReportError,
    InvestigationReportIntegrityError,
)
from app.services.summary_traceability_query_service import (
    InvestigationSummaryNotFoundError,
    SummaryTraceabilityReportNotFoundError,
)


BASE_TIME = datetime(
    2026,
    7,
    27,
    13,
    0,
    tzinfo=timezone.utc,
)

USER_ID = uuid.uuid4()
CASE_ID = uuid.uuid4()
SUMMARY_ID = uuid.uuid4()
REPORT_ID = uuid.uuid4()


def make_user():
    return SimpleNamespace(
        id=USER_ID,
        email="analyst@example.com",
    )


def make_request(
    report_format:
        InvestigationReportFormat,
):
    return (
        InvestigationReportGenerationRequest(
            summary_id=SUMMARY_ID,
            format=report_format,
        )
    )


def make_artifact(
    report_format:
        InvestigationReportFormat,
):
    if (
        report_format
        == InvestigationReportFormat.pdf
    ):
        content = (
            b"%PDF-1.4\n"
            b"investigation-report\n"
            b"%%EOF"
        )

        filename = (
            "investigation-report.pdf"
        )

        media_type = (
            "application/pdf"
        )

    else:
        content = (
            b'{"status":"completed"}'
        )

        filename = (
            "investigation-report.json"
        )

        media_type = (
            "application/json"
        )

    result = (
        InvestigationReportExportResult(
            report_id=REPORT_ID,
            case_id=CASE_ID,
            summary_id=SUMMARY_ID,
            format=report_format,
            status=(
                InvestigationReportStatus
                .completed
            ),
            filename=filename,
            media_type=media_type,
            size_bytes=len(content),
            document_sha256="a" * 64,
            generated_at=BASE_TIME,
        )
    )

    return InvestigationReportArtifact(
        content=content,
        result=result,
    )


def test_pdf_export_returns_download_response():
    db = MagicMock(
        spec=Session
    )

    request = make_request(
        InvestigationReportFormat.pdf
    )

    artifact = make_artifact(
        InvestigationReportFormat.pdf
    )

    with patch(
        (
            "app.api.v1."
            "investigation_reports."
            "export_investigation_report_pdf"
        ),
        return_value=artifact,
    ) as export_mock:
        response = (
            export_investigation_report(
                request=request,
                current_user=make_user(),
                db=db,
            )
        )

    export_mock.assert_called_once_with(
        db=db,
        request=request,
        generated_by_user_id=USER_ID,
    )

    assert (
        response.body
        == artifact.content
    )

    assert (
        response.media_type
        == "application/pdf"
    )

    assert (
        response.headers[
            "content-disposition"
        ]
        == (
            'attachment; filename="'
            'investigation-report.pdf"'
        )
    )

    assert (
        response.headers[
            "x-report-id"
        ]
        == str(REPORT_ID)
    )

    assert (
        response.headers[
            "x-case-id"
        ]
        == str(CASE_ID)
    )

    assert (
        response.headers[
            "x-summary-id"
        ]
        == str(SUMMARY_ID)
    )

    assert (
        response.headers[
            "x-report-format"
        ]
        == "pdf"
    )

    assert (
        response.headers[
            "x-document-sha256"
        ]
        == "a" * 64
    )


def test_json_export_returns_download_response():
    db = MagicMock(
        spec=Session
    )

    request = make_request(
        InvestigationReportFormat.json
    )

    artifact = make_artifact(
        InvestigationReportFormat.json
    )

    with patch(
        (
            "app.api.v1."
            "investigation_reports."
            "export_investigation_report_json"
        ),
        return_value=artifact,
    ) as export_mock:
        response = (
            export_investigation_report(
                request=request,
                current_user=make_user(),
                db=db,
            )
        )

    export_mock.assert_called_once_with(
        db=db,
        request=request,
        generated_by_user_id=USER_ID,
    )

    assert (
        response.body
        == artifact.content
    )

    assert (
        response.media_type
        == "application/json"
    )

    assert (
        response.headers[
            "content-disposition"
        ]
        == (
            'attachment; filename="'
            'investigation-report.json"'
        )
    )

    assert (
        response.headers[
            "x-report-format"
        ]
        == "json"
    )


@pytest.mark.parametrize(
    (
        "error",
        "expected_status",
    ),
    [
        (
            InvestigationSummaryNotFoundError(
                (
                    "Investigation summary "
                    "was not found."
                )
            ),
            404,
        ),
        (
            SummaryTraceabilityReportNotFoundError(
                (
                    "Traceability report "
                    "was not found."
                )
            ),
            404,
        ),
        (
            InvestigationReportFormatError(
                (
                    "Unsupported report "
                    "format."
                )
            ),
            400,
        ),
        (
            InvestigationReportCaseMismatchError(
                (
                    "Case references do "
                    "not match."
                )
            ),
            409,
        ),
        (
            InvestigationReportIntegrityError(
                (
                    "Report integrity "
                    "verification failed."
                )
            ),
            409,
        ),
        (
            InvestigationReportError(
                (
                    "Report generation "
                    "failed."
                )
            ),
            422,
        ),
    ],
)
def test_report_errors_map_to_http_status(
    error,
    expected_status,
):
    with pytest.raises(
        HTTPException
    ) as captured:
        raise_report_http_error(
            error
        )

    assert (
        captured.value.status_code
        == expected_status
    )

    assert (
        captured.value.detail
        == str(error)
    )


def test_export_converts_missing_summary_to_404():
    db = MagicMock(
        spec=Session
    )

    request = make_request(
        InvestigationReportFormat.pdf
    )

    with patch(
        (
            "app.api.v1."
            "investigation_reports."
            "export_investigation_report_pdf"
        ),
        side_effect=(
            InvestigationSummaryNotFoundError(
                (
                    "Investigation summary "
                    "was not found."
                )
            )
        ),
    ):
        with pytest.raises(
            HTTPException
        ) as captured:
            export_investigation_report(
                request=request,
                current_user=make_user(),
                db=db,
            )

    assert (
        captured.value.status_code
        == 404
    )


def test_export_converts_integrity_error_to_409():
    db = MagicMock(
        spec=Session
    )

    request = make_request(
        InvestigationReportFormat.json
    )

    with patch(
        (
            "app.api.v1."
            "investigation_reports."
            "export_investigation_report_json"
        ),
        side_effect=(
            InvestigationReportIntegrityError(
                (
                    "Report integrity "
                    "verification failed."
                )
            )
        ),
    ):
        with pytest.raises(
            HTTPException
        ) as captured:
            export_investigation_report(
                request=request,
                current_user=make_user(),
                db=db,
            )

    assert (
        captured.value.status_code
        == 409
    )


def test_unknown_error_is_reraised():
    error = RuntimeError(
        "Unexpected export failure"
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "Unexpected export failure"
        ),
    ):
        raise_report_http_error(
            error
        )