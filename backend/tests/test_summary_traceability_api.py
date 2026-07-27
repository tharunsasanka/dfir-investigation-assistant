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

from app.api.v1.summary_traceability import (
    raise_traceability_http_error,
    read_summary_traceability,
    read_summary_traceability_integrity,
)
from app.services.summary_traceability_persistence_service import (
    SummaryTraceabilityIntegrityError,
)
from app.services.summary_traceability_query_service import (
    InvestigationSummaryNotFoundError,
    SummaryTraceabilityCaseNotFoundError,
    SummaryTraceabilityQueryError,
    SummaryTraceabilityReportNotFoundError,
)


SUMMARY_ID = uuid.uuid4()
REPORT_ID = uuid.uuid4()
CASE_ID = uuid.uuid4()


def make_user():
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="analyst@example.com",
    )


def make_report():
    return SimpleNamespace(
        id=REPORT_ID,
        investigation_summary_id=SUMMARY_ID,
        case_id=CASE_ID,
    )


def make_integrity_result():
    return SimpleNamespace(
        report_id=REPORT_ID,
        investigation_summary_id=SUMMARY_ID,
        source_summary_output_sha256=(
            "a" * 64
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
        verified_at=datetime.now(
            timezone.utc
        ),
    )


def test_read_summary_traceability_returns_report():
    db = MagicMock(
        spec=Session
    )

    current_user = make_user()
    report = make_report()

    with patch(
        (
            "app.api.v1."
            "summary_traceability."
            "get_summary_traceability_report"
        ),
        return_value=report,
    ) as query_mock:
        result = read_summary_traceability(
            summary_id=SUMMARY_ID,
            _current_user=current_user,
            db=db,
        )

    query_mock.assert_called_once_with(
        db=db,
        investigation_summary_id=(
            SUMMARY_ID
        ),
    )

    assert result is report


def test_read_integrity_returns_result():
    db = MagicMock(
        spec=Session
    )

    current_user = make_user()
    integrity_result = (
        make_integrity_result()
    )

    with patch(
        (
            "app.api.v1."
            "summary_traceability."
            "verify_summary_"
            "traceability_integrity"
        ),
        return_value=integrity_result,
    ) as verify_mock:
        result = (
            read_summary_traceability_integrity(
                summary_id=SUMMARY_ID,
                _current_user=current_user,
                db=db,
            )
        )

    verify_mock.assert_called_once_with(
        db=db,
        investigation_summary_id=(
            SUMMARY_ID
        ),
    )

    assert result is integrity_result


@pytest.mark.parametrize(
    "error",
    [
        InvestigationSummaryNotFoundError(
            "Investigation summary was not found."
        ),
        SummaryTraceabilityReportNotFoundError(
            "Traceability report was not found."
        ),
        SummaryTraceabilityCaseNotFoundError(
            "Investigation case was not found."
        ),
    ],
)
def test_not_found_errors_become_http_404(
    error,
):
    with pytest.raises(
        HTTPException
    ) as captured:
        raise_traceability_http_error(
            error
        )

    assert (
        captured.value.status_code
        == 404
    )

    assert captured.value.detail == str(
        error
    )


@pytest.mark.parametrize(
    "error",
    [
        SummaryTraceabilityIntegrityError(
            "Integrity verification failed."
        ),
        SummaryTraceabilityQueryError(
            "Traceability references do not match."
        ),
    ],
)
def test_conflict_errors_become_http_409(
    error,
):
    with pytest.raises(
        HTTPException
    ) as captured:
        raise_traceability_http_error(
            error
        )

    assert (
        captured.value.status_code
        == 409
    )

    assert captured.value.detail == str(
        error
    )


def test_read_report_converts_missing_summary_to_404():
    db = MagicMock(
        spec=Session
    )

    with patch(
        (
            "app.api.v1."
            "summary_traceability."
            "get_summary_traceability_report"
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
            read_summary_traceability(
                summary_id=SUMMARY_ID,
                _current_user=make_user(),
                db=db,
            )

    assert (
        captured.value.status_code
        == 404
    )


def test_read_integrity_converts_integrity_error_to_409():
    db = MagicMock(
        spec=Session
    )

    with patch(
        (
            "app.api.v1."
            "summary_traceability."
            "verify_summary_"
            "traceability_integrity"
        ),
        side_effect=(
            SummaryTraceabilityIntegrityError(
                (
                    "Stored traceability "
                    "integrity verification "
                    "failed."
                )
            )
        ),
    ):
        with pytest.raises(
            HTTPException
        ) as captured:
            read_summary_traceability_integrity(
                summary_id=SUMMARY_ID,
                _current_user=make_user(),
                db=db,
            )

    assert (
        captured.value.status_code
        == 409
    )


def test_unknown_error_is_reraised():
    error = RuntimeError(
        "Unexpected failure"
    )

    with pytest.raises(
        RuntimeError,
        match="Unexpected failure",
    ):
        raise_traceability_http_error(
            error
        )