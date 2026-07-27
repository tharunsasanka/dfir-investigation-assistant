import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.services.summary_traceability_query_service import (
    InvestigationSummaryNotFoundError,
    SummaryTraceabilityQueryError,
    SummaryTraceabilityReportNotFoundError,
    get_summary_traceability_report,
    verify_summary_traceability_integrity,
)


CASE_ID = uuid.uuid4()
SUMMARY_ID = uuid.uuid4()
REPORT_ID = uuid.uuid4()

SOURCE_HASH = "a" * 64
REPORT_HASH = "b" * 64


def make_summary(
    case_id=CASE_ID,
    output_sha256=SOURCE_HASH,
):
    return SimpleNamespace(
        id=SUMMARY_ID,
        case_id=case_id,
        output_sha256=output_sha256,
    )


def make_report(
    case_id=CASE_ID,
    source_sha256=SOURCE_HASH,
    report_sha256=REPORT_HASH,
):
    return SimpleNamespace(
        id=REPORT_ID,
        investigation_summary_id=SUMMARY_ID,
        case_id=case_id,
        source_summary_output_sha256=source_sha256,
        report_sha256=report_sha256,
    )


def make_case():
    return SimpleNamespace(
        id=CASE_ID,
        title="Test investigation",
    )


def make_reconstructed_report(
    report_sha256=REPORT_HASH,
):
    return SimpleNamespace(
        report_sha256=report_sha256,
    )


def test_get_summary_traceability_report_returns_report():
    db = MagicMock(spec=Session)

    summary = make_summary()
    report = make_report()

    db.scalar.side_effect = [
        summary,
        report,
    ]

    result = get_summary_traceability_report(
        db,
        SUMMARY_ID,
    )

    assert result is report
    assert db.scalar.call_count == 2


def test_get_summary_traceability_report_rejects_missing_summary():
    db = MagicMock(spec=Session)
    db.scalar.return_value = None

    with pytest.raises(
        InvestigationSummaryNotFoundError,
        match="summary was not found",
    ):
        get_summary_traceability_report(
            db,
            SUMMARY_ID,
        )


def test_get_summary_traceability_report_rejects_missing_report():
    db = MagicMock(spec=Session)

    db.scalar.side_effect = [
        make_summary(),
        None,
    ]

    with pytest.raises(
        SummaryTraceabilityReportNotFoundError,
        match="report was not found",
    ):
        get_summary_traceability_report(
            db,
            SUMMARY_ID,
        )


def test_get_summary_traceability_report_rejects_case_mismatch():
    db = MagicMock(spec=Session)

    db.scalar.side_effect = [
        make_summary(),
        make_report(
            case_id=uuid.uuid4()
        ),
    ]

    with pytest.raises(
        SummaryTraceabilityQueryError,
        match="does not match",
    ):
        get_summary_traceability_report(
            db,
            SUMMARY_ID,
        )


def test_verify_summary_traceability_integrity_succeeds():
    db = MagicMock(spec=Session)

    summary = make_summary()
    report = make_report()
    investigation_case = make_case()

    db.scalar.side_effect = [
        summary,
        report,
        investigation_case,
    ]

    with patch(
        (
            "app.services."
            "summary_traceability_query_service."
            "build_traceability_report_from_summary"
        ),
        return_value=make_reconstructed_report(),
    ):
        result = (
            verify_summary_traceability_integrity(
                db,
                SUMMARY_ID,
            )
        )

    assert result.report_id == REPORT_ID
    assert (
        result.investigation_summary_id
        == SUMMARY_ID
    )
    assert result.source_hash_matches is True
    assert result.report_hash_matches is True
    assert result.integrity_verified is True
    assert result.verified_at is not None


def test_verify_integrity_detects_source_hash_mismatch():
    db = MagicMock(spec=Session)

    summary = make_summary(
        output_sha256="c" * 64
    )

    report = make_report()
    investigation_case = make_case()

    db.scalar.side_effect = [
        summary,
        report,
        investigation_case,
    ]

    with patch(
        (
            "app.services."
            "summary_traceability_query_service."
            "build_traceability_report_from_summary"
        ),
        return_value=make_reconstructed_report(),
    ):
        result = (
            verify_summary_traceability_integrity(
                db,
                SUMMARY_ID,
            )
        )

    assert result.source_hash_matches is False
    assert result.report_hash_matches is True
    assert result.integrity_verified is False


def test_verify_integrity_detects_report_hash_mismatch():
    db = MagicMock(spec=Session)

    summary = make_summary()
    report = make_report()
    investigation_case = make_case()

    db.scalar.side_effect = [
        summary,
        report,
        investigation_case,
    ]

    with patch(
        (
            "app.services."
            "summary_traceability_query_service."
            "build_traceability_report_from_summary"
        ),
        return_value=make_reconstructed_report(
            report_sha256="d" * 64
        ),
    ):
        result = (
            verify_summary_traceability_integrity(
                db,
                SUMMARY_ID,
            )
        )

    assert result.source_hash_matches is True
    assert result.report_hash_matches is False
    assert result.integrity_verified is False