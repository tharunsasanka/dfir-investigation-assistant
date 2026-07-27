from types import SimpleNamespace
from unittest.mock import (
    MagicMock,
    patch,
)

import pytest
from sqlalchemy.orm import Session

from app.services.summary_traceability_transaction_service import (
    commit_summary_with_traceability,
)


def make_summary():
    return SimpleNamespace(
        id="summary-id",
        case_id="case-id",
        output_sha256="a" * 64,
    )


def make_case():
    return SimpleNamespace(
        id="case-id",
        title="Test investigation",
    )


def make_report():
    return SimpleNamespace(
        id="report-id",
        investigation_summary_id=(
            "summary-id"
        ),
    )


def test_commit_summary_with_traceability_succeeds():
    db = MagicMock(
        spec=Session
    )

    summary = make_summary()
    investigation_case = make_case()
    report = make_report()

    with patch(
        (
            "app.services."
            "summary_traceability_"
            "transaction_service."
            "persist_summary_"
            "traceability_report"
        ),
        return_value=report,
    ) as persist_mock:
        result = (
            commit_summary_with_traceability(
                db=db,
                summary=summary,
                investigation_case=(
                    investigation_case
                ),
            )
        )

    db.flush.assert_called_once_with()

    persist_mock.assert_called_once_with(
        db=db,
        summary=summary,
        investigation_case=(
            investigation_case
        ),
    )

    db.commit.assert_called_once_with()

    db.refresh.assert_any_call(
        summary
    )

    db.refresh.assert_any_call(
        report
    )

    assert db.refresh.call_count == 2
    db.rollback.assert_not_called()

    assert result is report


def test_commit_rolls_back_when_persistence_fails():
    db = MagicMock(
        spec=Session
    )

    summary = make_summary()
    investigation_case = make_case()

    with patch(
        (
            "app.services."
            "summary_traceability_"
            "transaction_service."
            "persist_summary_"
            "traceability_report"
        ),
        side_effect=RuntimeError(
            "Traceability failed"
        ),
    ):
        with pytest.raises(
            RuntimeError,
            match="Traceability failed",
        ):
            commit_summary_with_traceability(
                db=db,
                summary=summary,
                investigation_case=(
                    investigation_case
                ),
            )

    db.flush.assert_called_once_with()
    db.rollback.assert_called_once_with()
    db.commit.assert_not_called()
    db.refresh.assert_not_called()


def test_commit_rolls_back_when_flush_fails():
    db = MagicMock(
        spec=Session
    )

    db.flush.side_effect = RuntimeError(
        "Flush failed"
    )

    summary = make_summary()
    investigation_case = make_case()

    with patch(
        (
            "app.services."
            "summary_traceability_"
            "transaction_service."
            "persist_summary_"
            "traceability_report"
        )
    ) as persist_mock:
        with pytest.raises(
            RuntimeError,
            match="Flush failed",
        ):
            commit_summary_with_traceability(
                db=db,
                summary=summary,
                investigation_case=(
                    investigation_case
                ),
            )

    persist_mock.assert_not_called()
    db.rollback.assert_called_once_with()
    db.commit.assert_not_called()
    db.refresh.assert_not_called()