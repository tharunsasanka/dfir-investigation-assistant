import uuid
from datetime import (
    datetime,
    timezone,
)
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session

from app.models.investigation_summary import (
    InvestigationSummary,
)
from app.models.summary_traceability import (
    InvestigationSummaryTraceabilityReport,
)
from app.services.summary_traceability_persistence_service import (
    SummaryTraceabilityCaseMismatchError,
    SummaryTraceabilityIntegrityError,
    build_traceability_report_from_summary,
    normalize_sha256,
    persist_summary_traceability_report,
)


BASE_TIME = datetime(
    2026,
    7,
    27,
    9,
    0,
    tzinfo=timezone.utc,
)

CASE_ID = uuid.uuid4()
SUMMARY_ID = uuid.uuid4()


def make_case(
    case_id=CASE_ID,
):
    return SimpleNamespace(
        id=case_id,
        title=(
            "Suspicious authentication "
            "activity"
        ),
        severity="high",
        status="investigating",
    )


def make_summary(
    output_sha256="a" * 64,
):
    return InvestigationSummary(
        id=SUMMARY_ID,
        case_id=CASE_ID,
        version_number=1,
        executive_summary=(
            "The investigation contains "
            "two timeline entries."
        ),
        technical_narrative=(
            "The available records require "
            "analyst validation."
        ),
        technical_findings=[],
        incident_scope={
            "total_timeline_entries": 2,
            "log_event_count": 2,
            "security_finding_count": 0,
            "event_correlation_count": 0,
            "case_audit_count": 0,
            "evidence_custody_count": 0,
            "evidence_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "first_activity_at":
                BASE_TIME.isoformat(),
            "last_activity_at":
                BASE_TIME.isoformat(),
            "affected_hosts": [],
            "affected_usernames": [],
            "observed_source_ips": [],
            "observed_destination_ips": [],
            "observed_processes": [],
            "evidence_ids": [],
        },
        mitre_coverage={
            "tactic_count": 0,
            "technique_count": 0,
            "tactics": [],
            "techniques": [],
        },
        evidence_references=[],
        recommended_actions=[],
        verified_facts=[],
        assumptions=[],
        limitations=[
            (
                "Automated conclusions "
                "require analyst validation."
            )
        ],
        output_sha256=output_sha256,
        generation_completed_at=BASE_TIME,
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )


def make_existing_record(
    report_sha256: str,
    source_sha256: str = "a" * 64,
):
    return (
        InvestigationSummaryTraceabilityReport(
            id=uuid.uuid4(),
            investigation_summary_id=(
                SUMMARY_ID
            ),
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
            source_summary_output_sha256=(
                source_sha256
            ),
            report_sha256=report_sha256,
            generated_at=BASE_TIME,
            created_at=BASE_TIME,
        )
    )


def test_normalize_sha256_lowercases_hash():
    normalized = normalize_sha256(
        "A" * 64
    )

    assert normalized == "a" * 64


def test_normalize_sha256_rejects_invalid_hash():
    with pytest.raises(
        SummaryTraceabilityIntegrityError
    ):
        normalize_sha256(
            "invalid-hash"
        )


def test_build_report_from_summary_is_deterministic():
    summary = make_summary()
    investigation_case = make_case()

    first_report = (
        build_traceability_report_from_summary(
            summary,
            investigation_case,
        )
    )

    second_report = (
        build_traceability_report_from_summary(
            summary,
            investigation_case,
        )
    )

    assert (
        first_report.report_sha256
        == second_report.report_sha256
    )

    assert (
        first_report.generated_at
        == BASE_TIME
    )

    assert (
        first_report.total_claim_count
        > 0
    )

    assert (
        first_report.supported_claim_count
        + first_report
        .unsupported_claim_count
        == first_report
        .total_claim_count
    )


def test_build_report_rejects_case_mismatch():
    summary = make_summary()

    investigation_case = make_case(
        uuid.uuid4()
    )

    with pytest.raises(
        SummaryTraceabilityCaseMismatchError
    ):
        build_traceability_report_from_summary(
            summary,
            investigation_case,
        )


def test_persist_creates_new_traceability_record():
    db = MagicMock(
        spec=Session
    )

    db.scalar.return_value = None

    summary = make_summary()
    investigation_case = make_case()

    record = (
        persist_summary_traceability_report(
            db,
            summary,
            investigation_case,
        )
    )

    db.add.assert_called_once_with(
        record
    )

    db.flush.assert_called_once_with()

    assert (
        record.investigation_summary_id
        == SUMMARY_ID
    )

    assert record.case_id == CASE_ID

    assert (
        record.source_summary_output_sha256
        == "a" * 64
    )

    assert len(
        record.report_sha256
    ) == 64

    assert (
        record.total_claim_count
        > 0
    )

    assert (
        record.supported_claim_count
        + record.unsupported_claim_count
        == record.total_claim_count
    )


def test_persist_returns_matching_existing_record():
    db = MagicMock(
        spec=Session
    )

    summary = make_summary()
    investigation_case = make_case()

    generated_report = (
        build_traceability_report_from_summary(
            summary,
            investigation_case,
        )
    )

    existing = make_existing_record(
        generated_report.report_sha256
    )

    db.scalar.return_value = existing

    result = (
        persist_summary_traceability_report(
            db,
            summary,
            investigation_case,
        )
    )

    assert result is existing

    db.add.assert_not_called()
    db.flush.assert_not_called()


def test_persist_rejects_existing_source_hash_mismatch():
    db = MagicMock(
        spec=Session
    )

    summary = make_summary()
    investigation_case = make_case()

    generated_report = (
        build_traceability_report_from_summary(
            summary,
            investigation_case,
        )
    )

    db.scalar.return_value = (
        make_existing_record(
            report_sha256=(
                generated_report
                .report_sha256
            ),
            source_sha256="b" * 64,
        )
    )

    with pytest.raises(
        SummaryTraceabilityIntegrityError,
        match="different summary output",
    ):
        persist_summary_traceability_report(
            db,
            summary,
            investigation_case,
        )

    db.add.assert_not_called()
    db.flush.assert_not_called()


def test_persist_rejects_existing_report_hash_mismatch():
    db = MagicMock(
        spec=Session
    )

    summary = make_summary()
    investigation_case = make_case()

    db.scalar.return_value = (
        make_existing_record(
            report_sha256="b" * 64
        )
    )

    with pytest.raises(
        SummaryTraceabilityIntegrityError,
        match=(
            "deterministically "
            "reconstructed report"
        ),
    ):
        persist_summary_traceability_report(
            db,
            summary,
            investigation_case,
        )

    db.add.assert_not_called()
    db.flush.assert_not_called()