import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.models.event_correlation import (
    EventCorrelationType,
)
from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.services.event_correlation_service import (
    detect_event_correlations,
)


BASE_TIME = datetime(
    2026,
    7,
    24,
    10,
    0,
    tzinfo=timezone.utc,
)


def make_event(
    *,
    evidence_id: uuid.UUID,
    minutes: int = 0,
    username: str = "",
    source_ip: str = "",
    destination_ip: str = "",
    host: str = "",
    process_name: str = "",
    event_code: str = "",
    message: str = "",
    severity: LogEventSeverity = (
        LogEventSeverity.informational
    ),
):
    return SimpleNamespace(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        evidence_id=evidence_id,
        ingestion_job_id=uuid.uuid4(),
        event_index=minutes + 1,
        event_time=(
            BASE_TIME
            + timedelta(minutes=minutes)
        ),
        source_type="test",
        event_code=event_code,
        severity=severity,
        host=host,
        username=username,
        process_name=process_name,
        source_ip=source_ip,
        destination_ip=destination_ip,
        message=message,
        raw_event={},
        normalized_event={},
        parse_error=None,
        created_at=BASE_TIME,
    )


def make_finding(
    event,
    *,
    technique_id: str,
    tactic: str,
    technique_name: str,
    severity: LogEventSeverity = (
        LogEventSeverity.high
    ),
    confidence: int = 90,
):
    return SimpleNamespace(
        id=uuid.uuid4(),
        case_id=event.case_id,
        evidence_id=event.evidence_id,
        ingestion_job_id=(
            event.ingestion_job_id
        ),
        parsed_event_id=event.id,
        event_index=event.event_index,
        event_time=event.event_time,
        rule_id="TEST-RULE",
        title="Test finding",
        description="Test finding",
        severity=severity,
        confidence=confidence,
        event_code=event.event_code,
        source_type=event.source_type,
        mitre_tactic=tactic,
        mitre_technique_id=technique_id,
        mitre_technique_name=(
            technique_name
        ),
        indicators={},
        created_at=BASE_TIME,
    )


def get_candidate(
    candidates,
    rule_id: str,
):
    return next(
        candidate
        for candidate in candidates
        if candidate.rule_id == rule_id
    )


def test_detects_shared_identity_across_evidence():
    evidence_one = uuid.uuid4()
    evidence_two = uuid.uuid4()

    events = [
        make_event(
            evidence_id=evidence_one,
            minutes=0,
            username="administrator",
        ),
        make_event(
            evidence_id=evidence_two,
            minutes=5,
            username="Administrator",
        ),
    ]

    candidates = detect_event_correlations(
        events,
        [],
    )

    candidate = get_candidate(
        candidates,
        "CORR-SHARED-IDENTITY",
    )

    assert (
        candidate.correlation_type
        == EventCorrelationType.shared_identity
    )

    assert len(candidate.members) == 2

    assert (
        candidate.matched_fields[
            "username"
        ]
        == "administrator"
    )

    assert (
        len(
            {
                member.event.evidence_id
                for member
                in candidate.members
            }
        )
        == 2
    )


def test_detects_shared_source_ip_across_evidence():
    evidence_one = uuid.uuid4()
    evidence_two = uuid.uuid4()

    events = [
        make_event(
            evidence_id=evidence_one,
            minutes=0,
            source_ip="203.0.113.50",
        ),
        make_event(
            evidence_id=evidence_two,
            minutes=10,
            source_ip="203.0.113.50",
        ),
    ]

    candidates = detect_event_correlations(
        events,
        [],
    )

    candidate = get_candidate(
        candidates,
        "CORR-SHARED-SOURCE-IP",
    )

    assert (
        candidate.correlation_type
        == EventCorrelationType.shared_network
    )

    assert candidate.confidence >= 75

    assert (
        candidate.matched_fields[
            "source_ip"
        ]
        == "203.0.113.50"
    )

    assert len(candidate.members) == 2


def test_detects_authentication_success_after_failures():
    evidence_id = uuid.uuid4()

    failures = [
        make_event(
            evidence_id=evidence_id,
            minutes=minute,
            username="administrator",
            source_ip="203.0.113.50",
            host="workstation-01",
            event_code="4625",
            message=(
                "An account failed to log on."
            ),
            severity=(
                LogEventSeverity.medium
            ),
        )
        for minute in range(3)
    ]

    success = make_event(
        evidence_id=evidence_id,
        minutes=4,
        username="administrator",
        source_ip="203.0.113.50",
        host="workstation-01",
        event_code="4624",
        message=(
            "An account was successfully "
            "logged on."
        ),
        severity=(
            LogEventSeverity.informational
        ),
    )

    candidates = detect_event_correlations(
        [
            *failures,
            success,
        ],
        [],
    )

    candidate = get_candidate(
        candidates,
        "CORR-AUTH-FAILURE-SUCCESS",
    )

    assert (
        candidate.correlation_type
        == EventCorrelationType
        .authentication_sequence
    )

    assert (
        candidate.severity
        == LogEventSeverity.high
    )

    assert (
        candidate.mitre_technique_id
        == "T1110"
    )

    assert (
        candidate.matched_fields[
            "failure_count"
        ]
        == 3
    )

    assert len(candidate.members) == 4

    assert (
        candidate.members[
            -1
        ].relationship
        == "authentication_success"
    )


def test_detects_cross_evidence_temporal_cluster():
    evidence_one = uuid.uuid4()
    evidence_two = uuid.uuid4()

    events = [
        make_event(
            evidence_id=evidence_one,
            minutes=0,
            event_code="4625",
            severity=(
                LogEventSeverity.high
            ),
        ),
        make_event(
            evidence_id=evidence_two,
            minutes=1,
            event_code="4688",
            severity=(
                LogEventSeverity.high
            ),
        ),
        make_event(
            evidence_id=evidence_one,
            minutes=2,
            event_code="1",
            severity=(
                LogEventSeverity.critical
            ),
        ),
    ]

    candidates = detect_event_correlations(
        events,
        [],
    )

    candidate = get_candidate(
        candidates,
        "CORR-TEMPORAL-CLUSTER",
    )

    assert (
        candidate.correlation_type
        == EventCorrelationType
        .temporal_cluster
    )

    assert (
        candidate.severity
        == LogEventSeverity.critical
    )

    assert len(candidate.members) == 3

    assert (
        candidate.matched_fields[
            "evidence_count"
        ]
        == 2
    )


def test_detects_shared_mitre_technique():
    evidence_one = uuid.uuid4()
    evidence_two = uuid.uuid4()

    first_event = make_event(
        evidence_id=evidence_one,
        minutes=0,
        event_code="4625",
        severity=(
            LogEventSeverity.high
        ),
    )

    second_event = make_event(
        evidence_id=evidence_two,
        minutes=5,
        event_code="4625",
        severity=(
            LogEventSeverity.high
        ),
    )

    findings = [
        make_finding(
            first_event,
            technique_id="T1110",
            tactic="Credential Access",
            technique_name="Brute Force",
        ),
        make_finding(
            second_event,
            technique_id="T1110",
            tactic="Credential Access",
            technique_name="Brute Force",
        ),
    ]

    candidates = detect_event_correlations(
        [
            first_event,
            second_event,
        ],
        findings,
    )

    candidate = get_candidate(
        candidates,
        "CORR-MITRE-TECHNIQUE",
    )

    assert (
        candidate.correlation_type
        == EventCorrelationType
        .mitre_technique
    )

    assert (
        candidate.mitre_technique_id
        == "T1110"
    )

    assert (
        candidate.mitre_tactic
        == "Credential Access"
    )

    assert len(candidate.members) == 2


def test_ignores_single_evidence_shared_identity():
    evidence_id = uuid.uuid4()

    events = [
        make_event(
            evidence_id=evidence_id,
            minutes=0,
            username="analyst",
        ),
        make_event(
            evidence_id=evidence_id,
            minutes=5,
            username="analyst",
        ),
    ]

    candidates = detect_event_correlations(
        events,
        [],
    )

    assert not any(
        candidate.rule_id
        == "CORR-SHARED-IDENTITY"
        for candidate in candidates
    )