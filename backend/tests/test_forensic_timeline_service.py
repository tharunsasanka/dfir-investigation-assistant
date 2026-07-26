import uuid
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from types import SimpleNamespace

import app.services.forensic_timeline_service as timeline_service
from app.models.case_audit import (
    CaseAuditEventType,
)
from app.models.event_correlation import (
    EventCorrelationType,
)
from app.models.evidence import (
    EvidenceCustodyEventType,
    EvidenceType,
)
from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.schemas.forensic_timeline import (
    ForensicTimelineEntry,
    ForensicTimelineEntryType,
    ForensicTimelineSortOrder,
)
from app.services.forensic_timeline_service import (
    build_case_audit_entries,
    build_event_correlation_entries,
    build_evidence_custody_entries,
    build_log_event_entries,
    build_security_finding_entries,
    build_timeline_summary,
    filter_timeline_entries,
    get_case_forensic_timeline,
    sort_timeline_entries,
)


BASE_TIME = datetime(
    2026,
    7,
    24,
    10,
    0,
    tzinfo=timezone.utc,
)

CASE_ID = uuid.uuid4()


class FakeScalarResult:
    def __init__(
        self,
        items,
    ):
        self.items = items

    def all(self):
        return self.items


class FakeExecutionResult:
    def __init__(
        self,
        items,
    ):
        self.items = items

    def all(self):
        return self.items


class FakeSession:
    def __init__(
        self,
        scalar_items=None,
        row_items=None,
    ):
        self.scalar_items = (
            scalar_items or []
        )
        self.row_items = (
            row_items or []
        )

    def scalars(
        self,
        _statement,
    ):
        return FakeScalarResult(
            self.scalar_items
        )

    def execute(
        self,
        _statement,
    ):
        return FakeExecutionResult(
            self.row_items
        )


def make_timeline_entry(
    index: int,
    *,
    entry_type: ForensicTimelineEntryType = (
        ForensicTimelineEntryType
        .log_event
    ),
    severity: LogEventSeverity = (
        LogEventSeverity.informational
    ),
    evidence_id: uuid.UUID | None = None,
    title: str = "Timeline entry",
    description: str = "Timeline description",
    occurred_at: datetime | None = None,
) -> ForensicTimelineEntry:
    timestamp = (
        occurred_at
        or BASE_TIME
        + timedelta(minutes=index)
    )

    source_id = uuid.uuid4()

    return ForensicTimelineEntry(
        id=(
            f"{entry_type.value}:"
            f"{index}"
        ),
        case_id=CASE_ID,
        entry_type=entry_type,
        occurred_at=timestamp,
        recorded_at=timestamp,
        title=title,
        description=description,
        severity=severity,
        confidence=None,
        source_id=source_id,
        source_type=(
            entry_type.value
        ),
        evidence_id=evidence_id,
        event_code="",
        rule_id="",
        host="",
        username="",
        process_name="",
        source_ip="",
        destination_ip="",
        actor_email="",
        actor_full_name="",
        mitre_tactic="",
        mitre_technique_id="",
        mitre_technique_name="",
        correlation_type="",
        correlation_key="",
        details={
            "index": index,
        },
    )


def test_builds_log_event_timeline_entry():
    event_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    ingestion_job_id = uuid.uuid4()

    event = SimpleNamespace(
        id=event_id,
        case_id=CASE_ID,
        evidence_id=evidence_id,
        ingestion_job_id=(
            ingestion_job_id
        ),
        event_index=7,
        event_time=BASE_TIME,
        source_type="windows_event",
        event_code="4688",
        severity=(
            LogEventSeverity.high
        ),
        host="WORKSTATION-01",
        username="administrator",
        process_name="powershell.exe",
        source_ip="203.0.113.50",
        destination_ip="",
        message=(
            "A new process was created."
        ),
        raw_event={
            "EventID": "4688",
        },
        normalized_event={
            "process_name":
                "powershell.exe",
        },
        parse_error=None,
        created_at=(
            BASE_TIME
            + timedelta(seconds=5)
        ),
    )

    entries = build_log_event_entries(
        FakeSession(
            scalar_items=[event],
        ),
        CASE_ID,
    )

    assert len(entries) == 1

    entry = entries[0]

    assert (
        entry.entry_type
        == ForensicTimelineEntryType
        .log_event
    )
    assert entry.source_id == event_id
    assert (
        entry.evidence_id
        == evidence_id
    )
    assert (
        entry.ingestion_job_id
        == ingestion_job_id
    )
    assert (
        entry.parsed_event_id
        == event_id
    )
    assert entry.event_code == "4688"
    assert (
        entry.severity
        == LogEventSeverity.high
    )
    assert (
        entry.process_name
        == "powershell.exe"
    )
    assert (
        entry.details[
            "event_index"
        ]
        == 7
    )


def test_builds_security_finding_timeline_entry():
    finding_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    ingestion_job_id = uuid.uuid4()
    parsed_event_id = uuid.uuid4()

    finding = SimpleNamespace(
        id=finding_id,
        case_id=CASE_ID,
        evidence_id=evidence_id,
        ingestion_job_id=(
            ingestion_job_id
        ),
        parsed_event_id=(
            parsed_event_id
        ),
        event_index=4,
        event_time=BASE_TIME,
        title=(
            "Encoded PowerShell command"
        ),
        description=(
            "An encoded command was detected."
        ),
        severity=(
            LogEventSeverity.high
        ),
        confidence=95,
        source_type="windows_event",
        event_code="4688",
        rule_id=(
            "WINDOWS-ENCODED-COMMAND"
        ),
        mitre_tactic="Execution",
        mitre_technique_id=(
            "T1059.001"
        ),
        mitre_technique_name=(
            "PowerShell"
        ),
        indicators={
            "encoded_command": True,
        },
        created_at=(
            BASE_TIME
            + timedelta(seconds=10)
        ),
    )

    entries = (
        build_security_finding_entries(
            FakeSession(
                scalar_items=[finding],
            ),
            CASE_ID,
        )
    )

    assert len(entries) == 1

    entry = entries[0]

    assert (
        entry.entry_type
        == ForensicTimelineEntryType
        .security_finding
    )
    assert (
        entry.security_finding_id
        == finding_id
    )
    assert (
        entry.parsed_event_id
        == parsed_event_id
    )
    assert entry.confidence == 95
    assert (
        entry.rule_id
        == "WINDOWS-ENCODED-COMMAND"
    )
    assert (
        entry.mitre_technique_id
        == "T1059.001"
    )
    assert (
        entry.details[
            "indicators"
        ][
            "encoded_command"
        ]
        is True
    )


def test_builds_event_correlation_timeline_entry():
    correlation_id = uuid.uuid4()

    correlation = SimpleNamespace(
        id=correlation_id,
        case_id=CASE_ID,
        correlation_type=(
            EventCorrelationType
            .shared_identity
        ),
        title=(
            "Shared identity across evidence"
        ),
        description=(
            "Multiple evidence items share "
            "the same username."
        ),
        severity=(
            LogEventSeverity.medium
        ),
        confidence=80,
        window_start=BASE_TIME,
        window_end=(
            BASE_TIME
            + timedelta(minutes=5)
        ),
        created_at=(
            BASE_TIME
            + timedelta(minutes=6)
        ),
        event_count=3,
        evidence_count=2,
        matched_fields={
            "username":
                "administrator",
        },
        rule_id=(
            "CORR-SHARED-IDENTITY"
        ),
        mitre_tactic="",
        mitre_technique_id="",
        mitre_technique_name="",
        correlation_key=(
            "username:administrator"
        ),
    )

    entries = (
        build_event_correlation_entries(
            FakeSession(
                scalar_items=[
                    correlation
                ],
            ),
            CASE_ID,
        )
    )

    assert len(entries) == 1

    entry = entries[0]

    assert (
        entry.entry_type
        == ForensicTimelineEntryType
        .event_correlation
    )
    assert (
        entry.correlation_id
        == correlation_id
    )
    assert (
        entry.correlation_type
        == "shared_identity"
    )
    assert (
        entry.rule_id
        == "CORR-SHARED-IDENTITY"
    )
    assert entry.confidence == 80
    assert (
        entry.details[
            "event_count"
        ]
        == 3
    )
    assert (
        entry.details[
            "evidence_count"
        ]
        == 2
    )


def test_builds_case_audit_timeline_entry():
    audit_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    audit_event = SimpleNamespace(
        id=audit_id,
        case_id=CASE_ID,
        event_type=(
            CaseAuditEventType.updated
        ),
        actor_user_id=actor_id,
        actor_email=(
            "analyst@example.com"
        ),
        actor_full_name=(
            "Forensic Analyst"
        ),
        changes={
            "status": {
                "old": "open",
                "new": "investigating",
            },
        },
        ip_address="192.0.2.10",
        user_agent="Test Agent",
        created_at=BASE_TIME,
    )

    entries = build_case_audit_entries(
        FakeSession(
            scalar_items=[
                audit_event
            ],
        ),
        CASE_ID,
    )

    assert len(entries) == 1

    entry = entries[0]

    assert (
        entry.entry_type
        == ForensicTimelineEntryType
        .case_audit
    )
    assert (
        entry.audit_event_id
        == audit_id
    )
    assert (
        entry.actor_user_id
        == actor_id
    )
    assert (
        entry.actor_email
        == "analyst@example.com"
    )
    assert (
        entry.source_ip
        == "192.0.2.10"
    )
    assert (
        entry.details[
            "audit_event_type"
        ]
        == "updated"
    )


def test_builds_evidence_custody_timeline_entry():
    evidence_id = uuid.uuid4()
    custody_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    evidence = SimpleNamespace(
        id=evidence_id,
        case_id=CASE_ID,
        original_filename=(
            "security-events.jsonl"
        ),
        evidence_type=(
            EvidenceType.log
        ),
        sha256="a" * 64,
        size_bytes=2048,
        source="Workstation export",
    )

    custody_event = SimpleNamespace(
        id=custody_id,
        evidence_id=evidence_id,
        event_type=(
            EvidenceCustodyEventType
            .integrity_verified
        ),
        actor_user_id=actor_id,
        actor_email=(
            "analyst@example.com"
        ),
        actor_full_name=(
            "Forensic Analyst"
        ),
        details={
            "verified": True,
        },
        ip_address="192.0.2.20",
        user_agent="Test Agent",
        created_at=BASE_TIME,
    )

    entries = (
        build_evidence_custody_entries(
            FakeSession(
                row_items=[
                    (
                        custody_event,
                        evidence,
                    )
                ],
            ),
            CASE_ID,
        )
    )

    assert len(entries) == 1

    entry = entries[0]

    assert (
        entry.entry_type
        == ForensicTimelineEntryType
        .evidence_custody
    )
    assert (
        entry.custody_event_id
        == custody_id
    )
    assert (
        entry.evidence_id
        == evidence_id
    )
    assert (
        entry.severity
        == LogEventSeverity.low
    )
    assert (
        entry.details[
            "filename"
        ]
        == "security-events.jsonl"
    )
    assert (
        entry.details[
            "evidence_type"
        ]
        == "log"
    )


def test_sorts_timeline_entries_in_both_orders():
    first = make_timeline_entry(
        1,
        occurred_at=BASE_TIME,
    )

    second = make_timeline_entry(
        2,
        occurred_at=(
            BASE_TIME
            + timedelta(minutes=2)
        ),
    )

    third = make_timeline_entry(
        3,
        occurred_at=(
            BASE_TIME
            + timedelta(minutes=1)
        ),
    )

    ascending = (
        sort_timeline_entries(
            [
                second,
                first,
                third,
            ],
            ForensicTimelineSortOrder
            .ascending,
        )
    )

    descending = (
        sort_timeline_entries(
            [
                second,
                first,
                third,
            ],
            ForensicTimelineSortOrder
            .descending,
        )
    )

    assert [
        entry.id
        for entry in ascending
    ] == [
        first.id,
        third.id,
        second.id,
    ]

    assert [
        entry.id
        for entry in descending
    ] == [
        second.id,
        third.id,
        first.id,
    ]


def test_filters_timeline_entries():
    evidence_one = uuid.uuid4()
    evidence_two = uuid.uuid4()

    log_entry = make_timeline_entry(
        1,
        entry_type=(
            ForensicTimelineEntryType
            .log_event
        ),
        severity=(
            LogEventSeverity.high
        ),
        evidence_id=evidence_one,
        title="PowerShell execution",
        occurred_at=BASE_TIME,
    )

    finding_entry = (
        make_timeline_entry(
            2,
            entry_type=(
                ForensicTimelineEntryType
                .security_finding
            ),
            severity=(
                LogEventSeverity.critical
            ),
            evidence_id=evidence_two,
            title=(
                "Credential attack detected"
            ),
            description=(
                "Repeated authentication "
                "failures were detected."
            ),
            occurred_at=(
                BASE_TIME
                + timedelta(minutes=5)
            ),
        )
    )

    audit_entry = make_timeline_entry(
        3,
        entry_type=(
            ForensicTimelineEntryType
            .case_audit
        ),
        severity=(
            LogEventSeverity
            .informational
        ),
        title="Case updated",
        occurred_at=(
            BASE_TIME
            + timedelta(minutes=10)
        ),
    )

    filtered = (
        filter_timeline_entries(
            [
                log_entry,
                finding_entry,
                audit_entry,
            ],
            search="authentication",
            entry_types={
                ForensicTimelineEntryType
                .security_finding
            },
            severity=(
                LogEventSeverity.critical
            ),
            evidence_id=evidence_two,
            start_time=(
                BASE_TIME
                + timedelta(minutes=1)
            ),
            end_time=(
                BASE_TIME
                + timedelta(minutes=6)
            ),
        )
    )

    assert filtered == [
        finding_entry
    ]


def test_builds_timeline_summary():
    evidence_one = uuid.uuid4()
    evidence_two = uuid.uuid4()

    entries = [
        make_timeline_entry(
            1,
            entry_type=(
                ForensicTimelineEntryType
                .log_event
            ),
            severity=(
                LogEventSeverity.high
            ),
            evidence_id=evidence_one,
        ),
        make_timeline_entry(
            2,
            entry_type=(
                ForensicTimelineEntryType
                .security_finding
            ),
            severity=(
                LogEventSeverity.critical
            ),
            evidence_id=evidence_one,
        ),
        make_timeline_entry(
            3,
            entry_type=(
                ForensicTimelineEntryType
                .event_correlation
            ),
            severity=(
                LogEventSeverity.high
            ),
        ),
        make_timeline_entry(
            4,
            entry_type=(
                ForensicTimelineEntryType
                .case_audit
            ),
            severity=(
                LogEventSeverity
                .informational
            ),
        ),
        make_timeline_entry(
            5,
            entry_type=(
                ForensicTimelineEntryType
                .evidence_custody
            ),
            severity=(
                LogEventSeverity.low
            ),
            evidence_id=evidence_two,
        ),
    ]

    summary = build_timeline_summary(
        entries
    )

    assert summary.total_entries == 5
    assert summary.log_event_count == 1
    assert (
        summary.security_finding_count
        == 1
    )
    assert (
        summary.event_correlation_count
        == 1
    )
    assert summary.case_audit_count == 1
    assert (
        summary.evidence_custody_count
        == 1
    )
    assert summary.critical_count == 1
    assert summary.high_count == 2
    assert summary.evidence_count == 2
    assert (
        summary.first_event_at
        == entries[0].occurred_at
    )
    assert (
        summary.last_event_at
        == entries[-1].occurred_at
    )


def test_paginates_unified_timeline(
    monkeypatch,
):
    entries = [
        make_timeline_entry(
            index,
            occurred_at=(
                BASE_TIME
                + timedelta(
                    minutes=index
                )
            ),
        )
        for index in range(5)
    ]

    monkeypatch.setattr(
        timeline_service,
        "build_all_timeline_entries",
        lambda db, case_id: entries,
    )

    response = (
        get_case_forensic_timeline(
            db=FakeSession(),
            case_id=CASE_ID,
            page=2,
            page_size=2,
            sort_order=(
                ForensicTimelineSortOrder
                .ascending
            ),
        )
    )

    assert response.total == 5
    assert response.page == 2
    assert response.page_size == 2
    assert response.pages == 3
    assert (
        response.summary.total_entries
        == 5
    )

    assert [
        item.details["index"]
        for item in response.items
    ] == [
        2,
        3,
    ]