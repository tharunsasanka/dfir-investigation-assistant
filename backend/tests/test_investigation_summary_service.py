import uuid
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from types import SimpleNamespace

import pytest

import app.services.investigation_summary_service as summary_service
from app.models.case import (
    Case,
    CaseSeverity,
    CaseStatus,
)
from app.models.investigation_summary import (
    InvestigationSummary,
    InvestigationSummarySource,
    InvestigationSummaryStatus,
)
from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.schemas.forensic_timeline import (
    ForensicTimelineEntry,
    ForensicTimelineEntryType,
)
from app.schemas.investigation_summary import (
    InvestigationActionPriority,
    InvestigationEvidenceReference,
    InvestigationIncidentScope,
    InvestigationMitreCoverage,
    InvestigationMitreTechnique,
    InvestigationSummaryFinding,
    InvestigationSummaryGenerateRequest,
    InvestigationSummaryRevisionRequest,
    InvestigationSummaryReviewDecision,
)
from app.services.investigation_summary_service import (
    InvestigationSummaryStateError,
    UnsupportedSummaryProviderError,
    build_assumptions,
    build_incident_scope,
    build_mitre_coverage,
    build_recommended_actions,
    calculate_confidence_score,
    calculate_sha256,
    create_analyst_revision,
    generate_investigation_summary,
    review_investigation_summary,
)


BASE_TIME = datetime(
    2026,
    7,
    26,
    8,
    0,
    tzinfo=timezone.utc,
)

CASE_ID = uuid.uuid4()
USER_ID = uuid.uuid4()


class FakeSession:
    def __init__(
        self,
        investigation_case=None,
        summaries=None,
        scalar_value=None,
    ):
        self.investigation_case = (
            investigation_case
        )

        self.summaries = {
            summary.id: summary
            for summary in (
                summaries or []
            )
        }

        self.scalar_value = scalar_value
        self.added = []
        self.commit_count = 0
        self.rollback_count = 0

    def get(
        self,
        model,
        identifier,
    ):
        if model is Case:
            if (
                self.investigation_case
                is not None
                and self.investigation_case.id
                == identifier
            ):
                return (
                    self.investigation_case
                )

            return None

        if (
            model
            is InvestigationSummary
        ):
            return self.summaries.get(
                identifier
            )

        return None

    def scalar(
        self,
        statement,
    ):
        descriptions = getattr(
            statement,
            "column_descriptions",
            [],
        )

        for description in descriptions:
            entity = description.get(
                "entity"
            )

            entity_name = getattr(
                entity,
                "__name__",
                "",
            )

            if (
                entity_name
                == (
                    "InvestigationSummary"
                    "TraceabilityReport"
                )
            ):
                return None

        return self.scalar_value

    def add(
        self,
        instance,
    ):
        if (
            getattr(
                instance,
                "id",
                None,
            )
            is None
        ):
            instance.id = uuid.uuid4()

        self.added.append(instance)

        if isinstance(
            instance,
            InvestigationSummary,
        ):
            self.summaries[
                instance.id
            ] = instance

    def commit(self):
        self.commit_count += 1

    def flush(self):
        return None

    def rollback(self):
        self.rollback_count += 1

    def refresh(
        self,
        _instance,
    ):
        return None


def make_timeline_entry(
    index: int,
    *,
    entry_type: ForensicTimelineEntryType = (
        ForensicTimelineEntryType
        .log_event
    ),
    severity: LogEventSeverity = (
        LogEventSeverity
        .informational
    ),
    evidence_id: uuid.UUID | None = None,
    host: str = "",
    username: str = "",
    process_name: str = "",
    source_ip: str = "",
    destination_ip: str = "",
    occurred_at: datetime | None = None,
    recorded_at: datetime | None = None,
) -> ForensicTimelineEntry:
    event_time = (
        occurred_at
        or BASE_TIME
        + timedelta(
            minutes=index
        )
    )

    record_time = (
        recorded_at
        or event_time
    )

    source_id = uuid.uuid4()

    return ForensicTimelineEntry(
        id=(
            f"{entry_type.value}:"
            f"{source_id}"
        ),
        case_id=CASE_ID,
        entry_type=entry_type,
        occurred_at=event_time,
        recorded_at=record_time,
        title=(
            f"Timeline entry {index}"
        ),
        description=(
            f"Forensic event {index}"
        ),
        severity=severity,
        confidence=None,
        source_id=source_id,
        source_type=(
            entry_type.value
        ),
        evidence_id=evidence_id,
        event_code="",
        rule_id="",
        host=host,
        username=username,
        process_name=process_name,
        source_ip=source_ip,
        destination_ip=(
            destination_ip
        ),
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


def make_summary_finding(
    *,
    severity: LogEventSeverity = (
        LogEventSeverity.high
    ),
    technique_id: str = (
        "T1059.001"
    ),
    tactic: str = "Execution",
    security_finding_id: (
        uuid.UUID | None
    ) = None,
    correlation_id: (
        uuid.UUID | None
    ) = None,
    rule_id: str = (
        "TEST-RULE-001"
    ),
) -> InvestigationSummaryFinding:
    return InvestigationSummaryFinding(
        title=(
            "Suspicious PowerShell activity"
        ),
        description=(
            "A suspicious PowerShell "
            "command was detected."
        ),
        severity=severity,
        confidence=90,
        rule_id=rule_id,
        event_time=BASE_TIME,
        security_finding_id=(
            security_finding_id
        ),
        correlation_id=(
            correlation_id
        ),
        source_type=(
            "windows_event"
        ),
        event_code="4688",
        mitre_tactic=tactic,
        mitre_technique_id=(
            technique_id
        ),
        mitre_technique_name=(
            "PowerShell"
        ),
        indicators={
            "process":
                "powershell.exe",
        },
    )


def test_calculate_sha256_is_stable():
    first_value = {
        "status": "ready",
        "count": 5,
        "items": [
            "one",
            "two",
        ],
    }

    second_value = {
        "items": [
            "one",
            "two",
        ],
        "count": 5,
        "status": "ready",
    }

    first_hash = calculate_sha256(
        first_value
    )

    second_hash = calculate_sha256(
        second_value
    )

    assert first_hash == second_hash
    assert len(first_hash) == 64


def test_builds_incident_scope():
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
            host="WORKSTATION-01",
            username="laura.chen",
            process_name=(
                "powershell.exe"
            ),
            source_ip=(
                "203.0.113.50"
            ),
            destination_ip=(
                "192.0.2.20"
            ),
        ),
        make_timeline_entry(
            2,
            entry_type=(
                ForensicTimelineEntryType
                .security_finding
            ),
            severity=(
                LogEventSeverity
                .critical
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
            evidence_id=evidence_two,
        ),
        make_timeline_entry(
            4,
            entry_type=(
                ForensicTimelineEntryType
                .case_audit
            ),
        ),
        make_timeline_entry(
            5,
            entry_type=(
                ForensicTimelineEntryType
                .evidence_custody
            ),
            evidence_id=evidence_two,
        ),
    ]

    scope = build_incident_scope(
        entries
    )

    assert (
        scope.total_timeline_entries
        == 5
    )

    assert scope.log_event_count == 1

    assert (
        scope.security_finding_count
        == 1
    )

    assert (
        scope.event_correlation_count
        == 1
    )

    assert scope.case_audit_count == 1

    assert (
        scope.evidence_custody_count
        == 1
    )

    assert scope.evidence_count == 2
    assert scope.critical_count == 1
    assert scope.high_count == 2

    assert scope.affected_hosts == [
        "WORKSTATION-01"
    ]

    assert scope.affected_usernames == [
        "laura.chen"
    ]

    assert (
        scope.observed_source_ips
        == [
            "203.0.113.50"
        ]
    )

    assert (
        scope.observed_destination_ips
        == [
            "192.0.2.20"
        ]
    )

    assert scope.observed_processes == [
        "powershell.exe"
    ]

    assert set(
        scope.evidence_ids
    ) == {
        evidence_one,
        evidence_two,
    }


def test_builds_mitre_coverage():
    first_finding_id = uuid.uuid4()
    second_finding_id = uuid.uuid4()
    correlation_id = uuid.uuid4()

    findings = [
        make_summary_finding(
            security_finding_id=(
                first_finding_id
            ),
            rule_id="RULE-001",
        ),
        make_summary_finding(
            security_finding_id=(
                second_finding_id
            ),
            rule_id="RULE-002",
        ),
        make_summary_finding(
            correlation_id=(
                correlation_id
            ),
            rule_id="CORR-001",
        ),
        make_summary_finding(
            technique_id="T1110",
            tactic=(
                "Credential Access"
            ),
            security_finding_id=(
                uuid.uuid4()
            ),
            rule_id="RULE-003",
        ),
    ]

    coverage = build_mitre_coverage(
        findings
    )

    assert coverage.tactic_count == 2
    assert coverage.technique_count == 2

    powershell = next(
        technique
        for technique
        in coverage.techniques
        if (
            technique.technique_id
            == "T1059.001"
        )
    )

    assert (
        powershell.finding_count
        == 2
    )

    assert (
        powershell.correlation_count
        == 1
    )

    assert set(
        powershell.related_rule_ids
    ) == {
        "RULE-001",
        "RULE-002",
        "CORR-001",
    }


def test_builds_recommended_actions():
    evidence_id = uuid.uuid4()

    scope = InvestigationIncidentScope(
        total_timeline_entries=10,
        log_event_count=6,
        security_finding_count=2,
        event_correlation_count=1,
        evidence_count=1,
        critical_count=1,
        high_count=2,
        observed_source_ips=[
            "203.0.113.50"
        ],
        evidence_ids=[
            evidence_id
        ],
    )

    mitre_coverage = (
        InvestigationMitreCoverage(
            tactic_count=1,
            technique_count=1,
            tactics=[
                "Execution"
            ],
            techniques=[
                InvestigationMitreTechnique(
                    tactic="Execution",
                    technique_id=(
                        "T1059.001"
                    ),
                    technique_name=(
                        "PowerShell"
                    ),
                    finding_count=1,
                    correlation_count=0,
                    related_rule_ids=[
                        "RULE-001"
                    ],
                )
            ],
        )
    )

    findings = [
        make_summary_finding(
            security_finding_id=(
                uuid.uuid4()
            ),
            rule_id="RULE-001",
        )
    ]

    actions = (
        build_recommended_actions(
            scope,
            mitre_coverage,
            findings,
        )
    )

    titles = {
        action.title
        for action in actions
    }

    assert (
        "Contain affected accounts "
        "and systems"
    ) in titles

    assert (
        "Investigate observed source "
        "IP addresses"
    ) in titles

    assert (
        "Validate MITRE ATT&CK-mapped "
        "activity"
    ) in titles

    assert (
        "Preserve and re-verify "
        "digital evidence"
    ) in titles

    assert (
        "Complete root-cause and "
        "lessons-learned review"
    ) in titles

    immediate_actions = [
        action
        for action in actions
        if (
            action.priority
            == InvestigationActionPriority
            .immediate
        )
    ]

    assert len(
        immediate_actions
    ) == 2


def test_calculates_confidence_score():
    scope = InvestigationIncidentScope(
        total_timeline_entries=20,
        log_event_count=10,
        security_finding_count=3,
        event_correlation_count=2,
        evidence_count=2,
        first_activity_at=BASE_TIME,
        last_activity_at=(
            BASE_TIME
            + timedelta(hours=1)
        ),
    )

    mitre_coverage = (
        InvestigationMitreCoverage(
            tactic_count=2,
            technique_count=2,
            tactics=[
                "Execution",
                "Credential Access",
            ],
            techniques=[
                InvestigationMitreTechnique(
                    tactic="Execution",
                    technique_id=(
                        "T1059.001"
                    ),
                    technique_name=(
                        "PowerShell"
                    ),
                ),
                InvestigationMitreTechnique(
                    tactic=(
                        "Credential Access"
                    ),
                    technique_id="T1110",
                    technique_name=(
                        "Brute Force"
                    ),
                ),
            ],
        )
    )

    score = calculate_confidence_score(
        scope,
        mitre_coverage,
    )

    assert score == 65


def test_builds_timestamp_assumption():
    entries = [
        make_timeline_entry(
            1,
            entry_type=(
                ForensicTimelineEntryType
                .log_event
            ),
            occurred_at=BASE_TIME,
            recorded_at=BASE_TIME,
        ),
        make_timeline_entry(
            2,
            entry_type=(
                ForensicTimelineEntryType
                .case_audit
            ),
            occurred_at=BASE_TIME,
            recorded_at=BASE_TIME,
        ),
    ]

    assumptions = build_assumptions(
        entries
    )

    assert len(assumptions) == 1

    assert (
        "1 records may use their "
        "recorded timestamp"
        in assumptions[0].statement
    )


def test_generates_deterministic_summary(
    monkeypatch,
):
    investigation_case = (
        SimpleNamespace(
            id=CASE_ID,
            title=(
                "Suspicious mailbox activity"
            ),
            description=(
                "Investigation of suspicious "
                "identity and mailbox activity."
            ),
            severity=(
                CaseSeverity.high
            ),
            status=(
                CaseStatus.investigating
            ),
            created_at=BASE_TIME,
            updated_at=(
                BASE_TIME
                + timedelta(minutes=30)
            ),
            is_deleted=False,
        )
    )

    evidence_id = uuid.uuid4()

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
            evidence_id=evidence_id,
            host="WORKSTATION-01",
            username="laura.chen",
            process_name=(
                "powershell.exe"
            ),
            source_ip=(
                "203.0.113.50"
            ),
        ),
        make_timeline_entry(
            2,
            entry_type=(
                ForensicTimelineEntryType
                .security_finding
            ),
            severity=(
                LogEventSeverity
                .critical
            ),
            evidence_id=evidence_id,
        ),
    ]

    findings = [
        make_summary_finding(
            severity=(
                LogEventSeverity
                .critical
            ),
            security_finding_id=(
                uuid.uuid4()
            ),
            rule_id=(
                "WINDOWS-POWERSHELL-001"
            ),
        )
    ]

    evidence_references = [
        InvestigationEvidenceReference(
            evidence_id=evidence_id,
            original_filename=(
                "security-events.jsonl"
            ),
            evidence_type="log",
            sha256="a" * 64,
            size_bytes=2048,
            source=(
                "Workstation export"
            ),
            created_at=BASE_TIME,
            related_event_count=1,
            related_finding_count=1,
            related_correlation_count=0,
        )
    ]

    monkeypatch.setattr(
        summary_service,
        "build_all_timeline_entries",
        lambda db, case_id: entries,
    )

    monkeypatch.setattr(
        summary_service,
        "build_summary_findings",
        lambda db, case_id: findings,
    )

    monkeypatch.setattr(
        summary_service,
        "build_evidence_references",
        lambda db, case_id:
            evidence_references,
    )

    session = FakeSession(
        investigation_case=(
            investigation_case
        ),
        scalar_value=0,
    )

    generated = (
        generate_investigation_summary(
            db=session,
            case_id=CASE_ID,
            requested_by_user_id=(
                USER_ID
            ),
            request=(
                InvestigationSummaryGenerateRequest()
            ),
        )
    )

    assert generated.id is not None
    assert generated.case_id == CASE_ID
    assert generated.version_number == 1

    assert (
        generated.status
        == InvestigationSummaryStatus
        .pending_review
    )

    assert (
        generated.generation_source
        == InvestigationSummarySource
        .deterministic
    )

    assert (
        generated.requested_by_user_id
        == USER_ID
    )

    assert (
        generated.confidence_score
        > 0
    )

    assert len(
        generated.source_snapshot_sha256
    ) == 64

    assert len(
        generated.output_sha256
    ) == 64

    assert (
        generated.generation_error
        == ""
    )

    assert (
        generated
        .generation_completed_at
        is not None
    )

    assert (
        generated.incident_scope[
            "total_timeline_entries"
        ]
        == 2
    )

    assert (
        generated.mitre_coverage[
            "technique_count"
        ]
        == 1
    )

    assert (
        len(
            generated
            .technical_findings
        )
        == 1
    )

    assert session.commit_count == 2


def test_rejects_unsupported_provider():
    session = FakeSession()

    request = (
        InvestigationSummaryGenerateRequest(
            generation_source=(
                InvestigationSummarySource
                .local_ai
            ),
            provider_name="local",
            model_name="test-model",
        )
    )

    with pytest.raises(
        UnsupportedSummaryProviderError,
        match=(
            "Only deterministic summary "
            "generation is currently enabled"
        ),
    ):
        generate_investigation_summary(
            db=session,
            case_id=CASE_ID,
            requested_by_user_id=(
                USER_ID
            ),
            request=request,
        )


def test_reviews_pending_summary():
    summary_id = uuid.uuid4()

    summary = InvestigationSummary(
        id=summary_id,
        case_id=CASE_ID,
        version_number=1,
        status=(
            InvestigationSummaryStatus
            .pending_review
        ),
        generation_source=(
            InvestigationSummarySource
            .deterministic
        ),
    )

    session = FakeSession(
        summaries=[
            summary
        ],
    )

    reviewed = (
        review_investigation_summary(
            db=session,
            summary_id=summary_id,
            reviewed_by_user_id=(
                USER_ID
            ),
            decision=(
                InvestigationSummaryReviewDecision
                .approved
            ),
            review_notes=(
                "Validated against "
                "the original evidence."
            ),
        )
    )

    assert (
        reviewed.status
        == InvestigationSummaryStatus
        .approved
    )

    assert (
        reviewed.reviewed_by_user_id
        == USER_ID
    )

    assert (
        reviewed.review_notes
        == (
            "Validated against "
            "the original evidence."
        )
    )

    assert reviewed.reviewed_at is not None
    assert session.commit_count == 1


def test_prevents_second_review():
    summary_id = uuid.uuid4()

    summary = InvestigationSummary(
        id=summary_id,
        case_id=CASE_ID,
        version_number=1,
        status=(
            InvestigationSummaryStatus
            .approved
        ),
        generation_source=(
            InvestigationSummarySource
            .deterministic
        ),
    )

    session = FakeSession(
        summaries=[
            summary
        ],
    )

    with pytest.raises(
        InvestigationSummaryStateError,
        match=(
            "Only summaries pending review"
        ),
    ):
        review_investigation_summary(
            db=session,
            summary_id=summary_id,
            reviewed_by_user_id=(
                USER_ID
            ),
            decision=(
                InvestigationSummaryReviewDecision
                .rejected
            ),
            review_notes=(
                "Rejected after review."
            ),
        )


def test_creates_analyst_revision():
    parent_id = uuid.uuid4()

    parent_summary = InvestigationSummary(
        id=parent_id,
        case_id=CASE_ID,
        version_number=2,
        status=(
            InvestigationSummaryStatus
            .rejected
        ),
        generation_source=(
            InvestigationSummarySource
            .deterministic
        ),
        prompt_template_version=(
            "1.0.0"
        ),
        source_snapshot={
            "case": {
                "id": str(CASE_ID),
            },
        },
        source_snapshot_sha256=(
            "b" * 64
        ),
    )

    investigation_case = SimpleNamespace(
        id=CASE_ID,
        title="Analyst revision case",
        description="Case used for analyst revision testing.",
        severity=CaseSeverity.high,
        status=CaseStatus.investigating,
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
        is_deleted=False,
    )

    session = FakeSession(
        investigation_case=investigation_case,
        summaries=[
            parent_summary
        ],
        scalar_value=2,
    )

    request = (
        InvestigationSummaryRevisionRequest(
            title=(
                "Analyst Investigation "
                "Summary v3"
            ),
            executive_summary=(
                "The analyst validated "
                "the identified activity."
            ),
            technical_narrative=(
                "Original evidence and "
                "timeline records were "
                "reviewed."
            ),
            incident_scope=(
                InvestigationIncidentScope(
                    total_timeline_entries=5,
                    evidence_count=1,
                )
            ),
            mitre_coverage=(
                InvestigationMitreCoverage()
            ),
            confidence_score=95,
        )
    )

    revision = (
        create_analyst_revision(
            db=session,
            summary_id=parent_id,
            requested_by_user_id=(
                USER_ID
            ),
            request=request,
        )
    )

    assert revision.id is not None

    assert (
        revision.parent_summary_id
        == parent_id
    )

    assert revision.version_number == 3

    assert (
        revision.status
        == InvestigationSummaryStatus
        .pending_review
    )

    assert (
        revision.generation_source
        == InvestigationSummarySource
        .analyst
    )

    assert (
        revision.requested_by_user_id
        == USER_ID
    )

    assert (
        revision.source_snapshot_sha256
        == "b" * 64
    )

    assert len(
        revision.output_sha256
    ) == 64

    assert (
        revision.generation_started_at
        is not None
    )

    assert (
        revision
        .generation_completed_at
        is not None
    )

    assert session.commit_count == 1