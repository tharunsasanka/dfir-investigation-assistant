import uuid
from datetime import (
    datetime,
    timezone,
)
from types import SimpleNamespace

from app.models.case import (
    CaseSeverity,
    CaseStatus,
)
from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.schemas.investigation_summary import (
    InvestigationActionPriority,
    InvestigationAssumption,
    InvestigationEvidenceReference,
    InvestigationIncidentScope,
    InvestigationMitreCoverage,
    InvestigationMitreTechnique,
    InvestigationRecommendedAction,
    InvestigationSummaryFinding,
    InvestigationVerifiedFact,
)
from app.schemas.summary_traceability import (
    SummaryCitationSourceType,
    SummaryClaimSection,
    SummaryClaimSupportLevel,
)
from app.services.summary_traceability_service import (
    build_summary_traceability_report,
    calculate_sha256,
    split_claim_text,
    stable_identifier,
)


BASE_TIME = datetime(
    2026,
    7,
    27,
    8,
    0,
    tzinfo=timezone.utc,
)

CASE_ID = uuid.uuid4()
EVIDENCE_ID = uuid.uuid4()
PARSED_EVENT_ID = uuid.uuid4()
FINDING_ID = uuid.uuid4()
CORRELATION_ID = uuid.uuid4()


def make_case():
    return SimpleNamespace(
        id=CASE_ID,
        title=(
            "Suspicious PowerShell "
            "activity"
        ),
        description=(
            "Investigation of suspicious "
            "endpoint activity."
        ),
        severity=CaseSeverity.high,
        status=CaseStatus.investigating,
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
        is_deleted=False,
    )


def make_scope():
    return InvestigationIncidentScope(
        total_timeline_entries=12,
        log_event_count=7,
        security_finding_count=1,
        event_correlation_count=1,
        case_audit_count=1,
        evidence_custody_count=1,
        evidence_count=1,
        critical_count=0,
        high_count=1,
        first_activity_at=BASE_TIME,
        last_activity_at=BASE_TIME,
        affected_hosts=[
            "WORKSTATION-01"
        ],
        affected_usernames=[
            "laura.chen@example.com"
        ],
        observed_source_ips=[
            "203.0.113.50"
        ],
        observed_destination_ips=[
            "192.0.2.20"
        ],
        observed_processes=[
            "powershell.exe"
        ],
        evidence_ids=[
            EVIDENCE_ID
        ],
    )


def make_finding(
    **overrides,
):
    values = {
        "title":
            (
                "Suspicious PowerShell "
                "activity"
            ),
        "description":
            (
                "A suspicious PowerShell "
                "process was recorded."
            ),
        "severity":
            LogEventSeverity.high,
        "confidence":
            90,
        "rule_id":
            "WINDOWS-POWERSHELL-001",
        "event_time":
            BASE_TIME,
        "evidence_id":
            EVIDENCE_ID,
        "parsed_event_id":
            PARSED_EVENT_ID,
        "security_finding_id":
            FINDING_ID,
        "correlation_id":
            CORRELATION_ID,
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
        "indicators": {
            "raw_event": {
                "command_line":
                    (
                        "This value must not "
                        "enter citation metadata."
                    ),
            },
            "process_name":
                "powershell.exe",
        },
    }

    values.update(overrides)

    return InvestigationSummaryFinding(
        **values,
    )


def make_mitre_coverage():
    return InvestigationMitreCoverage(
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
                correlation_count=1,
                related_rule_ids=[
                    (
                        "WINDOWS-"
                        "POWERSHELL-001"
                    )
                ],
            )
        ],
    )


def make_evidence_reference():
    return InvestigationEvidenceReference(
        evidence_id=EVIDENCE_ID,
        original_filename=(
            "windows-events.json"
        ),
        evidence_type=(
            "windows_event_log"
        ),
        sha256="c" * 64,
        size_bytes=4096,
        source="analyst_upload",
        collected_at=BASE_TIME,
        created_at=BASE_TIME,
        related_event_count=7,
        related_finding_count=1,
        related_correlation_count=1,
    )


def make_action(
    **overrides,
):
    values = {
        "priority":
            (
                InvestigationActionPriority
                .immediate
            ),
        "title":
            "Validate PowerShell activity",
        "description":
            (
                "Review the recorded process "
                "activity on the affected "
                "system."
            ),
        "rationale":
            (
                "A high-severity PowerShell "
                "finding was recorded."
            ),
        "related_rule_ids": [
            "WINDOWS-POWERSHELL-001"
        ],
        "related_mitre_technique_ids": [
            "T1059.001"
        ],
        "related_evidence_ids": [
            EVIDENCE_ID
        ],
    }

    values.update(overrides)

    return InvestigationRecommendedAction(
        **values,
    )


def make_verified_fact():
    return InvestigationVerifiedFact(
        statement=(
            "The case contains twelve "
            "timeline entries."
        ),
        source_type=(
            "forensic_timeline"
        ),
        source_ids=[
            str(CASE_ID)
        ],
        confidence=100,
    )


def make_assumption():
    return InvestigationAssumption(
        statement=(
            "The recorded timestamp "
            "represents observed activity."
        ),
        reason=(
            "No separate source timestamp "
            "was available."
        ),
        confidence=80,
    )


def build_report(
    findings=None,
    actions=None,
):
    return build_summary_traceability_report(
        investigation_case=make_case(),
        executive_summary=(
            "The investigation contains "
            "12 timeline entries and one "
            "PowerShell finding. Analyst "
            "validation remains required."
        ),
        technical_narrative=(
            "Event 4688 recorded activity "
            "from 203.0.113.50 on "
            "WORKSTATION-01. The finding "
            "was detected by "
            "WINDOWS-POWERSHELL-001 and "
            "mapped to T1059.001."
        ),
        findings=(
            findings
            if findings is not None
            else [
                make_finding()
            ]
        ),
        scope=make_scope(),
        mitre_coverage=(
            make_mitre_coverage()
        ),
        evidence_references=[
            make_evidence_reference()
        ],
        recommended_actions=(
            actions
            if actions is not None
            else [
                make_action()
            ]
        ),
        verified_facts=[
            make_verified_fact()
        ],
        assumptions=[
            make_assumption()
        ],
        limitations=[
            (
                "Automated findings require "
                "analyst validation."
            )
        ],
        generated_at=BASE_TIME,
    )


def test_split_claim_text_separates_sentences():
    claims = split_claim_text(
        (
            "The first claim is recorded. "
            "The second claim is recorded. "
            "Analyst validation is required."
        )
    )

    assert claims == [
        "The first claim is recorded.",
        "The second claim is recorded.",
        "Analyst validation is required.",
    ]


def test_stable_identifier_is_repeatable():
    first_identifier = (
        stable_identifier(
            "claim",
            "executive_summary",
            0,
            "Recorded claim",
        )
    )

    second_identifier = (
        stable_identifier(
            "claim",
            "executive_summary",
            0,
            "Recorded claim",
        )
    )

    assert (
        first_identifier
        == second_identifier
    )

    assert first_identifier.startswith(
        "claim-"
    )


def test_calculate_sha256_is_repeatable():
    first_hash = calculate_sha256(
        {
            "case_id":
                str(CASE_ID),
            "count":
                12,
        }
    )

    second_hash = calculate_sha256(
        {
            "count":
                12,
            "case_id":
                str(CASE_ID),
        }
    )

    assert first_hash == second_hash
    assert len(first_hash) == 64


def test_report_contains_supported_claims_and_citations():
    report = build_report()

    assert report.total_claim_count > 0

    assert (
        report.supported_claim_count
        == report.total_claim_count
    )

    assert (
        report.unsupported_claim_count
        == 0
    )

    assert report.citation_count > 0

    assert (
        report.direct_support_count
        > 0
    )

    assert (
        report.derived_support_count
        > 0
    )

    assert len(
        report.report_sha256
    ) == 64


def test_finding_claim_links_exact_sources():
    report = build_report()

    finding_claim = next(
        claim
        for claim in report.claims
        if (
            claim.section
            == SummaryClaimSection
            .technical_finding
        )
    )

    citation_types = {
        citation.source_type
        for citation
        in finding_claim.citations
    }

    citation_source_ids = {
        citation.source_id
        for citation
        in finding_claim.citations
    }

    assert (
        finding_claim.support_level
        == SummaryClaimSupportLevel
        .direct
    )

    assert (
        SummaryCitationSourceType
        .security_finding
        in citation_types
    )

    assert (
        SummaryCitationSourceType
        .parsed_log_event
        in citation_types
    )

    assert (
        SummaryCitationSourceType
        .event_correlation
        in citation_types
    )

    assert (
        SummaryCitationSourceType
        .evidence
        in citation_types
    )

    assert str(FINDING_ID) in (
        citation_source_ids
    )

    assert str(
        PARSED_EVENT_ID
    ) in citation_source_ids

    assert str(
        CORRELATION_ID
    ) in citation_source_ids

    assert str(
        EVIDENCE_ID
    ) in citation_source_ids


def test_citation_metadata_excludes_finding_indicators():
    report = build_report()

    serialized_metadata = str(
        [
            citation.metadata
            for claim in report.claims
            for citation
            in claim.citations
        ]
    )

    assert (
        "raw_event"
        not in serialized_metadata
    )

    assert (
        "command_line"
        not in serialized_metadata
    )

    assert (
        "This value must not enter"
        not in serialized_metadata
    )

    assert (
        "process_name"
        not in serialized_metadata
    )


def test_report_hash_and_claim_ids_are_deterministic():
    first_report = build_report()
    second_report = build_report()

    assert (
        first_report.report_sha256
        == second_report.report_sha256
    )

    assert [
        claim.claim_id
        for claim
        in first_report.claims
    ] == [
        claim.claim_id
        for claim
        in second_report.claims
    ]

    assert [
        citation.citation_id
        for claim
        in first_report.claims
        for citation
        in claim.citations
    ] == [
        citation.citation_id
        for claim
        in second_report.claims
        for citation
        in claim.citations
    ]


def test_unlinked_finding_is_marked_unsupported():
    unsupported_finding = (
        make_finding(
            rule_id="",
            event_time=None,
            evidence_id=None,
            parsed_event_id=None,
            security_finding_id=None,
            correlation_id=None,
            event_code="",
            mitre_tactic="",
            mitre_technique_id="",
            mitre_technique_name="",
            indicators={},
        )
    )

    report = build_report(
        findings=[
            unsupported_finding
        ],
        actions=[],
    )

    finding_claim = next(
        claim
        for claim in report.claims
        if (
            claim.section
            == SummaryClaimSection
            .technical_finding
        )
    )

    assert (
        finding_claim.supported
        is False
    )

    assert (
        finding_claim.support_level
        == SummaryClaimSupportLevel
        .unsupported
    )

    assert (
        finding_claim.citations
        == []
    )

    assert (
        finding_claim.unsupported_reason
    )


def test_unlinked_action_is_marked_unsupported():
    unsupported_action = (
        make_action(
            related_rule_ids=[],
            related_mitre_technique_ids=[],
            related_evidence_ids=[],
        )
    )

    report = build_report(
        actions=[
            unsupported_action
        ]
    )

    action_claim = next(
        claim
        for claim in report.claims
        if (
            claim.section
            == SummaryClaimSection
            .recommended_action
        )
    )

    assert (
        action_claim.supported
        is False
    )

    assert (
        action_claim.support_level
        == SummaryClaimSupportLevel
        .unsupported
    )

    assert (
        "no linked finding"
        in action_claim
        .unsupported_reason
        .casefold()
    )


def test_evidence_citation_preserves_integrity_hash():
    report = build_report()

    evidence_citations = [
        citation
        for claim in report.claims
        for citation
        in claim.citations
        if (
            citation.source_type
            == SummaryCitationSourceType
            .evidence
        )
    ]

    assert evidence_citations

    assert all(
        citation.integrity_sha256
        == "c" * 64
        for citation
        in evidence_citations
    )