import hashlib
import json
import math
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.services.summary_traceability_transaction_service import (
    commit_summary_with_traceability,
)

from app.models.case import Case
from app.models.event_correlation import (
    EventCorrelation,
    EventCorrelationMember,
)
from app.models.evidence import Evidence
from app.models.investigation_summary import (
    InvestigationSummary,
    InvestigationSummarySource,
    InvestigationSummaryStatus,
)
from app.models.log_ingestion import (
    LogEventSeverity,
    ParsedLogEvent,
)
from app.models.security_finding import (
    SecurityFinding,
)
from app.schemas.forensic_timeline import (
    ForensicTimelineEntry,
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
    InvestigationSummaryGenerateRequest,
    InvestigationSummaryListResponse,
    InvestigationSummaryResponse,
    InvestigationSummaryRevisionRequest,
    InvestigationSummaryReviewDecision,
    InvestigationVerifiedFact,
)
from app.services.forensic_timeline_service import (
    build_all_timeline_entries,
    build_timeline_summary,
)


class InvestigationSummaryNotFoundError(
    ValueError,
):
    pass


class InvestigationSummaryStateError(
    ValueError,
):
    pass


class UnsupportedSummaryProviderError(
    ValueError,
):
    pass


SEVERITY_ORDER = {
    LogEventSeverity.unknown: 0,
    LogEventSeverity.informational: 1,
    LogEventSeverity.low: 2,
    LogEventSeverity.medium: 3,
    LogEventSeverity.high: 4,
    LogEventSeverity.critical: 5,
}


def utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def enum_value(
    value: Any,
) -> Any:
    if hasattr(value, "value"):
        return value.value

    return value


def canonical_json(
    value: Any,
) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def calculate_sha256(
    value: Any,
) -> str:
    return hashlib.sha256(
        canonical_json(value).encode(
            "utf-8"
        )
    ).hexdigest()


def format_identifier_label(
    value: str,
) -> str:
    return value.replace(
        "_",
        " ",
    ).title()


def format_timestamp(
    value: datetime | None,
) -> str:
    if value is None:
        return "an unknown time"

    return value.astimezone(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def get_case_or_raise(
    db: Session,
    case_id: uuid.UUID,
) -> Case:
    investigation_case = db.get(
        Case,
        case_id,
    )

    if investigation_case is None:
        raise InvestigationSummaryNotFoundError(
            "Case not found."
        )

    if getattr(
        investigation_case,
        "is_deleted",
        False,
    ):
        raise InvestigationSummaryNotFoundError(
            "Case not found."
        )

    return investigation_case


def get_summary_or_raise(
    db: Session,
    summary_id: uuid.UUID,
) -> InvestigationSummary:
    summary = db.get(
        InvestigationSummary,
        summary_id,
    )

    if summary is None:
        raise InvestigationSummaryNotFoundError(
            "Investigation summary not found."
        )

    return summary


def get_next_version_number(
    db: Session,
    case_id: uuid.UUID,
) -> int:
    current_version = db.scalar(
        select(
            func.max(
                InvestigationSummary
                .version_number
            )
        ).where(
            InvestigationSummary.case_id
            == case_id
        )
    )

    return (
        int(current_version)
        if current_version is not None
        else 0
    ) + 1


def collect_unique_values(
    entries: list[
        ForensicTimelineEntry
    ],
    field_name: str,
) -> list[str]:
    values = {
        str(
            getattr(
                entry,
                field_name,
                "",
            )
        ).strip()
        for entry in entries
        if str(
            getattr(
                entry,
                field_name,
                "",
            )
        ).strip()
    }

    return sorted(values)


def build_incident_scope(
    entries: list[
        ForensicTimelineEntry
    ],
) -> InvestigationIncidentScope:
    timeline_summary = (
        build_timeline_summary(
            entries
        )
    )

    evidence_ids = sorted(
        {
            entry.evidence_id
            for entry in entries
            if entry.evidence_id
            is not None
        },
        key=str,
    )

    return InvestigationIncidentScope(
        total_timeline_entries=(
            timeline_summary
            .total_entries
        ),
        log_event_count=(
            timeline_summary
            .log_event_count
        ),
        security_finding_count=(
            timeline_summary
            .security_finding_count
        ),
        event_correlation_count=(
            timeline_summary
            .event_correlation_count
        ),
        case_audit_count=(
            timeline_summary
            .case_audit_count
        ),
        evidence_custody_count=(
            timeline_summary
            .evidence_custody_count
        ),
        evidence_count=(
            timeline_summary
            .evidence_count
        ),
        critical_count=(
            timeline_summary
            .critical_count
        ),
        high_count=(
            timeline_summary
            .high_count
        ),
        first_activity_at=(
            timeline_summary
            .first_event_at
        ),
        last_activity_at=(
            timeline_summary
            .last_event_at
        ),
        affected_hosts=(
            collect_unique_values(
                entries,
                "host",
            )
        ),
        affected_usernames=(
            collect_unique_values(
                entries,
                "username",
            )
        ),
        observed_source_ips=(
            collect_unique_values(
                entries,
                "source_ip",
            )
        ),
        observed_destination_ips=(
            collect_unique_values(
                entries,
                "destination_ip",
            )
        ),
        observed_processes=(
            collect_unique_values(
                entries,
                "process_name",
            )
        ),
        evidence_ids=evidence_ids,
    )


def build_summary_findings(
    db: Session,
    case_id: uuid.UUID,
) -> list[
    InvestigationSummaryFinding
]:
    findings = list(
        db.scalars(
            select(
                SecurityFinding
            )
            .where(
                SecurityFinding.case_id
                == case_id
            )
        ).all()
    )

    correlations = list(
        db.scalars(
            select(
                EventCorrelation
            )
            .where(
                EventCorrelation.case_id
                == case_id
            )
        ).all()
    )

    summary_findings: list[
        InvestigationSummaryFinding
    ] = []

    for finding in findings:
        summary_findings.append(
            InvestigationSummaryFinding(
                title=finding.title,
                description=(
                    finding.description
                ),
                severity=(
                    finding.severity
                ),
                confidence=(
                    finding.confidence
                ),
                rule_id=(
                    finding.rule_id
                ),
                event_time=(
                    finding.event_time
                    or finding.created_at
                ),
                evidence_id=(
                    finding.evidence_id
                ),
                parsed_event_id=(
                    finding.parsed_event_id
                ),
                security_finding_id=(
                    finding.id
                ),
                event_code=(
                    finding.event_code
                ),
                source_type=(
                    finding.source_type
                ),
                mitre_tactic=(
                    finding.mitre_tactic
                ),
                mitre_technique_id=(
                    finding
                    .mitre_technique_id
                ),
                mitre_technique_name=(
                    finding
                    .mitre_technique_name
                ),
                indicators=(
                    finding.indicators
                ),
            )
        )

    for correlation in correlations:
        summary_findings.append(
            InvestigationSummaryFinding(
                title=(
                    correlation.title
                ),
                description=(
                    correlation.description
                ),
                severity=(
                    correlation.severity
                ),
                confidence=(
                    correlation.confidence
                ),
                rule_id=(
                    correlation.rule_id
                ),
                event_time=(
                    correlation.window_start
                    or correlation.created_at
                ),
                correlation_id=(
                    correlation.id
                ),
                source_type=(
                    correlation
                    .correlation_type.value
                ),
                mitre_tactic=(
                    correlation.mitre_tactic
                ),
                mitre_technique_id=(
                    correlation
                    .mitre_technique_id
                ),
                mitre_technique_name=(
                    correlation
                    .mitre_technique_name
                ),
                indicators={
                    "correlation_type":
                        correlation
                        .correlation_type
                        .value,
                    "correlation_key":
                        correlation
                        .correlation_key,
                    "event_count":
                        correlation
                        .event_count,
                    "evidence_count":
                        correlation
                        .evidence_count,
                    "window_start":
                        correlation
                        .window_start,
                    "window_end":
                        correlation
                        .window_end,
                    "matched_fields":
                        correlation
                        .matched_fields,
                },
            )
        )

    summary_findings.sort(
        key=lambda item: (
            SEVERITY_ORDER[
                item.severity
            ],
            item.confidence,
            item.event_time
            or datetime.min.replace(
                tzinfo=timezone.utc
            ),
        ),
        reverse=True,
    )

    return summary_findings[:100]


def build_mitre_coverage(
    findings: list[
        InvestigationSummaryFinding
    ],
) -> InvestigationMitreCoverage:
    techniques: dict[
        str,
        dict[str, Any],
    ] = {}

    tactics: set[str] = set()

    for finding in findings:
        technique_id = (
            finding
            .mitre_technique_id
            .strip()
        )

        tactic = (
            finding.mitre_tactic.strip()
        )

        if tactic:
            tactics.add(tactic)

        if not technique_id:
            continue

        if technique_id not in techniques:
            techniques[
                technique_id
            ] = {
                "tactic": tactic,
                "technique_name":
                    finding
                    .mitre_technique_name,
                "finding_count": 0,
                "correlation_count": 0,
                "rule_ids": set(),
            }

        technique = techniques[
            technique_id
        ]

        if (
            finding
            .security_finding_id
            is not None
        ):
            technique[
                "finding_count"
            ] += 1

        if (
            finding.correlation_id
            is not None
        ):
            technique[
                "correlation_count"
            ] += 1

        if finding.rule_id:
            technique[
                "rule_ids"
            ].add(
                finding.rule_id
            )

        if (
            not technique[
                "tactic"
            ]
            and tactic
        ):
            technique[
                "tactic"
            ] = tactic

        if (
            not technique[
                "technique_name"
            ]
            and finding
            .mitre_technique_name
        ):
            technique[
                "technique_name"
            ] = (
                finding
                .mitre_technique_name
            )

    technique_models = [
        InvestigationMitreTechnique(
            tactic=data["tactic"],
            technique_id=technique_id,
            technique_name=(
                data[
                    "technique_name"
                ]
            ),
            finding_count=(
                data[
                    "finding_count"
                ]
            ),
            correlation_count=(
                data[
                    "correlation_count"
                ]
            ),
            related_rule_ids=sorted(
                data["rule_ids"]
            ),
        )
        for technique_id, data
        in sorted(
            techniques.items()
        )
    ]

    return InvestigationMitreCoverage(
        tactic_count=len(tactics),
        technique_count=len(
            technique_models
        ),
        tactics=sorted(tactics),
        techniques=technique_models,
    )


def get_grouped_count_map(
    db: Session,
    statement: Any,
) -> dict[uuid.UUID, int]:
    return {
        evidence_id: int(count)
        for evidence_id, count
        in db.execute(
            statement
        ).all()
    }


def build_evidence_references(
    db: Session,
    case_id: uuid.UUID,
) -> list[
    InvestigationEvidenceReference
]:
    evidence_items = list(
        db.scalars(
            select(
                Evidence
            )
            .where(
                Evidence.case_id
                == case_id
            )
            .order_by(
                Evidence.created_at.asc()
            )
        ).all()
    )

    event_counts = (
        get_grouped_count_map(
            db,
            select(
                ParsedLogEvent.evidence_id,
                func.count(
                    ParsedLogEvent.id
                ),
            )
            .where(
                ParsedLogEvent.case_id
                == case_id
            )
            .group_by(
                ParsedLogEvent
                .evidence_id
            ),
        )
    )

    finding_counts = (
        get_grouped_count_map(
            db,
            select(
                SecurityFinding.evidence_id,
                func.count(
                    SecurityFinding.id
                ),
            )
            .where(
                SecurityFinding.case_id
                == case_id
            )
            .group_by(
                SecurityFinding
                .evidence_id
            ),
        )
    )

    correlation_counts = (
        get_grouped_count_map(
            db,
            select(
                EventCorrelationMember
                .evidence_id,
                func.count(
                    func.distinct(
                        EventCorrelationMember
                        .correlation_id
                    )
                ),
            )
            .where(
                EventCorrelationMember
                .case_id
                == case_id
            )
            .group_by(
                EventCorrelationMember
                .evidence_id
            ),
        )
    )

    return [
        InvestigationEvidenceReference(
            evidence_id=evidence.id,
            original_filename=(
                evidence
                .original_filename
            ),
            evidence_type=(
                evidence
                .evidence_type.value
            ),
            sha256=evidence.sha256,
            size_bytes=(
                evidence.size_bytes
            ),
            source=evidence.source,
            collected_at=(
                evidence.collected_at
            ),
            created_at=(
                evidence.created_at
            ),
            related_event_count=(
                event_counts.get(
                    evidence.id,
                    0,
                )
            ),
            related_finding_count=(
                finding_counts.get(
                    evidence.id,
                    0,
                )
            ),
            related_correlation_count=(
                correlation_counts.get(
                    evidence.id,
                    0,
                )
            ),
        )
        for evidence in evidence_items
    ]


def build_recommended_actions(
    scope: InvestigationIncidentScope,
    mitre_coverage: InvestigationMitreCoverage,
    findings: list[
        InvestigationSummaryFinding
    ],
) -> list[
    InvestigationRecommendedAction
]:
    actions: list[
        InvestigationRecommendedAction
    ] = []

    rule_ids = sorted(
        {
            finding.rule_id
            for finding in findings
            if finding.rule_id
        }
    )

    technique_ids = sorted(
        {
            technique.technique_id
            for technique
            in mitre_coverage.techniques
        }
    )

    evidence_ids = (
        scope.evidence_ids
    )

    if (
        scope.critical_count > 0
        or scope.high_count > 0
    ):
        actions.append(
            InvestigationRecommendedAction(
                priority=(
                    InvestigationActionPriority
                    .immediate
                ),
                title=(
                    "Contain affected accounts "
                    "and systems"
                ),
                description=(
                    "Restrict access for affected "
                    "identities and isolate hosts "
                    "associated with critical or "
                    "high-severity activity."
                ),
                rationale=(
                    "The investigation contains "
                    "critical or high-severity "
                    "timeline entries."
                ),
                related_rule_ids=(
                    rule_ids
                ),
                related_mitre_technique_ids=(
                    technique_ids
                ),
                related_evidence_ids=(
                    evidence_ids
                ),
            )
        )

    if scope.observed_source_ips:
        actions.append(
            InvestigationRecommendedAction(
                priority=(
                    InvestigationActionPriority
                    .immediate
                ),
                title=(
                    "Investigate observed source "
                    "IP addresses"
                ),
                description=(
                    "Validate the observed source "
                    "IP addresses against firewall, "
                    "identity, endpoint, proxy and "
                    "threat-intelligence records."
                ),
                rationale=(
                    "Network source indicators "
                    "appear in the unified forensic "
                    "timeline."
                ),
                related_rule_ids=(
                    rule_ids
                ),
                related_mitre_technique_ids=(
                    technique_ids
                ),
                related_evidence_ids=(
                    evidence_ids
                ),
            )
        )

    if mitre_coverage.technique_count:
        actions.append(
            InvestigationRecommendedAction(
                priority=(
                    InvestigationActionPriority
                    .short_term
                ),
                title=(
                    "Validate MITRE ATT&CK-mapped "
                    "activity"
                ),
                description=(
                    "Review the original events "
                    "supporting each mapped tactic "
                    "and technique and determine "
                    "whether additional related "
                    "activity exists."
                ),
                rationale=(
                    "Automated findings or "
                    "correlations include MITRE "
                    "ATT&CK mappings."
                ),
                related_rule_ids=(
                    rule_ids
                ),
                related_mitre_technique_ids=(
                    technique_ids
                ),
                related_evidence_ids=(
                    evidence_ids
                ),
            )
        )

    if scope.evidence_count:
        actions.append(
            InvestigationRecommendedAction(
                priority=(
                    InvestigationActionPriority
                    .short_term
                ),
                title=(
                    "Preserve and re-verify "
                    "digital evidence"
                ),
                description=(
                    "Retain original evidence, "
                    "confirm SHA-256 values and "
                    "document every subsequent "
                    "access or transfer."
                ),
                rationale=(
                    "The summary relies on digital "
                    "evidence that must remain "
                    "verifiable and traceable."
                ),
                related_rule_ids=[],
                related_mitre_technique_ids=[],
                related_evidence_ids=(
                    evidence_ids
                ),
            )
        )

    actions.append(
        InvestigationRecommendedAction(
            priority=(
                InvestigationActionPriority
                .long_term
            ),
            title=(
                "Complete root-cause and "
                "lessons-learned review"
            ),
            description=(
                "Confirm the initial access path, "
                "document control failures, record "
                "remediation ownership and validate "
                "that corrective controls remain "
                "effective."
            ),
            rationale=(
                "A final analyst-led review is "
                "required before closing the case."
            ),
            related_rule_ids=(
                rule_ids
            ),
            related_mitre_technique_ids=(
                technique_ids
            ),
            related_evidence_ids=(
                evidence_ids
            ),
        )
    )

    return actions


def build_verified_facts(
    scope: InvestigationIncidentScope,
    findings: list[
        InvestigationSummaryFinding
    ],
    evidence_references: list[
        InvestigationEvidenceReference
    ],
) -> list[
    InvestigationVerifiedFact
]:
    facts: list[
        InvestigationVerifiedFact
    ] = []

    facts.append(
        InvestigationVerifiedFact(
            statement=(
                f"The case contains "
                f"{scope.total_timeline_entries} "
                f"unified timeline entries."
            ),
            source_type=(
                "forensic_timeline"
            ),
            source_ids=[],
            confidence=100,
        )
    )

    facts.append(
        InvestigationVerifiedFact(
            statement=(
                f"The case contains "
                f"{len(evidence_references)} "
                f"registered evidence items."
            ),
            source_type="evidence",
            source_ids=[
                str(
                    evidence.evidence_id
                )
                for evidence
                in evidence_references
            ],
            confidence=100,
        )
    )

    if findings:
        facts.append(
            InvestigationVerifiedFact(
                statement=(
                    f"Automated analysis produced "
                    f"{scope.security_finding_count} "
                    f"security findings and "
                    f"{scope.event_correlation_count} "
                    f"event correlations."
                ),
                source_type=(
                    "automated_analysis"
                ),
                source_ids=[
                    str(
                        finding
                        .security_finding_id
                        or finding
                        .correlation_id
                    )
                    for finding in findings
                    if (
                        finding
                        .security_finding_id
                        or finding
                        .correlation_id
                    )
                ],
                confidence=100,
            )
        )

    if (
        scope.first_activity_at
        and scope.last_activity_at
    ):
        facts.append(
            InvestigationVerifiedFact(
                statement=(
                    "Recorded investigation "
                    f"activity spans from "
                    f"{format_timestamp(scope.first_activity_at)} "
                    f"to "
                    f"{format_timestamp(scope.last_activity_at)}."
                ),
                source_type=(
                    "forensic_timeline"
                ),
                source_ids=[],
                confidence=100,
            )
        )

    return facts


def build_assumptions(
    entries: list[
        ForensicTimelineEntry
    ],
) -> list[
    InvestigationAssumption
]:
    fallback_count = sum(
        1
        for entry in entries
        if (
            entry.occurred_at
            == entry.recorded_at
            and entry.entry_type.value
            in {
                "log_event",
                "security_finding",
                "event_correlation",
            }
        )
    )

    if fallback_count == 0:
        return []

    return [
        InvestigationAssumption(
            statement=(
                f"{fallback_count} records may "
                f"use their recorded timestamp "
                f"because a distinct source-event "
                f"timestamp was unavailable."
            ),
            reason=(
                "Some forensic source records do "
                "not contain an independently "
                "recorded event time."
            ),
            confidence=85,
        )
    ]


def build_limitations(
    scope: InvestigationIncidentScope,
    findings: list[
        InvestigationSummaryFinding
    ],
) -> list[str]:
    limitations = [
        (
            "This summary is generated "
            "deterministically from records "
            "currently stored in the case."
        ),
        (
            "Automated findings and MITRE ATT&CK "
            "mappings require analyst validation "
            "before they are treated as final "
            "conclusions."
        ),
        (
            "The absence of an indicator in this "
            "summary does not prove that the "
            "activity did not occur."
        ),
        (
            "The summary does not replace review "
            "of original evidence, raw events and "
            "chain-of-custody records."
        ),
    ]

    if scope.total_timeline_entries == 0:
        limitations.append(
            "No unified timeline entries were "
            "available during generation."
        )

    if not findings:
        limitations.append(
            "No automated findings or event "
            "correlations were available during "
            "generation."
        )

    return limitations


def calculate_confidence_score(
    scope: InvestigationIncidentScope,
    mitre_coverage: InvestigationMitreCoverage,
) -> int:
    score = 40

    score += min(
        15,
        scope.evidence_count * 3,
    )

    score += min(
        15,
        scope.log_event_count // 5,
    )

    score += min(
        10,
        scope.security_finding_count * 2,
    )

    score += min(
        10,
        scope.event_correlation_count * 2,
    )

    score += min(
        5,
        mitre_coverage.technique_count,
    )

    if (
        scope.first_activity_at
        and scope.last_activity_at
    ):
        score += 5

    return min(
        95,
        max(
            0,
            score,
        ),
    )


def build_executive_summary(
    investigation_case: Case,
    scope: InvestigationIncidentScope,
    mitre_coverage: InvestigationMitreCoverage,
) -> str:
    case_severity = format_identifier_label(
        str(
            enum_value(
                investigation_case
                .severity
            )
        )
    )

    case_status = format_identifier_label(
        str(
            enum_value(
                investigation_case
                .status
            )
        )
    )

    activity_window = (
        f"Recorded activity spans from "
        f"{format_timestamp(scope.first_activity_at)} "
        f"to "
        f"{format_timestamp(scope.last_activity_at)}."
        if (
            scope.first_activity_at
            and scope.last_activity_at
        )
        else (
            "A complete activity window could "
            "not be established from the "
            "available timestamps."
        )
    )

    return (
        f'Case "{investigation_case.title}" is '
        f"classified as {case_severity} severity "
        f"and is currently {case_status}. "
        f"The available records contain "
        f"{scope.total_timeline_entries} unified "
        f"timeline entries across "
        f"{scope.evidence_count} evidence items. "
        f"Automated analysis identified "
        f"{scope.security_finding_count} security "
        f"findings and "
        f"{scope.event_correlation_count} "
        f"cross-evidence correlations, including "
        f"{scope.critical_count} critical and "
        f"{scope.high_count} high-severity "
        f"entries. MITRE ATT&CK coverage includes "
        f"{mitre_coverage.tactic_count} tactics "
        f"and {mitre_coverage.technique_count} "
        f"techniques. {activity_window}"
    )


def build_technical_narrative(
    scope: InvestigationIncidentScope,
    mitre_coverage: InvestigationMitreCoverage,
) -> str:
    sections = [
        (
            "The unified forensic timeline "
            f"contains {scope.log_event_count} "
            "parsed log events, "
            f"{scope.security_finding_count} "
            "security findings, "
            f"{scope.event_correlation_count} "
            "event correlations, "
            f"{scope.case_audit_count} case-audit "
            "records and "
            f"{scope.evidence_custody_count} "
            "evidence-custody events."
        )
    ]

    if scope.affected_hosts:
        sections.append(
            "Observed hosts: "
            + ", ".join(
                scope.affected_hosts
            )
            + "."
        )

    if scope.affected_usernames:
        sections.append(
            "Observed usernames: "
            + ", ".join(
                scope.affected_usernames
            )
            + "."
        )

    if scope.observed_source_ips:
        sections.append(
            "Observed source IP addresses: "
            + ", ".join(
                scope.observed_source_ips
            )
            + "."
        )

    if scope.observed_destination_ips:
        sections.append(
            "Observed destination IP addresses: "
            + ", ".join(
                scope.observed_destination_ips
            )
            + "."
        )

    if scope.observed_processes:
        sections.append(
            "Observed processes: "
            + ", ".join(
                scope.observed_processes
            )
            + "."
        )

    if mitre_coverage.techniques:
        sections.append(
            "Mapped MITRE ATT&CK techniques: "
            + ", ".join(
                (
                    f"{technique.technique_id}"
                    + (
                        f" ({technique.technique_name})"
                        if technique.technique_name
                        else ""
                    )
                )
                for technique
                in mitre_coverage.techniques
            )
            + "."
        )

    return "\n\n".join(sections)


def build_source_snapshot(
    investigation_case: Case,
    scope: InvestigationIncidentScope,
    findings: list[
        InvestigationSummaryFinding
    ],
    mitre_coverage: InvestigationMitreCoverage,
    evidence_references: list[
        InvestigationEvidenceReference
    ],
) -> dict[str, Any]:
    return {
        "case": {
            "id": str(
                investigation_case.id
            ),
            "title":
                investigation_case.title,
            "description":
                investigation_case
                .description,
            "severity": enum_value(
                investigation_case
                .severity
            ),
            "status": enum_value(
                investigation_case
                .status
            ),
            "created_at":
                investigation_case
                .created_at,
            "updated_at":
                investigation_case
                .updated_at,
        },
        "incident_scope":
            scope.model_dump(
                mode="json"
            ),
        "technical_findings": [
            finding.model_dump(
                mode="json"
            )
            for finding in findings
        ],
        "mitre_coverage":
            mitre_coverage.model_dump(
                mode="json"
            ),
        "evidence_references": [
            evidence.model_dump(
                mode="json"
            )
            for evidence
            in evidence_references
        ],
    }


def build_output_payload(
    title: str,
    executive_summary: str,
    technical_narrative: str,
    findings: list[
        InvestigationSummaryFinding
    ],
    scope: InvestigationIncidentScope,
    mitre_coverage: InvestigationMitreCoverage,
    evidence_references: list[
        InvestigationEvidenceReference
    ],
    recommended_actions: list[
        InvestigationRecommendedAction
    ],
    verified_facts: list[
        InvestigationVerifiedFact
    ],
    assumptions: list[
        InvestigationAssumption
    ],
    limitations: list[str],
    confidence_score: int,
) -> dict[str, Any]:
    return {
        "title": title,
        "executive_summary":
            executive_summary,
        "technical_narrative":
            technical_narrative,
        "technical_findings": [
            finding.model_dump(
                mode="json"
            )
            for finding in findings
        ],
        "incident_scope":
            scope.model_dump(
                mode="json"
            ),
        "mitre_coverage":
            mitre_coverage.model_dump(
                mode="json"
            ),
        "evidence_references": [
            evidence.model_dump(
                mode="json"
            )
            for evidence
            in evidence_references
        ],
        "recommended_actions": [
            action.model_dump(
                mode="json"
            )
            for action
            in recommended_actions
        ],
        "verified_facts": [
            fact.model_dump(
                mode="json"
            )
            for fact in verified_facts
        ],
        "assumptions": [
            assumption.model_dump(
                mode="json"
            )
            for assumption
            in assumptions
        ],
        "limitations": limitations,
        "confidence_score":
            confidence_score,
    }


def generate_investigation_summary(
    db: Session,
    case_id: uuid.UUID,
    requested_by_user_id: uuid.UUID | None,
    request: InvestigationSummaryGenerateRequest,
) -> InvestigationSummary:
    if (
        request.generation_source
        != InvestigationSummarySource
        .deterministic
    ):
        raise UnsupportedSummaryProviderError(
            "Only deterministic summary "
            "generation is currently enabled."
        )

    investigation_case = get_case_or_raise(
        db,
        case_id,
    )

    version_number = (
        get_next_version_number(
            db,
            case_id,
        )
    )

    started_at = utc_now()

    summary = InvestigationSummary(
        case_id=case_id,
        version_number=version_number,
        status=(
            InvestigationSummaryStatus
            .generating
        ),
        generation_source=(
            request.generation_source
        ),
        title=(
            f"Investigation Summary "
            f"v{version_number}: "
            f"{investigation_case.title}"
        )[:255],
        provider_name=(
            request.provider_name
        ),
        model_name=(
            request.model_name
        ),
        prompt_template_version=(
            request
            .prompt_template_version
        ),
        generation_parameters=(
            request
            .generation_parameters
        ),
        requested_by_user_id=(
            requested_by_user_id
        ),
        generation_started_at=(
            started_at
        ),
    )

    db.add(summary)
    db.commit()
    db.refresh(summary)

    try:
        entries = (
            build_all_timeline_entries(
                db,
                case_id,
            )
        )

        scope = build_incident_scope(
            entries
        )

        findings = (
            build_summary_findings(
                db,
                case_id,
            )
        )

        mitre_coverage = (
            build_mitre_coverage(
                findings
            )
        )

        evidence_references = (
            build_evidence_references(
                db,
                case_id,
            )
        )

        recommended_actions = (
            build_recommended_actions(
                scope,
                mitre_coverage,
                findings,
            )
        )

        verified_facts = (
            build_verified_facts(
                scope,
                findings,
                evidence_references,
            )
        )

        assumptions = build_assumptions(
            entries
        )

        limitations = build_limitations(
            scope,
            findings,
        )

        confidence_score = (
            calculate_confidence_score(
                scope,
                mitre_coverage,
            )
        )

        executive_summary = (
            build_executive_summary(
                investigation_case,
                scope,
                mitre_coverage,
            )
        )

        technical_narrative = (
            build_technical_narrative(
                scope,
                mitre_coverage,
            )
        )

        source_snapshot = (
            build_source_snapshot(
                investigation_case,
                scope,
                findings,
                mitre_coverage,
                evidence_references,
            )
        )

        output_payload = (
            build_output_payload(
                title=summary.title,
                executive_summary=(
                    executive_summary
                ),
                technical_narrative=(
                    technical_narrative
                ),
                findings=findings,
                scope=scope,
                mitre_coverage=(
                    mitre_coverage
                ),
                evidence_references=(
                    evidence_references
                ),
                recommended_actions=(
                    recommended_actions
                ),
                verified_facts=(
                    verified_facts
                ),
                assumptions=assumptions,
                limitations=limitations,
                confidence_score=(
                    confidence_score
                ),
            )
        )

        summary.executive_summary = (
            executive_summary
        )

        summary.technical_narrative = (
            technical_narrative
        )

        summary.technical_findings = [
            item.model_dump(
                mode="json"
            )
            for item in findings
        ]

        summary.incident_scope = (
            scope.model_dump(
                mode="json"
            )
        )

        summary.mitre_coverage = (
            mitre_coverage.model_dump(
                mode="json"
            )
        )

        summary.evidence_references = [
            item.model_dump(
                mode="json"
            )
            for item
            in evidence_references
        ]

        summary.recommended_actions = [
            item.model_dump(
                mode="json"
            )
            for item
            in recommended_actions
        ]

        summary.verified_facts = [
            item.model_dump(
                mode="json"
            )
            for item in verified_facts
        ]

        summary.assumptions = [
            item.model_dump(
                mode="json"
            )
            for item in assumptions
        ]

        summary.limitations = (
            limitations
        )

        summary.confidence_score = (
            confidence_score
        )

        summary.source_snapshot = (
            source_snapshot
        )

        summary.source_snapshot_sha256 = (
            calculate_sha256(
                source_snapshot
            )
        )

        summary.output_sha256 = (
            calculate_sha256(
                output_payload
            )
        )

        summary.status = (
            InvestigationSummaryStatus
            .pending_review
        )

        summary.generation_completed_at = (
            utc_now()
        )

        summary.generation_error = ""

        commit_summary_with_traceability(
            db=db,
            summary=summary,
            investigation_case=(
                investigation_case
            ),
        )

        return summary

    except Exception as error:
        db.rollback()

        failed_summary = db.get(
            InvestigationSummary,
            summary.id,
        )

        if failed_summary is not None:
            failed_summary.status = (
                InvestigationSummaryStatus
                .failed
            )

            failed_summary.generation_error = (
                str(error)
            )

            failed_summary.generation_completed_at = (
                utc_now()
            )

            db.commit()

        raise


def list_case_investigation_summaries(
    db: Session,
    case_id: uuid.UUID,
    page: int = 1,
    page_size: int = 20,
) -> InvestigationSummaryListResponse:
    get_case_or_raise(
        db,
        case_id,
    )

    total = int(
        db.scalar(
            select(
                func.count(
                    InvestigationSummary.id
                )
            ).where(
                InvestigationSummary.case_id
                == case_id
            )
        )
        or 0
    )

    pages = (
        math.ceil(
            total / page_size
        )
        if total
        else 0
    )

    offset = (
        page - 1
    ) * page_size

    summaries = list(
        db.scalars(
            select(
                InvestigationSummary
            )
            .where(
                InvestigationSummary.case_id
                == case_id
            )
            .order_by(
                InvestigationSummary
                .version_number.desc()
            )
            .offset(offset)
            .limit(page_size)
        ).all()
    )

    return InvestigationSummaryListResponse(
        items=[
            InvestigationSummaryResponse
            .model_validate(summary)
            for summary in summaries
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


def get_investigation_summary(
    db: Session,
    summary_id: uuid.UUID,
) -> InvestigationSummary:
    return get_summary_or_raise(
        db,
        summary_id,
    )


def review_investigation_summary(
    db: Session,
    summary_id: uuid.UUID,
    reviewed_by_user_id: uuid.UUID,
    decision: InvestigationSummaryReviewDecision,
    review_notes: str,
) -> InvestigationSummary:
    summary = get_summary_or_raise(
        db,
        summary_id,
    )

    if (
        summary.status
        != InvestigationSummaryStatus
        .pending_review
    ):
        raise InvestigationSummaryStateError(
            "Only summaries pending review "
            "can be approved or rejected."
        )

    summary.status = (
        InvestigationSummaryStatus
        .approved
        if (
            decision
            == InvestigationSummaryReviewDecision
            .approved
        )
        else (
            InvestigationSummaryStatus
            .rejected
        )
    )

    summary.reviewed_by_user_id = (
        reviewed_by_user_id
    )

    summary.review_notes = (
        review_notes.strip()
    )

    summary.reviewed_at = utc_now()

    db.commit()
    db.refresh(summary)

    return summary


def create_analyst_revision(
    db: Session,
    summary_id: uuid.UUID,
    requested_by_user_id: uuid.UUID,
    request: InvestigationSummaryRevisionRequest,
) -> InvestigationSummary:
    parent_summary = (
        get_summary_or_raise(
            db,
            summary_id,
        )
    )

    version_number = (
        get_next_version_number(
            db,
            parent_summary.case_id,
        )
    )

    output_payload = (
        build_output_payload(
            title=request.title,
            executive_summary=(
                request
                .executive_summary
            ),
            technical_narrative=(
                request
                .technical_narrative
            ),
            findings=(
                request
                .technical_findings
            ),
            scope=(
                request.incident_scope
            ),
            mitre_coverage=(
                request.mitre_coverage
            ),
            evidence_references=(
                request
                .evidence_references
            ),
            recommended_actions=(
                request
                .recommended_actions
            ),
            verified_facts=(
                request.verified_facts
            ),
            assumptions=(
                request.assumptions
            ),
            limitations=(
                request.limitations
            ),
            confidence_score=(
                request
                .confidence_score
            ),
        )
    )

    timestamp = utc_now()

    revision = InvestigationSummary(
        case_id=(
            parent_summary.case_id
        ),
        parent_summary_id=(
            parent_summary.id
        ),
        version_number=(
            version_number
        ),
        status=(
            InvestigationSummaryStatus
            .pending_review
        ),
        generation_source=(
            InvestigationSummarySource
            .analyst
        ),
        title=request.title,
        executive_summary=(
            request.executive_summary
        ),
        technical_narrative=(
            request.technical_narrative
        ),
        technical_findings=[
            item.model_dump(
                mode="json"
            )
            for item
            in request.technical_findings
        ],
        incident_scope=(
            request.incident_scope
            .model_dump(
                mode="json"
            )
        ),
        mitre_coverage=(
            request.mitre_coverage
            .model_dump(
                mode="json"
            )
        ),
        evidence_references=[
            item.model_dump(
                mode="json"
            )
            for item
            in request.evidence_references
        ],
        recommended_actions=[
            item.model_dump(
                mode="json"
            )
            for item
            in request.recommended_actions
        ],
        verified_facts=[
            item.model_dump(
                mode="json"
            )
            for item
            in request.verified_facts
        ],
        assumptions=[
            item.model_dump(
                mode="json"
            )
            for item
            in request.assumptions
        ],
        limitations=(
            request.limitations
        ),
        confidence_score=(
            request.confidence_score
        ),
        provider_name="analyst",
        model_name="",
        prompt_template_version=(
            parent_summary
            .prompt_template_version
        ),
        generation_parameters={
            "revision_of":
                str(
                    parent_summary.id
                ),
        },
        source_snapshot=(
            parent_summary
            .source_snapshot
        ),
        source_snapshot_sha256=(
            parent_summary
            .source_snapshot_sha256
        ),
        output_sha256=(
            calculate_sha256(
                output_payload
            )
        ),
        requested_by_user_id=(
            requested_by_user_id
        ),
        generation_started_at=(
            timestamp
        ),
        generation_completed_at=(
            timestamp
        ),
    )

    investigation_case = (
        get_case_or_raise(
            db,
            parent_summary.case_id,
        )
    )

    db.add(revision)

    commit_summary_with_traceability(
        db=db,
        summary=revision,
        investigation_case=(
            investigation_case
        ),
    )

    return revision