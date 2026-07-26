import json
import uuid
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case_audit import (
    CaseAuditEvent,
    CaseAuditEventType,
)
from app.models.event_correlation import (
    EventCorrelation,
)
from app.models.evidence import (
    Evidence,
    EvidenceCustodyEvent,
    EvidenceCustodyEventType,
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
    ForensicTimelineEntryType,
    ForensicTimelineResponse,
    ForensicTimelineSeverityCount,
    ForensicTimelineSortOrder,
    ForensicTimelineSummary,
    ForensicTimelineTypeCount,
)


def normalize_datetime(
    value: datetime,
) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc,
        )

    return value.astimezone(
        timezone.utc,
    )


def normalize_optional_datetime(
    value: datetime | None,
) -> datetime | None:
    if value is None:
        return None

    return normalize_datetime(value)


def get_log_event_title(
    event: ParsedLogEvent,
) -> str:
    if event.parse_error:
        return "Log parsing error"

    if event.event_code:
        return (
            f"Log event {event.event_code}"
        )

    if event.source_type:
        return (
            f"{event.source_type.replace('_', ' ').title()} event"
        )

    return "Parsed log event"


def get_log_event_description(
    event: ParsedLogEvent,
) -> str:
    if event.parse_error:
        return event.parse_error

    if event.message:
        return event.message

    available_fields = [
        value
        for value in [
            event.host,
            event.username,
            event.process_name,
            event.source_ip,
            event.destination_ip,
        ]
        if value
    ]

    if available_fields:
        return " | ".join(
            available_fields
        )

    return (
        "A parsed forensic log event "
        "was recorded."
    )


def get_case_audit_title(
    event_type: CaseAuditEventType,
) -> str:
    titles = {
        CaseAuditEventType.created:
            "Investigation case created",
        CaseAuditEventType.updated:
            "Investigation case updated",
        CaseAuditEventType.archived:
            "Investigation case archived",
    }

    return titles[event_type]


def get_case_audit_description(
    event: CaseAuditEvent,
) -> str:
    actor = (
        event.actor_full_name
        or event.actor_email
        or "Unknown user"
    )

    descriptions = {
        CaseAuditEventType.created:
            f"{actor} created the investigation case.",
        CaseAuditEventType.updated:
            f"{actor} updated the investigation case.",
        CaseAuditEventType.archived:
            f"{actor} archived the investigation case.",
    }

    return descriptions[event.event_type]


def get_case_audit_severity(
    event_type: CaseAuditEventType,
) -> LogEventSeverity:
    severities = {
        CaseAuditEventType.created:
            LogEventSeverity.informational,
        CaseAuditEventType.updated:
            LogEventSeverity.informational,
        CaseAuditEventType.archived:
            LogEventSeverity.medium,
    }

    return severities[event_type]


def get_custody_title(
    event_type: EvidenceCustodyEventType,
) -> str:
    titles = {
        EvidenceCustodyEventType.uploaded:
            "Evidence uploaded",
        EvidenceCustodyEventType.accessed:
            "Evidence accessed",
        EvidenceCustodyEventType.integrity_verified:
            "Evidence integrity verified",
        EvidenceCustodyEventType.integrity_failed:
            "Evidence integrity verification failed",
    }

    return titles[event_type]


def get_custody_description(
    custody_event: EvidenceCustodyEvent,
    evidence: Evidence,
) -> str:
    actor = (
        custody_event.actor_full_name
        or custody_event.actor_email
        or "Unknown user"
    )

    filename = (
        evidence.original_filename
        or str(evidence.id)
    )

    descriptions = {
        EvidenceCustodyEventType.uploaded:
            f"{actor} uploaded {filename}.",
        EvidenceCustodyEventType.accessed:
            f"{actor} accessed {filename}.",
        EvidenceCustodyEventType.integrity_verified:
            (
                f"{actor} verified the integrity "
                f"of {filename}."
            ),
        EvidenceCustodyEventType.integrity_failed:
            (
                f"Integrity verification failed "
                f"for {filename}."
            ),
    }

    return descriptions[
        custody_event.event_type
    ]


def get_custody_severity(
    event_type: EvidenceCustodyEventType,
) -> LogEventSeverity:
    severities = {
        EvidenceCustodyEventType.uploaded:
            LogEventSeverity.informational,
        EvidenceCustodyEventType.accessed:
            LogEventSeverity.informational,
        EvidenceCustodyEventType.integrity_verified:
            LogEventSeverity.low,
        EvidenceCustodyEventType.integrity_failed:
            LogEventSeverity.high,
    }

    return severities[event_type]


def build_log_event_entries(
    db: Session,
    case_id: uuid.UUID,
) -> list[ForensicTimelineEntry]:
    events = list(
        db.scalars(
            select(
                ParsedLogEvent
            )
            .where(
                ParsedLogEvent.case_id
                == case_id
            )
            .order_by(
                ParsedLogEvent.event_time
                .asc()
                .nullslast(),
                ParsedLogEvent
                .created_at.asc(),
                ParsedLogEvent
                .event_index.asc(),
            )
        ).all()
    )

    entries: list[
        ForensicTimelineEntry
    ] = []

    for event in events:
        occurred_at = (
            event.event_time
            or event.created_at
        )

        details = {
            "event_index":
                event.event_index,
            "raw_event":
                event.raw_event,
            "normalized_event":
                event.normalized_event,
            "parse_error":
                event.parse_error,
        }

        entries.append(
            ForensicTimelineEntry(
                id=f"log_event:{event.id}",
                case_id=event.case_id,
                entry_type=(
                    ForensicTimelineEntryType
                    .log_event
                ),
                occurred_at=(
                    normalize_datetime(
                        occurred_at
                    )
                ),
                recorded_at=(
                    normalize_datetime(
                        event.created_at
                    )
                ),
                title=(
                    get_log_event_title(
                        event
                    )
                ),
                description=(
                    get_log_event_description(
                        event
                    )
                ),
                severity=event.severity,
                confidence=None,
                source_id=event.id,
                source_type=(
                    event.source_type
                    or "unknown"
                ),
                evidence_id=(
                    event.evidence_id
                ),
                ingestion_job_id=(
                    event.ingestion_job_id
                ),
                parsed_event_id=event.id,
                event_code=(
                    event.event_code
                ),
                rule_id="",
                host=event.host,
                username=event.username,
                process_name=(
                    event.process_name
                ),
                source_ip=(
                    event.source_ip
                ),
                destination_ip=(
                    event.destination_ip
                ),
                actor_email="",
                actor_full_name="",
                mitre_tactic="",
                mitre_technique_id="",
                mitre_technique_name="",
                correlation_type="",
                correlation_key="",
                details=details,
            )
        )

    return entries


def build_security_finding_entries(
    db: Session,
    case_id: uuid.UUID,
) -> list[ForensicTimelineEntry]:
    findings = list(
        db.scalars(
            select(
                SecurityFinding
            )
            .where(
                SecurityFinding.case_id
                == case_id
            )
            .order_by(
                SecurityFinding.event_time
                .asc()
                .nullslast(),
                SecurityFinding
                .created_at.asc(),
            )
        ).all()
    )

    entries: list[
        ForensicTimelineEntry
    ] = []

    for finding in findings:
        occurred_at = (
            finding.event_time
            or finding.created_at
        )

        details = {
            "event_index":
                finding.event_index,
            "indicators":
                finding.indicators,
        }

        entries.append(
            ForensicTimelineEntry(
                id=(
                    f"security_finding:"
                    f"{finding.id}"
                ),
                case_id=finding.case_id,
                entry_type=(
                    ForensicTimelineEntryType
                    .security_finding
                ),
                occurred_at=(
                    normalize_datetime(
                        occurred_at
                    )
                ),
                recorded_at=(
                    normalize_datetime(
                        finding.created_at
                    )
                ),
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
                source_id=finding.id,
                source_type=(
                    finding.source_type
                    or "security_finding"
                ),
                evidence_id=(
                    finding.evidence_id
                ),
                ingestion_job_id=(
                    finding.ingestion_job_id
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
                rule_id=finding.rule_id,
                host="",
                username="",
                process_name="",
                source_ip="",
                destination_ip="",
                actor_email="",
                actor_full_name="",
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
                correlation_type="",
                correlation_key="",
                details=details,
            )
        )

    return entries


def build_event_correlation_entries(
    db: Session,
    case_id: uuid.UUID,
) -> list[ForensicTimelineEntry]:
    correlations = list(
        db.scalars(
            select(
                EventCorrelation
            )
            .where(
                EventCorrelation.case_id
                == case_id
            )
            .order_by(
                EventCorrelation.window_start
                .asc()
                .nullslast(),
                EventCorrelation
                .created_at.asc(),
            )
        ).all()
    )

    entries: list[
        ForensicTimelineEntry
    ] = []

    for correlation in correlations:
        occurred_at = (
            correlation.window_start
            or correlation.created_at
        )

        details = {
            "window_start":
                normalize_optional_datetime(
                    correlation.window_start
                ),
            "window_end":
                normalize_optional_datetime(
                    correlation.window_end
                ),
            "event_count":
                correlation.event_count,
            "evidence_count":
                correlation.evidence_count,
            "matched_fields":
                correlation.matched_fields,
        }

        entries.append(
            ForensicTimelineEntry(
                id=(
                    f"event_correlation:"
                    f"{correlation.id}"
                ),
                case_id=(
                    correlation.case_id
                ),
                entry_type=(
                    ForensicTimelineEntryType
                    .event_correlation
                ),
                occurred_at=(
                    normalize_datetime(
                        occurred_at
                    )
                ),
                recorded_at=(
                    normalize_datetime(
                        correlation.created_at
                    )
                ),
                title=correlation.title,
                description=(
                    correlation.description
                ),
                severity=(
                    correlation.severity
                ),
                confidence=(
                    correlation.confidence
                ),
                source_id=(
                    correlation.id
                ),
                source_type=(
                    correlation
                    .correlation_type
                    .value
                ),
                correlation_id=(
                    correlation.id
                ),
                event_code="",
                rule_id=(
                    correlation.rule_id
                ),
                host="",
                username="",
                process_name="",
                source_ip="",
                destination_ip="",
                actor_email="",
                actor_full_name="",
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
                correlation_type=(
                    correlation
                    .correlation_type
                    .value
                ),
                correlation_key=(
                    correlation
                    .correlation_key
                ),
                details=details,
            )
        )

    return entries


def build_case_audit_entries(
    db: Session,
    case_id: uuid.UUID,
) -> list[ForensicTimelineEntry]:
    audit_events = list(
        db.scalars(
            select(
                CaseAuditEvent
            )
            .where(
                CaseAuditEvent.case_id
                == case_id
            )
            .order_by(
                CaseAuditEvent
                .created_at.asc()
            )
        ).all()
    )

    entries: list[
        ForensicTimelineEntry
    ] = []

    for audit_event in audit_events:
        details = {
            "changes":
                audit_event.changes,
            "ip_address":
                audit_event.ip_address,
            "user_agent":
                audit_event.user_agent,
            "audit_event_type":
                audit_event
                .event_type.value,
        }

        entries.append(
            ForensicTimelineEntry(
                id=(
                    f"case_audit:"
                    f"{audit_event.id}"
                ),
                case_id=(
                    audit_event.case_id
                ),
                entry_type=(
                    ForensicTimelineEntryType
                    .case_audit
                ),
                occurred_at=(
                    normalize_datetime(
                        audit_event.created_at
                    )
                ),
                recorded_at=(
                    normalize_datetime(
                        audit_event.created_at
                    )
                ),
                title=(
                    get_case_audit_title(
                        audit_event
                        .event_type
                    )
                ),
                description=(
                    get_case_audit_description(
                        audit_event
                    )
                ),
                severity=(
                    get_case_audit_severity(
                        audit_event
                        .event_type
                    )
                ),
                confidence=None,
                source_id=(
                    audit_event.id
                ),
                source_type=(
                    audit_event
                    .event_type.value
                ),
                audit_event_id=(
                    audit_event.id
                ),
                event_code="",
                rule_id="",
                host="",
                username="",
                process_name="",
                source_ip=(
                    audit_event
                    .ip_address
                    or ""
                ),
                destination_ip="",
                actor_user_id=(
                    audit_event
                    .actor_user_id
                ),
                actor_email=(
                    audit_event.actor_email
                ),
                actor_full_name=(
                    audit_event
                    .actor_full_name
                ),
                mitre_tactic="",
                mitre_technique_id="",
                mitre_technique_name="",
                correlation_type="",
                correlation_key="",
                details=details,
            )
        )

    return entries


def build_evidence_custody_entries(
    db: Session,
    case_id: uuid.UUID,
) -> list[ForensicTimelineEntry]:
    statement = (
        select(
            EvidenceCustodyEvent,
            Evidence,
        )
        .join(
            Evidence,
            Evidence.id
            == EvidenceCustodyEvent
            .evidence_id,
        )
        .where(
            Evidence.case_id
            == case_id
        )
        .order_by(
            EvidenceCustodyEvent
            .created_at.asc()
        )
    )

    rows = db.execute(
        statement
    ).all()

    entries: list[
        ForensicTimelineEntry
    ] = []

    for custody_event, evidence in rows:
        details = {
            "custody_details":
                custody_event.details,
            "ip_address":
                custody_event.ip_address,
            "user_agent":
                custody_event.user_agent,
            "filename":
                evidence.original_filename,
            "evidence_type":
                evidence
                .evidence_type.value,
            "sha256":
                evidence.sha256,
            "size_bytes":
                evidence.size_bytes,
            "source":
                evidence.source,
        }

        entries.append(
            ForensicTimelineEntry(
                id=(
                    f"evidence_custody:"
                    f"{custody_event.id}"
                ),
                case_id=(
                    evidence.case_id
                ),
                entry_type=(
                    ForensicTimelineEntryType
                    .evidence_custody
                ),
                occurred_at=(
                    normalize_datetime(
                        custody_event
                        .created_at
                    )
                ),
                recorded_at=(
                    normalize_datetime(
                        custody_event
                        .created_at
                    )
                ),
                title=(
                    get_custody_title(
                        custody_event
                        .event_type
                    )
                ),
                description=(
                    get_custody_description(
                        custody_event,
                        evidence,
                    )
                ),
                severity=(
                    get_custody_severity(
                        custody_event
                        .event_type
                    )
                ),
                confidence=None,
                source_id=(
                    custody_event.id
                ),
                source_type=(
                    custody_event
                    .event_type.value
                ),
                evidence_id=(
                    evidence.id
                ),
                custody_event_id=(
                    custody_event.id
                ),
                event_code="",
                rule_id="",
                host="",
                username="",
                process_name="",
                source_ip=(
                    custody_event
                    .ip_address
                    or ""
                ),
                destination_ip="",
                actor_user_id=(
                    custody_event
                    .actor_user_id
                ),
                actor_email=(
                    custody_event
                    .actor_email
                ),
                actor_full_name=(
                    custody_event
                    .actor_full_name
                ),
                mitre_tactic="",
                mitre_technique_id="",
                mitre_technique_name="",
                correlation_type="",
                correlation_key="",
                details=details,
            )
        )

    return entries


def build_all_timeline_entries(
    db: Session,
    case_id: uuid.UUID,
) -> list[ForensicTimelineEntry]:
    entries: list[
        ForensicTimelineEntry
    ] = []

    entries.extend(
        build_log_event_entries(
            db,
            case_id,
        )
    )

    entries.extend(
        build_security_finding_entries(
            db,
            case_id,
        )
    )

    entries.extend(
        build_event_correlation_entries(
            db,
            case_id,
        )
    )

    entries.extend(
        build_case_audit_entries(
            db,
            case_id,
        )
    )

    entries.extend(
        build_evidence_custody_entries(
            db,
            case_id,
        )
    )

    return entries


def entry_matches_search(
    entry: ForensicTimelineEntry,
    normalized_search: str,
) -> bool:
    if not normalized_search:
        return True

    searchable_values = [
        entry.title,
        entry.description,
        entry.source_type,
        entry.event_code,
        entry.rule_id,
        entry.host,
        entry.username,
        entry.process_name,
        entry.source_ip,
        entry.destination_ip,
        entry.actor_email,
        entry.actor_full_name,
        entry.mitre_tactic,
        entry.mitre_technique_id,
        entry.mitre_technique_name,
        entry.correlation_type,
        entry.correlation_key,
        json.dumps(
            entry.details,
            default=str,
            ensure_ascii=False,
        ),
    ]

    return any(
        normalized_search
        in value.lower()
        for value in searchable_values
        if value
    )


def filter_timeline_entries(
    entries: Iterable[
        ForensicTimelineEntry
    ],
    search: str | None = None,
    entry_types: set[
        ForensicTimelineEntryType
    ] | None = None,
    severity: LogEventSeverity | None = None,
    evidence_id: uuid.UUID | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[ForensicTimelineEntry]:
    normalized_search = (
        search.strip().lower()
        if search
        else ""
    )

    normalized_start = (
        normalize_datetime(
            start_time
        )
        if start_time
        else None
    )

    normalized_end = (
        normalize_datetime(
            end_time
        )
        if end_time
        else None
    )

    filtered: list[
        ForensicTimelineEntry
    ] = []

    for entry in entries:
        if (
            entry_types
            and entry.entry_type
            not in entry_types
        ):
            continue

        if (
            severity is not None
            and entry.severity
            != severity
        ):
            continue

        if (
            evidence_id is not None
            and entry.evidence_id
            != evidence_id
        ):
            continue

        if (
            normalized_start
            and entry.occurred_at
            < normalized_start
        ):
            continue

        if (
            normalized_end
            and entry.occurred_at
            > normalized_end
        ):
            continue

        if not entry_matches_search(
            entry,
            normalized_search,
        ):
            continue

        filtered.append(entry)

    return filtered


def sort_timeline_entries(
    entries: list[
        ForensicTimelineEntry
    ],
    sort_order: ForensicTimelineSortOrder,
) -> list[ForensicTimelineEntry]:
    reverse = (
        sort_order
        == ForensicTimelineSortOrder
        .descending
    )

    return sorted(
        entries,
        key=lambda entry: (
            entry.occurred_at,
            entry.recorded_at,
            entry.id,
        ),
        reverse=reverse,
    )


def build_timeline_summary(
    entries: list[
        ForensicTimelineEntry
    ],
) -> ForensicTimelineSummary:
    type_counts = {
        entry_type: 0
        for entry_type
        in ForensicTimelineEntryType
    }

    severity_counts = {
        severity: 0
        for severity
        in LogEventSeverity
    }

    evidence_ids: set[
        uuid.UUID
    ] = set()

    for entry in entries:
        type_counts[
            entry.entry_type
        ] += 1

        severity_counts[
            entry.severity
        ] += 1

        if entry.evidence_id:
            evidence_ids.add(
                entry.evidence_id
            )

    occurred_times = [
        entry.occurred_at
        for entry in entries
    ]

    return ForensicTimelineSummary(
        total_entries=len(entries),
        first_event_at=(
            min(occurred_times)
            if occurred_times
            else None
        ),
        last_event_at=(
            max(occurred_times)
            if occurred_times
            else None
        ),
        log_event_count=(
            type_counts[
                ForensicTimelineEntryType
                .log_event
            ]
        ),
        security_finding_count=(
            type_counts[
                ForensicTimelineEntryType
                .security_finding
            ]
        ),
        event_correlation_count=(
            type_counts[
                ForensicTimelineEntryType
                .event_correlation
            ]
        ),
        case_audit_count=(
            type_counts[
                ForensicTimelineEntryType
                .case_audit
            ]
        ),
        evidence_custody_count=(
            type_counts[
                ForensicTimelineEntryType
                .evidence_custody
            ]
        ),
        critical_count=(
            severity_counts[
                LogEventSeverity.critical
            ]
        ),
        high_count=(
            severity_counts[
                LogEventSeverity.high
            ]
        ),
        evidence_count=len(
            evidence_ids
        ),
        type_counts=[
            ForensicTimelineTypeCount(
                entry_type=entry_type,
                count=count,
            )
            for entry_type, count
            in type_counts.items()
        ],
        severity_counts=[
            ForensicTimelineSeverityCount(
                severity=severity,
                count=count,
            )
            for severity, count
            in severity_counts.items()
        ],
    )


def get_case_forensic_timeline(
    db: Session,
    case_id: uuid.UUID,
    page: int = 1,
    page_size: int = 50,
    search: str | None = None,
    entry_types: set[
        ForensicTimelineEntryType
    ] | None = None,
    severity: LogEventSeverity | None = None,
    evidence_id: uuid.UUID | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    sort_order: ForensicTimelineSortOrder = (
        ForensicTimelineSortOrder
        .descending
    ),
) -> ForensicTimelineResponse:
    all_entries = (
        build_all_timeline_entries(
            db,
            case_id,
        )
    )

    filtered_entries = (
        filter_timeline_entries(
            entries=all_entries,
            search=search,
            entry_types=entry_types,
            severity=severity,
            evidence_id=evidence_id,
            start_time=start_time,
            end_time=end_time,
        )
    )

    sorted_entries = (
        sort_timeline_entries(
            filtered_entries,
            sort_order,
        )
    )

    summary = build_timeline_summary(
        sorted_entries
    )

    total = len(sorted_entries)

    pages = (
        (
            total
            + page_size
            - 1
        )
        // page_size
        if total > 0
        else 0
    )

    offset = (
        page - 1
    ) * page_size

    items = sorted_entries[
        offset:
        offset + page_size
    ]

    return ForensicTimelineResponse(
        items=items,
        summary=summary,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
        sort_order=sort_order,
    )