import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Callable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models.event_correlation import (
    EventCorrelation,
    EventCorrelationMember,
    EventCorrelationType,
)
from app.models.log_ingestion import (
    LogEventSeverity,
    ParsedLogEvent,
)
from app.models.security_finding import (
    SecurityFinding,
)
from app.schemas.event_correlation import (
    EventCorrelationRunResponse,
)


@dataclass
class CorrelationMemberCandidate:
    event: ParsedLogEvent
    relationship: str
    matched_values: dict[str, Any]


@dataclass
class CorrelationCandidate:
    signature: str
    correlation_type: EventCorrelationType
    rule_id: str
    title: str
    description: str
    severity: LogEventSeverity
    confidence: int
    correlation_key: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    matched_fields: dict[str, Any]
    members: list[CorrelationMemberCandidate]
    window_start: datetime | None
    window_end: datetime | None


SEVERITY_RANK = {
    LogEventSeverity.unknown: 0,
    LogEventSeverity.informational: 1,
    LogEventSeverity.low: 2,
    LogEventSeverity.medium: 3,
    LogEventSeverity.high: 4,
    LogEventSeverity.critical: 5,
}


IGNORED_VALUES = {
    "",
    "-",
    "unknown",
    "none",
    "null",
    "n/a",
    "not available",
}


IGNORED_IP_VALUES = {
    *IGNORED_VALUES,
    "0.0.0.0",
    "::",
    "::1",
    "127.0.0.1",
}


AUTHENTICATION_FAILURE_CODES = {
    "4625",
    "4771",
    "4776",
}


AUTHENTICATION_SUCCESS_CODES = {
    "4624",
}


AUTHENTICATION_FAILURE_TERMS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "failed logon",
    "account failed to log on",
)


AUTHENTICATION_SUCCESS_TERMS = (
    "accepted password",
    "accepted publickey",
    "successful logon",
    "successfully logged on",
    "account was successfully logged on",
)


def normalize_text(
    value: str | None,
) -> str:
    if value is None:
        return ""

    normalized = " ".join(
        value.strip().lower().split()
    )

    if normalized in IGNORED_VALUES:
        return ""

    return normalized


def normalize_ip(
    value: str | None,
) -> str:
    normalized = normalize_text(value)

    if normalized in IGNORED_IP_VALUES:
        return ""

    return normalized


def normalize_process(
    value: str | None,
) -> str:
    normalized = normalize_text(value)

    if not normalized:
        return ""

    normalized = normalized.replace(
        "\\",
        "/",
    )

    return normalized.rsplit(
        "/",
        1,
    )[-1]


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


def event_sort_key(
    event: ParsedLogEvent,
) -> tuple[
    int,
    datetime,
    int,
    str,
]:
    fallback = datetime.max.replace(
        tzinfo=timezone.utc,
    )

    event_time = (
        normalize_datetime(
            event.event_time,
        )
        if event.event_time is not None
        else fallback
    )

    return (
        1
        if event.event_time is None
        else 0,
        event_time,
        event.event_index,
        str(event.id),
    )


def cluster_events(
    events: list[ParsedLogEvent],
    window: timedelta,
) -> list[list[ParsedLogEvent]]:
    timed_events = [
        event
        for event in events
        if event.event_time is not None
    ]

    timed_events.sort(
        key=event_sort_key,
    )

    clusters: list[
        list[ParsedLogEvent]
    ] = []

    current_cluster: list[
        ParsedLogEvent
    ] = []

    for event in timed_events:
        event_time = normalize_datetime(
            event.event_time
        )

        if not current_cluster:
            current_cluster = [event]
            continue

        cluster_start = normalize_datetime(
            current_cluster[0].event_time
        )

        if (
            event_time - cluster_start
            <= window
        ):
            current_cluster.append(event)
            continue

        clusters.append(
            current_cluster
        )

        current_cluster = [event]

    if current_cluster:
        clusters.append(
            current_cluster
        )

    return clusters


def maximum_severity(
    events: list[ParsedLogEvent],
    minimum: LogEventSeverity,
) -> LogEventSeverity:
    severity = minimum

    for event in events:
        if (
            SEVERITY_RANK[event.severity]
            > SEVERITY_RANK[severity]
        ):
            severity = event.severity

    return severity


def build_signature(
    rule_id: str,
    correlation_key: str,
    members: list[
        CorrelationMemberCandidate
    ],
) -> str:
    event_ids = sorted(
        str(member.event.id)
        for member in members
    )

    signature_source = "|".join(
        [
            rule_id,
            correlation_key,
            *event_ids,
        ]
    )

    return sha256(
        signature_source.encode(
            "utf-8"
        )
    ).hexdigest()


def unique_members(
    members: list[
        CorrelationMemberCandidate
    ],
) -> list[
    CorrelationMemberCandidate
]:
    unique: dict[
        uuid.UUID,
        CorrelationMemberCandidate,
    ] = {}

    for member in members:
        if member.event.id not in unique:
            unique[
                member.event.id
            ] = member

    result = list(
        unique.values()
    )

    result.sort(
        key=lambda member: event_sort_key(
            member.event
        )
    )

    return result


def create_candidate(
    correlation_type: EventCorrelationType,
    rule_id: str,
    title: str,
    description: str,
    severity: LogEventSeverity,
    confidence: int,
    correlation_key: str,
    matched_fields: dict[str, Any],
    members: list[
        CorrelationMemberCandidate
    ],
    mitre_tactic: str = "",
    mitre_technique_id: str = "",
    mitre_technique_name: str = "",
) -> CorrelationCandidate:
    normalized_members = unique_members(
        members
    )

    event_times = [
        normalize_datetime(
            member.event.event_time
        )
        for member in normalized_members
        if member.event.event_time
        is not None
    ]

    window_start = (
        min(event_times)
        if event_times
        else None
    )

    window_end = (
        max(event_times)
        if event_times
        else None
    )

    return CorrelationCandidate(
        signature=build_signature(
            rule_id,
            correlation_key,
            normalized_members,
        ),
        correlation_type=(
            correlation_type
        ),
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        confidence=max(
            0,
            min(100, confidence),
        ),
        correlation_key=(
            correlation_key[:500]
        ),
        mitre_tactic=mitre_tactic,
        mitre_technique_id=(
            mitre_technique_id
        ),
        mitre_technique_name=(
            mitre_technique_name
        ),
        matched_fields=matched_fields,
        members=normalized_members,
        window_start=window_start,
        window_end=window_end,
    )


def build_shared_indicator_candidates(
    events: list[ParsedLogEvent],
    extractor: Callable[
        [ParsedLogEvent],
        str,
    ],
    field_name: str,
    correlation_type: EventCorrelationType,
    rule_id: str,
    title: str,
    description_label: str,
    relationship: str,
    window: timedelta,
    minimum_severity: LogEventSeverity,
    base_confidence: int,
) -> list[CorrelationCandidate]:
    groups: dict[
        str,
        list[ParsedLogEvent],
    ] = defaultdict(list)

    for event in events:
        value = extractor(event)

        if value:
            groups[value].append(event)

    candidates: list[
        CorrelationCandidate
    ] = []

    for value, grouped_events in groups.items():
        clusters = cluster_events(
            grouped_events,
            window,
        )

        for cluster in clusters:
            evidence_ids = {
                event.evidence_id
                for event in cluster
            }

            if (
                len(cluster) < 2
                or len(evidence_ids) < 2
            ):
                continue

            members = [
                CorrelationMemberCandidate(
                    event=event,
                    relationship=relationship,
                    matched_values={
                        field_name: value,
                    },
                )
                for event in cluster
            ]

            confidence = min(
                95,
                base_confidence
                + min(
                    20,
                    (
                        len(cluster) - 2
                    )
                    * 5,
                ),
            )

            candidates.append(
                create_candidate(
                    correlation_type=(
                        correlation_type
                    ),
                    rule_id=rule_id,
                    title=title,
                    description=(
                        f"Multiple events from "
                        f"{len(evidence_ids)} evidence "
                        f"items share the same "
                        f"{description_label}: {value}."
                    ),
                    severity=maximum_severity(
                        cluster,
                        minimum_severity,
                    ),
                    confidence=confidence,
                    correlation_key=(
                        f"{field_name}:{value}"
                    ),
                    matched_fields={
                        field_name: value,
                        "event_count": (
                            len(cluster)
                        ),
                        "evidence_count": (
                            len(
                                evidence_ids
                            )
                        ),
                        "window_seconds": (
                            int(
                                window.total_seconds()
                            )
                        ),
                    },
                    members=members,
                )
            )

    return candidates


def is_authentication_failure(
    event: ParsedLogEvent,
) -> bool:
    event_code = normalize_text(
        event.event_code
    )

    message = normalize_text(
        event.message
    )

    if (
        event_code
        in AUTHENTICATION_FAILURE_CODES
    ):
        return True

    return any(
        term in message
        for term
        in AUTHENTICATION_FAILURE_TERMS
    )


def is_authentication_success(
    event: ParsedLogEvent,
) -> bool:
    event_code = normalize_text(
        event.event_code
    )

    message = normalize_text(
        event.message
    )

    if (
        event_code
        in AUTHENTICATION_SUCCESS_CODES
    ):
        return True

    return any(
        term in message
        for term
        in AUTHENTICATION_SUCCESS_TERMS
    )


def authentication_key(
    event: ParsedLogEvent,
) -> tuple[str, str, str]:
    return (
        normalize_text(
            event.username
        ),
        normalize_ip(
            event.source_ip
        ),
        normalize_text(
            event.host
        ),
    )


def build_authentication_candidates(
    events: list[ParsedLogEvent],
) -> list[CorrelationCandidate]:
    groups: dict[
        tuple[str, str, str],
        list[ParsedLogEvent],
    ] = defaultdict(list)

    for event in events:
        if not (
            is_authentication_failure(
                event
            )
            or is_authentication_success(
                event
            )
        ):
            continue

        key = authentication_key(
            event
        )

        if not any(key):
            continue

        groups[key].append(event)

    window = timedelta(
        minutes=15,
    )

    candidates: list[
        CorrelationCandidate
    ] = []

    for key, grouped_events in groups.items():
        timed_events = [
            event
            for event in grouped_events
            if event.event_time
            is not None
        ]

        timed_events.sort(
            key=event_sort_key,
        )

        username, source_ip, host = key

        for success_event in timed_events:
            if not is_authentication_success(
                success_event
            ):
                continue

            success_time = normalize_datetime(
                success_event.event_time
            )

            failures = [
                event
                for event in timed_events
                if (
                    is_authentication_failure(
                        event
                    )
                    and normalize_datetime(
                        event.event_time
                    )
                    <= success_time
                    and success_time
                    - normalize_datetime(
                        event.event_time
                    )
                    <= window
                )
            ]

            if len(failures) < 3:
                continue

            members = [
                CorrelationMemberCandidate(
                    event=event,
                    relationship=(
                        "authentication_failure"
                    ),
                    matched_values={
                        "username": username,
                        "source_ip": (
                            source_ip
                        ),
                        "host": host,
                    },
                )
                for event in failures
            ]

            members.append(
                CorrelationMemberCandidate(
                    event=success_event,
                    relationship=(
                        "authentication_success"
                    ),
                    matched_values={
                        "username": username,
                        "source_ip": (
                            source_ip
                        ),
                        "host": host,
                    },
                )
            )

            correlation_key = (
                f"username:{username}|"
                f"source_ip:{source_ip}|"
                f"host:{host}|"
                f"success:{success_event.id}"
            )

            candidates.append(
                create_candidate(
                    correlation_type=(
                        EventCorrelationType
                        .authentication_sequence
                    ),
                    rule_id=(
                        "CORR-AUTH-FAILURE-SUCCESS"
                    ),
                    title=(
                        "Successful authentication "
                        "after repeated failures"
                    ),
                    description=(
                        f"A successful authentication "
                        f"was observed after "
                        f"{len(failures)} failures "
                        f"within 15 minutes."
                    ),
                    severity=(
                        LogEventSeverity.high
                    ),
                    confidence=min(
                        98,
                        85
                        + min(
                            13,
                            len(failures),
                        ),
                    ),
                    correlation_key=(
                        correlation_key
                    ),
                    mitre_tactic=(
                        "Credential Access"
                    ),
                    mitre_technique_id=(
                        "T1110"
                    ),
                    mitre_technique_name=(
                        "Brute Force"
                    ),
                    matched_fields={
                        "username": username,
                        "source_ip": (
                            source_ip
                        ),
                        "host": host,
                        "failure_count": (
                            len(failures)
                        ),
                        "window_seconds": (
                            int(
                                window.total_seconds()
                            )
                        ),
                    },
                    members=members,
                )
            )

    return candidates


def build_temporal_candidates(
    events: list[ParsedLogEvent],
    findings: list[SecurityFinding],
) -> list[CorrelationCandidate]:
    finding_event_ids = {
        finding.parsed_event_id
        for finding in findings
    }

    suspicious_events = [
        event
        for event in events
        if (
            event.id
            in finding_event_ids
            or event.severity
            in {
                LogEventSeverity.high,
                LogEventSeverity.critical,
            }
        )
    ]

    window = timedelta(
        minutes=5,
    )

    candidates: list[
        CorrelationCandidate
    ] = []

    for cluster in cluster_events(
        suspicious_events,
        window,
    ):
        evidence_ids = {
            event.evidence_id
            for event in cluster
        }

        if (
            len(cluster) < 3
            or len(evidence_ids) < 2
        ):
            continue

        members = [
            CorrelationMemberCandidate(
                event=event,
                relationship=(
                    "temporally_related"
                ),
                matched_values={
                    "event_code": (
                        event.event_code
                    ),
                    "severity": (
                        event.severity.value
                    ),
                },
            )
            for event in cluster
        ]

        candidates.append(
            create_candidate(
                correlation_type=(
                    EventCorrelationType
                    .temporal_cluster
                ),
                rule_id=(
                    "CORR-TEMPORAL-CLUSTER"
                ),
                title=(
                    "Cross-evidence suspicious "
                    "activity cluster"
                ),
                description=(
                    f"{len(cluster)} suspicious "
                    f"events from "
                    f"{len(evidence_ids)} evidence "
                    f"items occurred within "
                    f"a five-minute period."
                ),
                severity=maximum_severity(
                    cluster,
                    LogEventSeverity.medium,
                ),
                confidence=min(
                    90,
                    65
                    + min(
                        25,
                        (
                            len(cluster) - 3
                        )
                        * 5,
                    ),
                ),
                correlation_key=(
                    "temporal:"
                    + "|".join(
                        sorted(
                            str(event.id)
                            for event
                            in cluster
                        )
                    )
                ),
                matched_fields={
                    "event_count": (
                        len(cluster)
                    ),
                    "evidence_count": (
                        len(evidence_ids)
                    ),
                    "window_seconds": (
                        int(
                            window.total_seconds()
                        )
                    ),
                },
                members=members,
            )
        )

    return candidates


def build_mitre_candidates(
    events: list[ParsedLogEvent],
    findings: list[SecurityFinding],
) -> list[CorrelationCandidate]:
    event_by_id = {
        event.id: event
        for event in events
    }

    grouped_findings: dict[
        str,
        list[SecurityFinding],
    ] = defaultdict(list)

    for finding in findings:
        technique_id = normalize_text(
            finding.mitre_technique_id
        )

        if (
            technique_id
            and finding.parsed_event_id
            in event_by_id
        ):
            grouped_findings[
                technique_id
            ].append(finding)

    candidates: list[
        CorrelationCandidate
    ] = []

    window = timedelta(
        hours=1,
    )

    for (
        technique_id,
        technique_findings,
    ) in grouped_findings.items():
        unique_events = {
            finding.parsed_event_id: (
                event_by_id[
                    finding.parsed_event_id
                ]
            )
            for finding
            in technique_findings
        }

        clusters = cluster_events(
            list(
                unique_events.values()
            ),
            window,
        )

        for cluster in clusters:
            evidence_ids = {
                event.evidence_id
                for event in cluster
            }

            if (
                len(cluster) < 2
                or len(evidence_ids) < 2
            ):
                continue

            cluster_event_ids = {
                event.id
                for event in cluster
            }

            cluster_findings = [
                finding
                for finding
                in technique_findings
                if finding.parsed_event_id
                in cluster_event_ids
            ]

            first_finding = (
                cluster_findings[0]
            )

            members = [
                CorrelationMemberCandidate(
                    event=event,
                    relationship=(
                        "shared_mitre_technique"
                    ),
                    matched_values={
                        "mitre_technique_id": (
                            first_finding
                            .mitre_technique_id
                        ),
                        "mitre_tactic": (
                            first_finding
                            .mitre_tactic
                        ),
                    },
                )
                for event in cluster
            ]

            finding_severity = max(
                (
                    finding.severity
                    for finding
                    in cluster_findings
                ),
                key=lambda severity: (
                    SEVERITY_RANK[
                        severity
                    ]
                ),
            )

            confidence = max(
                finding.confidence
                for finding
                in cluster_findings
            )

            candidates.append(
                create_candidate(
                    correlation_type=(
                        EventCorrelationType
                        .mitre_technique
                    ),
                    rule_id=(
                        "CORR-MITRE-TECHNIQUE"
                    ),
                    title=(
                        "Shared MITRE ATT&CK "
                        "technique across evidence"
                    ),
                    description=(
                        f"Events from "
                        f"{len(evidence_ids)} evidence "
                        f"items map to MITRE ATT&CK "
                        f"technique "
                        f"{first_finding.mitre_technique_id}."
                    ),
                    severity=(
                        finding_severity
                    ),
                    confidence=min(
                        98,
                        max(
                            75,
                            confidence,
                        ),
                    ),
                    correlation_key=(
                        f"mitre:"
                        f"{first_finding.mitre_technique_id}"
                    ),
                    mitre_tactic=(
                        first_finding
                        .mitre_tactic
                    ),
                    mitre_technique_id=(
                        first_finding
                        .mitre_technique_id
                    ),
                    mitre_technique_name=(
                        first_finding
                        .mitre_technique_name
                    ),
                    matched_fields={
                        "mitre_tactic": (
                            first_finding
                            .mitre_tactic
                        ),
                        "mitre_technique_id": (
                            first_finding
                            .mitre_technique_id
                        ),
                        "mitre_technique_name": (
                            first_finding
                            .mitre_technique_name
                        ),
                        "finding_count": (
                            len(
                                cluster_findings
                            )
                        ),
                        "evidence_count": (
                            len(evidence_ids)
                        ),
                    },
                    members=members,
                )
            )

    return candidates


def detect_event_correlations(
    events: list[ParsedLogEvent],
    findings: list[SecurityFinding],
) -> list[CorrelationCandidate]:
    candidates: list[
        CorrelationCandidate
    ] = []

    candidates.extend(
        build_shared_indicator_candidates(
            events=events,
            extractor=lambda event: (
                normalize_text(
                    event.username
                )
            ),
            field_name="username",
            correlation_type=(
                EventCorrelationType
                .shared_identity
            ),
            rule_id=(
                "CORR-SHARED-IDENTITY"
            ),
            title=(
                "Shared identity across evidence"
            ),
            description_label="username",
            relationship=(
                "shared_identity"
            ),
            window=timedelta(
                minutes=30,
            ),
            minimum_severity=(
                LogEventSeverity.medium
            ),
            base_confidence=70,
        )
    )

    candidates.extend(
        build_shared_indicator_candidates(
            events=events,
            extractor=lambda event: (
                normalize_ip(
                    event.source_ip
                )
            ),
            field_name="source_ip",
            correlation_type=(
                EventCorrelationType
                .shared_network
            ),
            rule_id=(
                "CORR-SHARED-SOURCE-IP"
            ),
            title=(
                "Shared source IP across evidence"
            ),
            description_label=(
                "source IP address"
            ),
            relationship=(
                "shared_source_ip"
            ),
            window=timedelta(
                minutes=30,
            ),
            minimum_severity=(
                LogEventSeverity.medium
            ),
            base_confidence=75,
        )
    )

    candidates.extend(
        build_shared_indicator_candidates(
            events=events,
            extractor=lambda event: (
                normalize_ip(
                    event.destination_ip
                )
            ),
            field_name=(
                "destination_ip"
            ),
            correlation_type=(
                EventCorrelationType
                .shared_network
            ),
            rule_id=(
                "CORR-SHARED-DESTINATION-IP"
            ),
            title=(
                "Shared destination IP "
                "across evidence"
            ),
            description_label=(
                "destination IP address"
            ),
            relationship=(
                "shared_destination_ip"
            ),
            window=timedelta(
                minutes=30,
            ),
            minimum_severity=(
                LogEventSeverity.medium
            ),
            base_confidence=75,
        )
    )

    candidates.extend(
        build_shared_indicator_candidates(
            events=events,
            extractor=lambda event: (
                normalize_text(
                    event.host
                )
            ),
            field_name="host",
            correlation_type=(
                EventCorrelationType
                .shared_host
            ),
            rule_id=(
                "CORR-SHARED-HOST"
            ),
            title=(
                "Shared host across evidence"
            ),
            description_label="host",
            relationship="shared_host",
            window=timedelta(
                hours=1,
            ),
            minimum_severity=(
                LogEventSeverity.low
            ),
            base_confidence=65,
        )
    )

    candidates.extend(
        build_shared_indicator_candidates(
            events=events,
            extractor=lambda event: (
                normalize_process(
                    event.process_name
                )
            ),
            field_name="process_name",
            correlation_type=(
                EventCorrelationType
                .shared_process
            ),
            rule_id=(
                "CORR-SHARED-PROCESS"
            ),
            title=(
                "Shared process across evidence"
            ),
            description_label="process",
            relationship=(
                "shared_process"
            ),
            window=timedelta(
                minutes=30,
            ),
            minimum_severity=(
                LogEventSeverity.medium
            ),
            base_confidence=70,
        )
    )

    candidates.extend(
        build_authentication_candidates(
            events
        )
    )

    candidates.extend(
        build_temporal_candidates(
            events,
            findings,
        )
    )

    candidates.extend(
        build_mitre_candidates(
            events,
            findings,
        )
    )

    deduplicated: dict[
        str,
        CorrelationCandidate,
    ] = {}

    for candidate in candidates:
        existing = deduplicated.get(
            candidate.signature
        )

        if (
            existing is None
            or candidate.confidence
            > existing.confidence
        ):
            deduplicated[
                candidate.signature
            ] = candidate

    return list(
        deduplicated.values()
    )


def apply_candidate(
    db: Session,
    case_id: uuid.UUID,
    correlation: EventCorrelation,
    candidate: CorrelationCandidate,
) -> None:
    evidence_ids = {
        member.event.evidence_id
        for member in candidate.members
    }

    correlation.case_id = case_id
    correlation.correlation_type = (
        candidate.correlation_type
    )
    correlation.correlation_signature = (
        candidate.signature
    )
    correlation.rule_id = (
        candidate.rule_id
    )
    correlation.title = candidate.title
    correlation.description = (
        candidate.description
    )
    correlation.severity = (
        candidate.severity
    )
    correlation.confidence = (
        candidate.confidence
    )
    correlation.window_start = (
        candidate.window_start
    )
    correlation.window_end = (
        candidate.window_end
    )
    correlation.event_count = len(
        candidate.members
    )
    correlation.evidence_count = len(
        evidence_ids
    )
    correlation.correlation_key = (
        candidate.correlation_key
    )
    correlation.mitre_tactic = (
        candidate.mitre_tactic
    )
    correlation.mitre_technique_id = (
        candidate.mitre_technique_id
    )
    correlation.mitre_technique_name = (
        candidate.mitre_technique_name
    )
    correlation.matched_fields = (
        candidate.matched_fields
    )

    db.add(correlation)
    db.flush()

    db.execute(
        delete(
            EventCorrelationMember
        ).where(
            EventCorrelationMember
            .correlation_id
            == correlation.id
        )
    )

    for position, member in enumerate(
        candidate.members
    ):
        db.add(
            EventCorrelationMember(
                correlation_id=(
                    correlation.id
                ),
                case_id=case_id,
                evidence_id=(
                    member.event
                    .evidence_id
                ),
                parsed_event_id=(
                    member.event.id
                ),
                event_time=(
                    member.event
                    .event_time
                ),
                position=position,
                relationship=(
                    member.relationship
                ),
                matched_values=(
                    member
                    .matched_values
                ),
            )
        )


def run_case_event_correlation(
    db: Session,
    case_id: uuid.UUID,
) -> EventCorrelationRunResponse:
    events = list(
        db.scalars(
            select(
                ParsedLogEvent
            )
            .where(
                ParsedLogEvent.case_id
                == case_id,
                ParsedLogEvent.parse_error
                .is_(None),
            )
            .order_by(
                ParsedLogEvent.event_time
                .asc()
                .nullslast(),
                ParsedLogEvent
                .event_index.asc(),
            )
        ).all()
    )

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
                SecurityFinding
                .event_time
                .asc()
                .nullslast(),
                SecurityFinding
                .event_index.asc(),
            )
        ).all()
    )

    candidates = (
        detect_event_correlations(
            events,
            findings,
        )
    )

    candidate_by_signature = {
        candidate.signature: candidate
        for candidate in candidates
    }

    existing_correlations = list(
        db.scalars(
            select(
                EventCorrelation
            ).where(
                EventCorrelation.case_id
                == case_id
            )
        ).all()
    )

    existing_by_signature = {
        correlation
        .correlation_signature: correlation
        for correlation
        in existing_correlations
    }

    created_count = 0
    updated_count = 0
    deleted_count = 0

    for (
        signature,
        candidate,
    ) in candidate_by_signature.items():
        correlation = (
            existing_by_signature.get(
                signature
            )
        )

        if correlation is None:
            correlation = EventCorrelation(
                case_id=case_id,
                correlation_type=(
                    candidate
                    .correlation_type
                ),
                correlation_signature=(
                    signature
                ),
                rule_id=(
                    candidate.rule_id
                ),
                title=(
                    candidate.title
                ),
                description=(
                    candidate.description
                ),
            )

            created_count += 1
        else:
            updated_count += 1

        apply_candidate(
            db,
            case_id,
            correlation,
            candidate,
        )

    for correlation in existing_correlations:
        if (
            correlation
            .correlation_signature
            not in candidate_by_signature
        ):
            db.delete(correlation)
            deleted_count += 1

    db.commit()

    evidence_ids = {
        event.evidence_id
        for event in events
    }

    return EventCorrelationRunResponse(
        case_id=case_id,
        correlations_created=(
            created_count
        ),
        correlations_updated=(
            updated_count
        ),
        correlations_deleted=(
            deleted_count
        ),
        events_analyzed=len(events),
        evidence_analyzed=len(
            evidence_ids
        ),
    )