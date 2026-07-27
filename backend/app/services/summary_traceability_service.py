import hashlib
import json
import re
from datetime import (
    datetime,
    timezone,
)
from enum import Enum
from typing import Any

from app.models.case import Case
from app.schemas.investigation_summary import (
    InvestigationAssumption,
    InvestigationEvidenceReference,
    InvestigationIncidentScope,
    InvestigationMitreCoverage,
    InvestigationRecommendedAction,
    InvestigationSummaryFinding,
    InvestigationVerifiedFact,
)
from app.schemas.summary_traceability import (
    SummaryCitationSourceType,
    SummaryClaimCitation,
    SummaryClaimSection,
    SummaryClaimSupportLevel,
    SummaryTraceabilityReport,
    SummaryTraceableClaim,
)


SENTENCE_PATTERN = re.compile(
    r"(?<=[.!?])\s+(?=[A-Z0-9])"
)


SCOPE_TERMS = {
    "timeline",
    "timeline entries",
    "log events",
    "findings",
    "security findings",
    "correlations",
    "evidence",
    "critical",
    "high severity",
    "affected host",
    "affected hosts",
    "affected user",
    "affected users",
    "source ip",
    "destination ip",
    "process",
    "activity",
}


def utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def enum_value(
    value: Any,
) -> Any:
    if isinstance(
        value,
        Enum,
    ):
        return value.value

    return value


def normalize_text(
    value: Any,
) -> str:
    if value is None:
        return ""

    return str(value).strip()


def normalize_comparable(
    value: Any,
) -> str:
    return normalize_text(
        value
    ).casefold()


def serialize_datetime(
    value: datetime | None,
) -> str | None:
    if value is None:
        return None

    return value.isoformat()


def calculate_sha256(
    value: Any,
) -> str:
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    return hashlib.sha256(
        serialized.encode(
            "utf-8"
        )
    ).hexdigest()


def stable_identifier(
    prefix: str,
    *parts: Any,
) -> str:
    normalized_parts = [
        normalize_text(part)
        for part in parts
    ]

    digest = calculate_sha256(
        normalized_parts
    )[:24]

    return f"{prefix}-{digest}"


def split_claim_text(
    value: str,
) -> list[str]:
    normalized = " ".join(
        value.split()
    )

    if not normalized:
        return []

    claims = [
        item.strip()
        for item in SENTENCE_PATTERN.split(
            normalized
        )
        if item.strip()
    ]

    return claims or [
        normalized
    ]


def safe_metadata(
    values: dict[str, Any],
) -> dict[str, Any]:
    metadata: dict[
        str,
        Any,
    ] = {}

    for key, value in values.items():
        normalized_key = (
            normalize_text(key)
        )

        if not normalized_key:
            continue

        if value is None:
            continue

        if isinstance(
            value,
            Enum,
        ):
            metadata[
                normalized_key
            ] = value.value
            continue

        if isinstance(
            value,
            datetime,
        ):
            metadata[
                normalized_key
            ] = value.isoformat()
            continue

        if isinstance(
            value,
            (
                str,
                int,
                float,
                bool,
            ),
        ):
            metadata[
                normalized_key
            ] = value

    return metadata


def make_citation(
    source_type:
        SummaryCitationSourceType,
    label: str,
    relationship: str,
    source_id: str | None = None,
    evidence_id: str | None = None,
    event_time: datetime | None = None,
    integrity_sha256: str | None = None,
    metadata: dict[
        str,
        Any,
    ] | None = None,
) -> SummaryClaimCitation:
    normalized_source_id = (
        normalize_text(
            source_id
        )
        or None
    )

    normalized_evidence_id = (
        normalize_text(
            evidence_id
        )
        or None
    )

    normalized_hash = (
        normalize_text(
            integrity_sha256
        )
        or None
    )

    citation_id = stable_identifier(
        "citation",
        source_type.value,
        normalized_source_id,
        normalized_evidence_id,
        label,
        relationship,
        serialize_datetime(
            event_time
        ),
    )

    return SummaryClaimCitation(
        citation_id=citation_id,
        source_type=source_type,
        source_id=(
            normalized_source_id
        ),
        evidence_id=(
            normalized_evidence_id
        ),
        label=label.strip()[:500],
        relationship=(
            relationship.strip()[:200]
        ),
        event_time=event_time,
        integrity_sha256=(
            normalized_hash
        ),
        metadata=safe_metadata(
            metadata or {}
        ),
    )


def deduplicate_citations(
    citations: list[
        SummaryClaimCitation
    ],
) -> list[
    SummaryClaimCitation
]:
    unique: list[
        SummaryClaimCitation
    ] = []

    seen: set[str] = set()

    for citation in citations:
        if (
            citation.citation_id
            in seen
        ):
            continue

        seen.add(
            citation.citation_id
        )

        unique.append(
            citation
        )

    return unique


def evidence_reference_map(
    references: list[
        InvestigationEvidenceReference
    ],
) -> dict[
    str,
    InvestigationEvidenceReference,
]:
    return {
        str(reference.evidence_id):
            reference
        for reference in references
    }


def build_case_citation(
    investigation_case: Case,
) -> SummaryClaimCitation:
    return make_citation(
        source_type=(
            SummaryCitationSourceType
            .case
        ),
        source_id=str(
            investigation_case.id
        ),
        label=(
            investigation_case.title
        ),
        relationship=(
            "Provides case context"
        ),
        metadata={
            "severity":
                enum_value(
                    investigation_case
                    .severity
                ),
            "status":
                enum_value(
                    investigation_case
                    .status
                ),
        },
    )


def build_scope_citation(
    investigation_case: Case,
    scope: InvestigationIncidentScope,
) -> SummaryClaimCitation:
    return make_citation(
        source_type=(
            SummaryCitationSourceType
            .incident_scope
        ),
        source_id=str(
            investigation_case.id
        ),
        label=(
            "Calculated investigation "
            "scope"
        ),
        relationship=(
            "Supports derived scope "
            "statement"
        ),
        event_time=(
            scope.last_activity_at
        ),
        metadata={
            "total_timeline_entries":
                scope
                .total_timeline_entries,
            "log_event_count":
                scope.log_event_count,
            "security_finding_count":
                scope
                .security_finding_count,
            "event_correlation_count":
                scope
                .event_correlation_count,
            "evidence_count":
                scope.evidence_count,
            "critical_count":
                scope.critical_count,
            "high_count":
                scope.high_count,
            "first_activity_at":
                serialize_datetime(
                    scope
                    .first_activity_at
                ),
            "last_activity_at":
                serialize_datetime(
                    scope
                    .last_activity_at
                ),
        },
    )


def build_evidence_citation(
    reference:
        InvestigationEvidenceReference,
    relationship: str,
) -> SummaryClaimCitation:
    return make_citation(
        source_type=(
            SummaryCitationSourceType
            .evidence
        ),
        source_id=str(
            reference.evidence_id
        ),
        evidence_id=str(
            reference.evidence_id
        ),
        label=(
            reference.original_filename
        ),
        relationship=relationship,
        event_time=(
            reference.collected_at
            or reference.created_at
        ),
        integrity_sha256=(
            reference.sha256
        ),
        metadata={
            "evidence_type":
                reference.evidence_type,
            "source":
                reference.source,
            "size_bytes":
                reference.size_bytes,
            "related_event_count":
                reference
                .related_event_count,
            "related_finding_count":
                reference
                .related_finding_count,
            "related_correlation_count":
                reference
                .related_correlation_count,
        },
    )


def build_finding_citations(
    finding:
        InvestigationSummaryFinding,
    references: dict[
        str,
        InvestigationEvidenceReference,
    ],
) -> list[
    SummaryClaimCitation
]:
    citations: list[
        SummaryClaimCitation
    ] = []

    metadata = {
        "severity":
            enum_value(
                finding.severity
            ),
        "confidence":
            finding.confidence,
        "rule_id":
            finding.rule_id,
        "event_code":
            finding.event_code,
        "source_type":
            finding.source_type,
        "mitre_tactic":
            finding.mitre_tactic,
        "mitre_technique_id":
            finding
            .mitre_technique_id,
        "mitre_technique_name":
            finding
            .mitre_technique_name,
    }

    if finding.security_finding_id:
        citations.append(
            make_citation(
                source_type=(
                    SummaryCitationSourceType
                    .security_finding
                ),
                source_id=str(
                    finding
                    .security_finding_id
                ),
                evidence_id=(
                    str(
                        finding.evidence_id
                    )
                    if finding.evidence_id
                    else None
                ),
                label=(
                    finding.title
                ),
                relationship=(
                    "Directly supports "
                    "the finding"
                ),
                event_time=(
                    finding.event_time
                ),
                metadata=metadata,
            )
        )

    if finding.parsed_event_id:
        citations.append(
            make_citation(
                source_type=(
                    SummaryCitationSourceType
                    .parsed_log_event
                ),
                source_id=str(
                    finding
                    .parsed_event_id
                ),
                evidence_id=(
                    str(
                        finding.evidence_id
                    )
                    if finding.evidence_id
                    else None
                ),
                label=(
                    finding.event_code
                    or finding.title
                ),
                relationship=(
                    "Provides the normalised "
                    "source event"
                ),
                event_time=(
                    finding.event_time
                ),
                metadata=metadata,
            )
        )

    if finding.correlation_id:
        citations.append(
            make_citation(
                source_type=(
                    SummaryCitationSourceType
                    .event_correlation
                ),
                source_id=str(
                    finding
                    .correlation_id
                ),
                evidence_id=(
                    str(
                        finding.evidence_id
                    )
                    if finding.evidence_id
                    else None
                ),
                label=(
                    finding.title
                ),
                relationship=(
                    "Provides correlated "
                    "event support"
                ),
                event_time=(
                    finding.event_time
                ),
                metadata=metadata,
            )
        )

    if finding.rule_id:
        citations.append(
            make_citation(
                source_type=(
                    SummaryCitationSourceType
                    .deterministic_rule
                ),
                source_id=(
                    finding.rule_id
                ),
                evidence_id=(
                    str(
                        finding.evidence_id
                    )
                    if finding.evidence_id
                    else None
                ),
                label=(
                    finding.rule_id
                ),
                relationship=(
                    "Identifies the "
                    "detection rule"
                ),
                event_time=(
                    finding.event_time
                ),
                metadata=metadata,
            )
        )

    if (
        finding.mitre_technique_id
    ):
        citations.append(
            make_citation(
                source_type=(
                    SummaryCitationSourceType
                    .mitre_mapping
                ),
                source_id=(
                    finding
                    .mitre_technique_id
                ),
                evidence_id=(
                    str(
                        finding.evidence_id
                    )
                    if finding.evidence_id
                    else None
                ),
                label=(
                    (
                        f"{finding.mitre_technique_id} "
                        f"{finding.mitre_technique_name}"
                    ).strip()
                ),
                relationship=(
                    "Supports the MITRE "
                    "ATT&CK mapping"
                ),
                event_time=(
                    finding.event_time
                ),
                metadata=metadata,
            )
        )

    if finding.evidence_id:
        reference = references.get(
            str(
                finding.evidence_id
            )
        )

        if reference is not None:
            citations.append(
                build_evidence_citation(
                    reference,
                    (
                        "Contains evidence "
                        "related to the finding"
                    ),
                )
            )

    return deduplicate_citations(
        citations
    )


def claim_contains(
    claim_text: str,
    value: Any,
) -> bool:
    normalized_value = (
        normalize_comparable(
            value
        )
    )

    if not normalized_value:
        return False

    return (
        normalized_value
        in normalize_comparable(
            claim_text
        )
    )


def claim_mentions_scope(
    claim_text: str,
    scope:
        InvestigationIncidentScope,
) -> bool:
    normalized_claim = (
        normalize_comparable(
            claim_text
        )
    )

    if any(
        term in normalized_claim
        for term in SCOPE_TERMS
    ):
        return True

    entity_values = (
        list(scope.affected_hosts)
        + list(
            scope.affected_usernames
        )
        + list(
            scope.observed_source_ips
        )
        + list(
            scope.observed_destination_ips
        )
        + list(
            scope.observed_processes
        )
    )

    return any(
        claim_contains(
            claim_text,
            value,
        )
        for value in entity_values
    )


def find_matching_citations(
    claim_text: str,
    findings: list[
        InvestigationSummaryFinding
    ],
    references: dict[
        str,
        InvestigationEvidenceReference,
    ],
) -> list[
    SummaryClaimCitation
]:
    citations: list[
        SummaryClaimCitation
    ] = []

    for finding in findings:
        match_values = [
            finding.title,
            finding.rule_id,
            finding.event_code,
            finding
            .mitre_technique_id,
            finding
            .mitre_technique_name,
        ]

        if not any(
            claim_contains(
                claim_text,
                value,
            )
            for value in match_values
        ):
            continue

        citations.extend(
            build_finding_citations(
                finding,
                references,
            )
        )

    for reference in (
        references.values()
    ):
        if (
            claim_contains(
                claim_text,
                reference
                .original_filename,
            )
            or claim_contains(
                claim_text,
                reference.sha256,
            )
        ):
            citations.append(
                build_evidence_citation(
                    reference,
                    (
                        "Explicitly referenced "
                        "by the claim"
                    ),
                )
            )

    return deduplicate_citations(
        citations
    )


def determine_support_level(
    citations: list[
        SummaryClaimCitation
    ],
) -> SummaryClaimSupportLevel:
    direct_types = {
        SummaryCitationSourceType
        .evidence,
        SummaryCitationSourceType
        .parsed_log_event,
        SummaryCitationSourceType
        .security_finding,
        SummaryCitationSourceType
        .event_correlation,
        SummaryCitationSourceType
        .case_audit_event,
        SummaryCitationSourceType
        .evidence_custody_event,
    }

    derived_types = {
        SummaryCitationSourceType
        .incident_scope,
        SummaryCitationSourceType
        .mitre_mapping,
        SummaryCitationSourceType
        .deterministic_rule,
    }

    if any(
        citation.source_type
        in direct_types
        for citation in citations
    ):
        return (
            SummaryClaimSupportLevel
            .direct
        )

    if any(
        citation.source_type
        in derived_types
        for citation in citations
    ):
        return (
            SummaryClaimSupportLevel
            .derived
        )

    if citations:
        return (
            SummaryClaimSupportLevel
            .contextual
        )

    return (
        SummaryClaimSupportLevel
        .unsupported
    )


def make_claim(
    section:
        SummaryClaimSection,
    ordinal: int,
    text: str,
    citations: list[
        SummaryClaimCitation
    ],
    unsupported_reason: str = "",
) -> SummaryTraceableClaim:
    unique_citations = (
        deduplicate_citations(
            citations
        )
    )

    support_level = (
        determine_support_level(
            unique_citations
        )
    )

    supported = (
        support_level
        != SummaryClaimSupportLevel
        .unsupported
    )

    reason = (
        ""
        if supported
        else (
            unsupported_reason.strip()
            or (
                "No structured supporting "
                "source was linked to this "
                "claim."
            )
        )
    )

    return SummaryTraceableClaim(
        claim_id=stable_identifier(
            "claim",
            section.value,
            ordinal,
            text,
        ),
        section=section,
        ordinal=ordinal,
        text=text.strip(),
        support_level=(
            support_level
        ),
        supported=supported,
        citations=unique_citations,
        unsupported_reason=reason,
    )


def build_narrative_claims(
    section:
        SummaryClaimSection,
    narrative: str,
    investigation_case: Case,
    scope:
        InvestigationIncidentScope,
    findings: list[
        InvestigationSummaryFinding
    ],
    references: dict[
        str,
        InvestigationEvidenceReference,
    ],
) -> list[
    SummaryTraceableClaim
]:
    claims: list[
        SummaryTraceableClaim
    ] = []

    scope_citation = (
        build_scope_citation(
            investigation_case,
            scope,
        )
    )

    case_citation = (
        build_case_citation(
            investigation_case
        )
    )

    for ordinal, claim_text in (
        enumerate(
            split_claim_text(
                narrative
            )
        )
    ):
        citations = (
            find_matching_citations(
                claim_text,
                findings,
                references,
            )
        )

        if claim_mentions_scope(
            claim_text,
            scope,
        ):
            citations.append(
                scope_citation
            )

        if not citations:
            citations.append(
                case_citation
            )

            if findings:
                citations.extend(
                    build_finding_citations(
                        findings[0],
                        references,
                    )
                )

            else:
                citations.append(
                    scope_citation
                )

        claims.append(
            make_claim(
                section=section,
                ordinal=ordinal,
                text=claim_text,
                citations=citations,
            )
        )

    return claims


def build_finding_claims(
    findings: list[
        InvestigationSummaryFinding
    ],
    references: dict[
        str,
        InvestigationEvidenceReference,
    ],
) -> list[
    SummaryTraceableClaim
]:
    return [
        make_claim(
            section=(
                SummaryClaimSection
                .technical_finding
            ),
            ordinal=index,
            text=(
                (
                    f"{finding.title}. "
                    f"{finding.description}"
                ).strip()
            ),
            citations=(
                build_finding_citations(
                    finding,
                    references,
                )
            ),
        )
        for index, finding
        in enumerate(findings)
    ]


def build_scope_claims(
    investigation_case: Case,
    scope:
        InvestigationIncidentScope,
) -> list[
    SummaryTraceableClaim
]:
    citation = build_scope_citation(
        investigation_case,
        scope,
    )

    claim_texts = [
        (
            "The investigation contains "
            f"{scope.total_timeline_entries} "
            "timeline entries, "
            f"{scope.log_event_count} log "
            "events, "
            f"{scope.security_finding_count} "
            "security findings, and "
            f"{scope.event_correlation_count} "
            "event correlations."
        ),
        (
            "The investigation references "
            f"{scope.evidence_count} evidence "
            "items, including "
            f"{scope.critical_count} critical "
            "and "
            f"{scope.high_count} high-severity "
            "records."
        ),
    ]

    if (
        scope.first_activity_at
        or scope.last_activity_at
    ):
        claim_texts.append(
            (
                "Observed activity ranges from "
                f"{serialize_datetime(scope.first_activity_at)} "
                "to "
                f"{serialize_datetime(scope.last_activity_at)}."
            )
        )

    return [
        make_claim(
            section=(
                SummaryClaimSection
                .incident_scope
            ),
            ordinal=index,
            text=text,
            citations=[
                citation
            ],
        )
        for index, text
        in enumerate(claim_texts)
    ]


def build_mitre_claims(
    coverage:
        InvestigationMitreCoverage,
) -> list[
    SummaryTraceableClaim
]:
    claims: list[
        SummaryTraceableClaim
    ] = []

    for index, technique in (
        enumerate(
            coverage.techniques
        )
    ):
        citation = make_citation(
            source_type=(
                SummaryCitationSourceType
                .mitre_mapping
            ),
            source_id=(
                technique.technique_id
            ),
            label=(
                (
                    f"{technique.technique_id} "
                    f"{technique.technique_name}"
                ).strip()
            ),
            relationship=(
                "Supports the recorded MITRE "
                "ATT&CK mapping"
            ),
            metadata={
                "tactic":
                    technique.tactic,
                "finding_count":
                    technique
                    .finding_count,
                "correlation_count":
                    technique
                    .correlation_count,
            },
        )

        claims.append(
            make_claim(
                section=(
                    SummaryClaimSection
                    .mitre_coverage
                ),
                ordinal=index,
                text=(
                    (
                        f"{technique.technique_id} "
                        f"{technique.technique_name} "
                        "is mapped under "
                        f"{technique.tactic or 'an unspecified tactic'}."
                    ).strip()
                ),
                citations=[
                    citation
                ],
            )
        )

    return claims


def build_action_claims(
    actions: list[
        InvestigationRecommendedAction
    ],
    findings: list[
        InvestigationSummaryFinding
    ],
    references: dict[
        str,
        InvestigationEvidenceReference,
    ],
) -> list[
    SummaryTraceableClaim
]:
    claims: list[
        SummaryTraceableClaim
    ] = []

    for index, action in (
        enumerate(actions)
    ):
        citations: list[
            SummaryClaimCitation
        ] = []

        for finding in findings:
            if (
                finding.rule_id
                in action.related_rule_ids
                or (
                    finding
                    .mitre_technique_id
                    in action
                    .related_mitre_technique_ids
                )
                or (
                    finding.evidence_id
                    and finding.evidence_id
                    in action
                    .related_evidence_ids
                )
            ):
                citations.extend(
                    build_finding_citations(
                        finding,
                        references,
                    )
                )

        for evidence_id in (
            action.related_evidence_ids
        ):
            reference = references.get(
                str(evidence_id)
            )

            if reference is not None:
                citations.append(
                    build_evidence_citation(
                        reference,
                        (
                            "Supports the "
                            "recommended action"
                        ),
                    )
                )

        claims.append(
            make_claim(
                section=(
                    SummaryClaimSection
                    .recommended_action
                ),
                ordinal=index,
                text=(
                    (
                        f"{action.title}. "
                        f"{action.description} "
                        f"{action.rationale}"
                    ).strip()
                ),
                citations=citations,
                unsupported_reason=(
                    "The recommendation has "
                    "no linked finding, rule, "
                    "MITRE mapping, or evidence "
                    "reference."
                ),
            )
        )

    return claims


def source_type_from_value(
    value: str,
) -> SummaryCitationSourceType:
    normalized = (
        normalize_comparable(
            value
        )
    )

    mapping = {
        "case":
            SummaryCitationSourceType
            .case,
        "evidence":
            SummaryCitationSourceType
            .evidence,
        "parsed_log_event":
            SummaryCitationSourceType
            .parsed_log_event,
        "forensic_timeline":
            SummaryCitationSourceType
            .incident_scope,
        "security_finding":
            SummaryCitationSourceType
            .security_finding,
        "event_correlation":
            SummaryCitationSourceType
            .event_correlation,
        "case_audit_event":
            SummaryCitationSourceType
            .case_audit_event,
        "evidence_custody_event":
            SummaryCitationSourceType
            .evidence_custody_event,
        "mitre_mapping":
            SummaryCitationSourceType
            .mitre_mapping,
        "analyst":
            SummaryCitationSourceType
            .analyst,
    }

    return mapping.get(
        normalized,
        SummaryCitationSourceType
        .deterministic_rule,
    )


def build_fact_claims(
    facts: list[
        InvestigationVerifiedFact
    ],
) -> list[
    SummaryTraceableClaim
]:
    claims: list[
        SummaryTraceableClaim
    ] = []

    for index, fact in (
        enumerate(facts)
    ):
        source_type = (
            source_type_from_value(
                fact.source_type
            )
        )

        citations = [
            make_citation(
                source_type=source_type,
                source_id=source_id,
                label=(
                    fact.source_type
                    or "Verified fact source"
                ),
                relationship=(
                    "Supports the verified "
                    "fact"
                ),
                metadata={
                    "confidence":
                        fact.confidence,
                },
            )
            for source_id
            in fact.source_ids
        ]

        if not citations:
            citations.append(
                make_citation(
                    source_type=source_type,
                    source_id=(
                        fact.source_type
                        or "verified-fact"
                    ),
                    label=(
                        fact.source_type
                        or "Verified fact"
                    ),
                    relationship=(
                        "Provides the recorded "
                        "fact source"
                    ),
                    metadata={
                        "confidence":
                            fact.confidence,
                    },
                )
            )

        claims.append(
            make_claim(
                section=(
                    SummaryClaimSection
                    .verified_fact
                ),
                ordinal=index,
                text=fact.statement,
                citations=citations,
            )
        )

    return claims


def build_assumption_claims(
    assumptions: list[
        InvestigationAssumption
    ],
) -> list[
    SummaryTraceableClaim
]:
    return [
        make_claim(
            section=(
                SummaryClaimSection
                .assumption
            ),
            ordinal=index,
            text=(
                (
                    f"{assumption.statement} "
                    f"{assumption.reason}"
                ).strip()
            ),
            citations=[
                make_citation(
                    source_type=(
                        SummaryCitationSourceType
                        .deterministic_rule
                    ),
                    source_id=(
                        "summary-assumption"
                    ),
                    label=(
                        "Recorded investigation "
                        "assumption"
                    ),
                    relationship=(
                        "Marks the statement as "
                        "an assumption"
                    ),
                    metadata={
                        "confidence":
                            assumption
                            .confidence,
                    },
                )
            ],
        )
        for index, assumption
        in enumerate(assumptions)
    ]


def build_limitation_claims(
    limitations: list[str],
) -> list[
    SummaryTraceableClaim
]:
    return [
        make_claim(
            section=(
                SummaryClaimSection
                .limitation
            ),
            ordinal=index,
            text=limitation,
            citations=[
                make_citation(
                    source_type=(
                        SummaryCitationSourceType
                        .deterministic_rule
                    ),
                    source_id=(
                        "summary-limitation"
                    ),
                    label=(
                        "Recorded investigation "
                        "limitation"
                    ),
                    relationship=(
                        "Marks a known data or "
                        "analysis limitation"
                    ),
                )
            ],
        )
        for index, limitation
        in enumerate(limitations)
        if limitation.strip()
    ]


def build_summary_traceability_report(
    investigation_case: Case,
    executive_summary: str,
    technical_narrative: str,
    findings: list[
        InvestigationSummaryFinding
    ],
    scope:
        InvestigationIncidentScope,
    mitre_coverage:
        InvestigationMitreCoverage,
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
    generated_at: datetime | None = None,
) -> SummaryTraceabilityReport:
    timestamp = (
        generated_at
        or utc_now()
    )

    references = (
        evidence_reference_map(
            evidence_references
        )
    )

    claims: list[
        SummaryTraceableClaim
    ] = []

    claims.extend(
        build_narrative_claims(
            section=(
                SummaryClaimSection
                .executive_summary
            ),
            narrative=(
                executive_summary
            ),
            investigation_case=(
                investigation_case
            ),
            scope=scope,
            findings=findings,
            references=references,
        )
    )

    claims.extend(
        build_narrative_claims(
            section=(
                SummaryClaimSection
                .technical_narrative
            ),
            narrative=(
                technical_narrative
            ),
            investigation_case=(
                investigation_case
            ),
            scope=scope,
            findings=findings,
            references=references,
        )
    )

    claims.extend(
        build_finding_claims(
            findings,
            references,
        )
    )

    claims.extend(
        build_scope_claims(
            investigation_case,
            scope,
        )
    )

    claims.extend(
        build_mitre_claims(
            mitre_coverage
        )
    )

    claims.extend(
        build_action_claims(
            recommended_actions,
            findings,
            references,
        )
    )

    claims.extend(
        build_fact_claims(
            verified_facts
        )
    )

    claims.extend(
        build_assumption_claims(
            assumptions
        )
    )

    claims.extend(
        build_limitation_claims(
            limitations
        )
    )

    supported_claim_count = sum(
        1
        for claim in claims
        if claim.supported
    )

    unsupported_claim_count = (
        len(claims)
        - supported_claim_count
    )

    direct_support_count = sum(
        1
        for claim in claims
        if (
            claim.support_level
            == SummaryClaimSupportLevel
            .direct
        )
    )

    derived_support_count = sum(
        1
        for claim in claims
        if (
            claim.support_level
            == SummaryClaimSupportLevel
            .derived
        )
    )

    contextual_support_count = sum(
        1
        for claim in claims
        if (
            claim.support_level
            == SummaryClaimSupportLevel
            .contextual
        )
    )

    citation_count = sum(
        len(
            claim.citations
        )
        for claim in claims
    )

    report_payload = {
        "schema_version":
            "1.0.0",
        "claims": [
            claim.model_dump(
                mode="json"
            )
            for claim in claims
        ],
        "total_claim_count":
            len(claims),
        "supported_claim_count":
            supported_claim_count,
        "unsupported_claim_count":
            unsupported_claim_count,
        "direct_support_count":
            direct_support_count,
        "derived_support_count":
            derived_support_count,
        "contextual_support_count":
            contextual_support_count,
        "citation_count":
            citation_count,
        "generated_at":
            timestamp.isoformat(),
    }

    return SummaryTraceabilityReport(
        schema_version="1.0.0",
        claims=claims,
        total_claim_count=(
            len(claims)
        ),
        supported_claim_count=(
            supported_claim_count
        ),
        unsupported_claim_count=(
            unsupported_claim_count
        ),
        direct_support_count=(
            direct_support_count
        ),
        derived_support_count=(
            derived_support_count
        ),
        contextual_support_count=(
            contextual_support_count
        ),
        citation_count=(
            citation_count
        ),
        generated_at=timestamp,
        report_sha256=(
            calculate_sha256(
                report_payload
            )
        ),
    )