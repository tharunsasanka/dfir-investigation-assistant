import ipaddress
import json
import re
from enum import Enum
from typing import Any

from pydantic import (
    BaseModel,
    Field,
)

from app.services.ai_summary_provider import (
    AISummaryProviderOutput,
    AISummarySafeContext,
)


class AISummaryValidationSeverity(
    str,
    Enum,
):
    warning = "warning"
    error = "error"


class AISummaryValidationIssue(
    BaseModel,
):
    code: str = Field(
        min_length=1,
        max_length=100,
    )

    severity: AISummaryValidationSeverity

    field_name: str = Field(
        min_length=1,
        max_length=100,
    )

    value: str = Field(
        default="",
        max_length=1000,
    )

    message: str = Field(
        min_length=1,
        max_length=2000,
    )


class AISummaryValidationResult(
    BaseModel,
):
    is_valid: bool

    issues: list[
        AISummaryValidationIssue
    ] = Field(
        default_factory=list,
    )

    checked_entity_count: int = Field(
        default=0,
        ge=0,
    )

    unsupported_entity_count: int = Field(
        default=0,
        ge=0,
    )

    unsupported_claim_count: int = Field(
        default=0,
        ge=0,
    )

    count_mismatch_count: int = Field(
        default=0,
        ge=0,
    )


class AISummaryValidationError(
    RuntimeError,
):
    def __init__(
        self,
        result: AISummaryValidationResult,
    ):
        self.result = result

        issue_codes = sorted(
            {
                issue.code
                for issue in result.issues
            }
        )

        message = (
            "Local AI output failed "
            "factual validation."
        )

        if issue_codes:
            message += (
                " Issues: "
                + ", ".join(issue_codes)
                + "."
            )

        super().__init__(message)

HIGH_RISK_CLAIMS = [
    "account takeover",
    "attributed to",
    "command and control",
    "confirmed compromise",
    "credential dumping",
    "credential theft",
    "data destruction",
    "data exfiltration",
    "initial compromise",
    "lateral movement",
    "malware infection",
    "privilege escalation",
    "ransomware",
    "root cause",
    "threat actor",
]


COUNT_LABELS = {
    "timeline entries":
        "total_timeline_entries",
    "log events":
        "log_event_count",
    "security findings":
        "security_finding_count",
    "findings":
        "security_finding_count",
    "event correlations":
        "event_correlation_count",
    "correlations":
        "event_correlation_count",
    "case audit events":
        "case_audit_count",
    "evidence custody events":
        "evidence_custody_count",
    "evidence items":
        "evidence_count",
    "critical findings":
        "critical_count",
    "high findings":
        "high_count",
    "mitre tactics":
        "tactic_count",
    "tactics":
        "tactic_count",
    "mitre techniques":
        "technique_count",
    "techniques":
        "technique_count",
}


IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


MITRE_PATTERN = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)


HASH_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


TIMESTAMP_PATTERN = re.compile(
    r"\b"
    r"\d{4}-\d{2}-\d{2}"
    r"(?:"
    r"T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})?"
    r")?"
    r"\b"
)


EMAIL_PATTERN = re.compile(
    r"\b"
    r"[A-Za-z0-9._%+-]+"
    r"@"
    r"[A-Za-z0-9.-]+"
    r"\.[A-Za-z]{2,}"
    r"\b"
)


DOMAIN_USER_PATTERN = re.compile(
    r"\b"
    r"[A-Za-z0-9._-]+"
    r"\\"
    r"[A-Za-z0-9._-]+"
    r"\b"
)


URL_PATTERN = re.compile(
    r"\b"
    r"https?://"
    r"[^\s<>()\"']+",
    re.IGNORECASE,
)


EVENT_CODE_PATTERN = re.compile(
    r"\b"
    r"event"
    r"(?:\s+(?:id|code))?"
    r"\s*[:#-]?\s*"
    r"(\d{3,8})"
    r"\b",
    re.IGNORECASE,
)


IDENTIFIER_PATTERN = re.compile(
    r"\b"
    r"[A-Z][A-Z0-9]+"
    r"(?:[-_][A-Z0-9]+)+"
    r"\b"
)


COUNT_PATTERN = re.compile(
    r"\b(\d+)\s+"
    r"("
    + "|".join(
        re.escape(label)
        for label in sorted(
            COUNT_LABELS,
            key=len,
            reverse=True,
        )
    )
    + r")\b",
    re.IGNORECASE,
)


def normalize_value(
    value: Any,
) -> str:
    if value is None:
        return ""

    return str(value).strip()


def normalize_comparable(
    value: Any,
) -> str:
    return normalize_value(
        value
    ).casefold()


def add_if_present(
    destination: set[str],
    value: Any,
) -> None:
    normalized = normalize_comparable(
        value
    )

    if normalized:
        destination.add(
            normalized
        )


def values_from_list(
    value: Any,
) -> list[Any]:
    if not isinstance(
        value,
        list,
    ):
        return []

    return value


def dictionaries_from_list(
    value: Any,
) -> list[dict[str, Any]]:
    if not isinstance(
        value,
        list,
    ):
        return []

    return [
        item
        for item in value
        if isinstance(
            item,
            dict,
        )
    ]


def build_source_corpus(
    context: AISummarySafeContext,
) -> str:
    payload = context.model_dump(
        mode="json"
    )

    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
    ).casefold()


def build_allowed_entities(
    context: AISummarySafeContext,
) -> dict[str, set[str]]:
    allowed = {
        "ips": set(),
        "mitre_ids": set(),
        "hashes": set(),
        "timestamps": set(),
        "usernames": set(),
        "hosts": set(),
        "processes": set(),
        "rule_ids": set(),
        "event_codes": set(),
        "identifiers": set(),
        "urls": set(),
    }

    scope = context.incident_scope

    for value in values_from_list(
        scope.get(
            "observed_source_ips"
        )
    ):
        add_if_present(
            allowed["ips"],
            value,
        )

    for value in values_from_list(
        scope.get(
            "observed_destination_ips"
        )
    ):
        add_if_present(
            allowed["ips"],
            value,
        )

    for value in values_from_list(
        scope.get(
            "affected_usernames"
        )
    ):
        add_if_present(
            allowed["usernames"],
            value,
        )

        add_if_present(
            allowed["identifiers"],
            value,
        )

    for value in values_from_list(
        scope.get(
            "affected_hosts"
        )
    ):
        add_if_present(
            allowed["hosts"],
            value,
        )

        add_if_present(
            allowed["identifiers"],
            value,
        )

    for value in values_from_list(
        scope.get(
            "observed_processes"
        )
    ):
        add_if_present(
            allowed["processes"],
            value,
        )

        add_if_present(
            allowed["identifiers"],
            value,
        )

    add_if_present(
        allowed["timestamps"],
        scope.get(
            "first_activity_at"
        ),
    )

    add_if_present(
        allowed["timestamps"],
        scope.get(
            "last_activity_at"
        ),
    )

    for finding in (
        context.technical_findings
    ):
        add_if_present(
            allowed["rule_ids"],
            finding.get(
                "rule_id"
            ),
        )

        add_if_present(
            allowed["identifiers"],
            finding.get(
                "rule_id"
            ),
        )

        add_if_present(
            allowed["event_codes"],
            finding.get(
                "event_code"
            ),
        )

        add_if_present(
            allowed["mitre_ids"],
            finding.get(
                "mitre_technique_id"
            ),
        )

        add_if_present(
            allowed["timestamps"],
            finding.get(
                "event_time"
            ),
        )

    techniques = dictionaries_from_list(
        context.mitre_coverage.get(
            "techniques"
        )
    )

    for technique in techniques:
        add_if_present(
            allowed["mitre_ids"],
            technique.get(
                "technique_id"
            ),
        )

        for rule_id in values_from_list(
            technique.get(
                "related_rule_ids"
            )
        ):
            add_if_present(
                allowed["rule_ids"],
                rule_id,
            )

            add_if_present(
                allowed["identifiers"],
                rule_id,
            )

    for action in (
        context.recommended_actions
    ):
        for rule_id in values_from_list(
            action.get(
                "related_rule_ids"
            )
        ):
            add_if_present(
                allowed["rule_ids"],
                rule_id,
            )

            add_if_present(
                allowed["identifiers"],
                rule_id,
            )

        for technique_id in values_from_list(
            action.get(
                "related_mitre_technique_ids"
            )
        ):
            add_if_present(
                allowed["mitre_ids"],
                technique_id,
            )

    return allowed


def extract_valid_ipv4_addresses(
    text: str,
) -> set[str]:
    addresses: set[str] = set()

    candidates = (
        IPV4_PATTERN.findall(
            text
        )
    )

    for candidate in candidates:
        try:
            parsed = ipaddress.ip_address(
                candidate
            )

        except ValueError:
            continue

        if parsed.version != 4:
            continue

        addresses.add(
            parsed.compressed.casefold()
        )

    return addresses


def extract_normalized_matches(
    pattern: re.Pattern[str],
    text: str,
) -> set[str]:
    return {
        normalize_comparable(
            match
        )
        for match in pattern.findall(
            text
        )
        if normalize_comparable(
            match
        )
    }


def output_fields(
    output: AISummaryProviderOutput,
) -> dict[str, str]:
    return {
        "executive_summary":
            output.executive_summary,
        "technical_narrative":
            output.technical_narrative,
        "additional_limitations":
            "\n".join(
                output
                .additional_limitations
            ),
    }


def make_issue(
    code: str,
    severity: AISummaryValidationSeverity,
    field_name: str,
    value: str,
    message: str,
) -> AISummaryValidationIssue:
    return AISummaryValidationIssue(
        code=code,
        severity=severity,
        field_name=field_name,
        value=value,
        message=message,
    )


def append_unique_issue(
    issues: list[
        AISummaryValidationIssue
    ],
    issue: AISummaryValidationIssue,
) -> None:
    identity = (
        issue.code,
        issue.field_name,
        issue.value.casefold(),
    )

    for existing in issues:
        existing_identity = (
            existing.code,
            existing.field_name,
            existing.value.casefold(),
        )

        if (
            existing_identity
            == identity
        ):
            return

    issues.append(issue)


def validate_entity_set(
    issues: list[
        AISummaryValidationIssue
    ],
    field_name: str,
    candidates: set[str],
    allowed: set[str],
    code: str,
    label: str,
) -> int:
    checked = 0

    for candidate in sorted(
        candidates
    ):
        checked += 1

        if candidate in allowed:
            continue

        append_unique_issue(
            issues,
            make_issue(
                code=code,
                severity=(
                    AISummaryValidationSeverity
                    .error
                ),
                field_name=field_name,
                value=candidate,
                message=(
                    f"The generated {label} "
                    "does not exist in the "
                    "structured investigation "
                    "context."
                ),
            ),
        )

    return checked


def build_expected_counts(
    context: AISummarySafeContext,
) -> dict[str, int]:
    scope = context.incident_scope

    counts: dict[str, int] = {}

    for label, key in (
        COUNT_LABELS.items()
    ):
        if key in {
            "tactic_count",
            "technique_count",
        }:
            source = (
                context.mitre_coverage
            )

        else:
            source = scope

        value = source.get(key)

        if isinstance(
            value,
            int,
        ):
            counts[label] = value

    return counts


def validate_count_claims(
    issues: list[
        AISummaryValidationIssue
    ],
    field_name: str,
    text: str,
    expected_counts: dict[
        str,
        int,
    ],
) -> int:
    checked = 0

    for match in (
        COUNT_PATTERN.finditer(text)
    ):
        checked += 1

        stated_count = int(
            match.group(1)
        )

        label = (
            match.group(2)
            .casefold()
        )

        expected_count = (
            expected_counts.get(
                label
            )
        )

        if expected_count is None:
            continue

        if stated_count == expected_count:
            continue

        append_unique_issue(
            issues,
            make_issue(
                code="count_mismatch",
                severity=(
                    AISummaryValidationSeverity
                    .error
                ),
                field_name=field_name,
                value=match.group(0),
                message=(
                    "The generated count does "
                    "not match the stored "
                    "investigation scope. "
                    f"Expected {expected_count}."
                ),
            ),
        )

    return checked


def validate_high_risk_claims(
    issues: list[
        AISummaryValidationIssue
    ],
    field_name: str,
    text: str,
    source_corpus: str,
) -> int:
    checked = 0

    normalized_text = text.casefold()

    for claim in HIGH_RISK_CLAIMS:
        if claim not in normalized_text:
            continue

        checked += 1

        if claim in source_corpus:
            continue

        append_unique_issue(
            issues,
            make_issue(
                code=(
                    "unsupported_high_risk_claim"
                ),
                severity=(
                    AISummaryValidationSeverity
                    .error
                ),
                field_name=field_name,
                value=claim,
                message=(
                    "The generated narrative "
                    "contains a high-impact "
                    "claim that is not supported "
                    "by the structured context."
                ),
            ),
        )

    return checked


def validate_ai_summary_output(
    context: AISummarySafeContext,
    output: AISummaryProviderOutput,
) -> AISummaryValidationResult:
    allowed = build_allowed_entities(
        context
    )

    source_corpus = (
        build_source_corpus(
            context
        )
    )

    expected_counts = (
        build_expected_counts(
            context
        )
    )

    issues: list[
        AISummaryValidationIssue
    ] = []

    checked_entity_count = 0

    for field_name, text in (
        output_fields(
            output
        ).items()
    ):
        ipv4_addresses = (
            extract_valid_ipv4_addresses(
                text
            )
        )

        checked_entity_count += (
            validate_entity_set(
                issues=issues,
                field_name=field_name,
                candidates=ipv4_addresses,
                allowed=allowed["ips"],
                code="unsupported_ip",
                label="IP address",
            )
        )

        mitre_ids = (
            extract_normalized_matches(
                MITRE_PATTERN,
                text,
            )
        )

        checked_entity_count += (
            validate_entity_set(
                issues=issues,
                field_name=field_name,
                candidates=mitre_ids,
                allowed=(
                    allowed["mitre_ids"]
                ),
                code=(
                    "unsupported_mitre_id"
                ),
                label=(
                    "MITRE ATT&CK technique"
                ),
            )
        )

        hashes = (
            extract_normalized_matches(
                HASH_PATTERN,
                text,
            )
        )

        checked_entity_count += (
            validate_entity_set(
                issues=issues,
                field_name=field_name,
                candidates=hashes,
                allowed=allowed["hashes"],
                code="unsupported_hash",
                label="cryptographic hash",
            )
        )

        timestamps = (
            extract_normalized_matches(
                TIMESTAMP_PATTERN,
                text,
            )
        )

        checked_entity_count += (
            validate_entity_set(
                issues=issues,
                field_name=field_name,
                candidates=timestamps,
                allowed=(
                    allowed["timestamps"]
                ),
                code=(
                    "unsupported_timestamp"
                ),
                label="timestamp",
            )
        )

        email_addresses = (
            extract_normalized_matches(
                EMAIL_PATTERN,
                text,
            )
        )

        checked_entity_count += (
            validate_entity_set(
                issues=issues,
                field_name=field_name,
                candidates=email_addresses,
                allowed=(
                    allowed["usernames"]
                ),
                code=(
                    "unsupported_username"
                ),
                label="username",
            )
        )

        domain_users = (
            extract_normalized_matches(
                DOMAIN_USER_PATTERN,
                text,
            )
        )

        checked_entity_count += (
            validate_entity_set(
                issues=issues,
                field_name=field_name,
                candidates=domain_users,
                allowed=(
                    allowed["usernames"]
                ),
                code=(
                    "unsupported_username"
                ),
                label="username",
            )
        )

        urls = (
            extract_normalized_matches(
                URL_PATTERN,
                text,
            )
        )

        checked_entity_count += (
            validate_entity_set(
                issues=issues,
                field_name=field_name,
                candidates=urls,
                allowed=allowed["urls"],
                code="unsupported_url",
                label="URL",
            )
        )

        event_codes = {
            normalize_comparable(
                match
            )
            for match in (
                EVENT_CODE_PATTERN.findall(
                    text
                )
            )
        }

        checked_entity_count += (
            validate_entity_set(
                issues=issues,
                field_name=field_name,
                candidates=event_codes,
                allowed=(
                    allowed["event_codes"]
                ),
                code=(
                    "unsupported_event_code"
                ),
                label="event code",
            )
        )

        identifiers = (
            extract_normalized_matches(
                IDENTIFIER_PATTERN,
                text,
            )
        )

        checked_entity_count += (
            validate_entity_set(
                issues=issues,
                field_name=field_name,
                candidates=identifiers,
                allowed=(
                    allowed["identifiers"]
                    | allowed["mitre_ids"]
                ),
                code=(
                    "unsupported_identifier"
                ),
                label="identifier",
            )
        )

        checked_entity_count += (
            validate_count_claims(
                issues=issues,
                field_name=field_name,
                text=text,
                expected_counts=(
                    expected_counts
                ),
            )
        )

        checked_entity_count += (
            validate_high_risk_claims(
                issues=issues,
                field_name=field_name,
                text=text,
                source_corpus=(
                    source_corpus
                ),
            )
        )

    unsupported_entity_count = sum(
        1
        for issue in issues
        if issue.code.startswith(
            "unsupported_"
        )
        and issue.code
        != (
            "unsupported_high_risk_claim"
        )
    )

    unsupported_claim_count = sum(
        1
        for issue in issues
        if issue.code
        == (
            "unsupported_high_risk_claim"
        )
    )

    count_mismatch_count = sum(
        1
        for issue in issues
        if issue.code
        == "count_mismatch"
    )

    is_valid = not any(
        issue.severity
        == (
            AISummaryValidationSeverity
            .error
        )
        for issue in issues
    )

    return AISummaryValidationResult(
        is_valid=is_valid,
        issues=issues,
        checked_entity_count=(
            checked_entity_count
        ),
        unsupported_entity_count=(
            unsupported_entity_count
        ),
        unsupported_claim_count=(
            unsupported_claim_count
        ),
        count_mismatch_count=(
            count_mismatch_count
        ),
    )


def validate_ai_summary_output_or_raise(
    context: AISummarySafeContext,
    output: AISummaryProviderOutput,
) -> AISummaryValidationResult:
    result = validate_ai_summary_output(
        context,
        output,
    )

    if not result.is_valid:
        raise AISummaryValidationError(
            result
        )

    return result