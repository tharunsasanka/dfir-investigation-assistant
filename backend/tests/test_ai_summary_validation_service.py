from app.services.ai_summary_provider import (
    AISummaryProviderOutput,
    AISummarySafeContext,
)
from app.services.ai_summary_validation_service import (
    AISummaryValidationSeverity,
    validate_ai_summary_output,
)


def make_context(
    **overrides,
) -> AISummarySafeContext:
    values = {
        "case_id":
            "99a012ce-2838-4421-ae64-"
            "6aef10b55fb6",
        "case_title":
            "Suspicious PowerShell activity",
        "case_severity":
            "high",
        "case_status":
            "investigating",
        "deterministic_executive_summary":
            (
                "The investigation contains "
                "suspicious PowerShell activity "
                "requiring analyst validation."
            ),
        "deterministic_technical_narrative":
            (
                "Event 4688 recorded "
                "powershell.exe activity on "
                "WORKSTATION-01 for "
                "laura.chen@example.com from "
                "203.0.113.50. The finding is "
                "mapped to T1059.001."
            ),
        "incident_scope": {
            "total_timeline_entries": 12,
            "log_event_count": 7,
            "security_finding_count": 2,
            "event_correlation_count": 1,
            "case_audit_count": 1,
            "evidence_custody_count": 1,
            "evidence_count": 2,
            "critical_count": 0,
            "high_count": 2,
            "first_activity_at":
                "2026-07-26T10:00:00+00:00",
            "last_activity_at":
                "2026-07-26T11:00:00+00:00",
            "affected_hosts": [
                "WORKSTATION-01"
            ],
            "affected_usernames": [
                "laura.chen@example.com"
            ],
            "observed_source_ips": [
                "203.0.113.50"
            ],
            "observed_destination_ips": [
                "192.0.2.20"
            ],
            "observed_processes": [
                "powershell.exe"
            ],
        },
        "technical_findings": [
            {
                "title":
                    "Suspicious PowerShell activity",
                "description":
                    (
                        "A suspicious PowerShell "
                        "process was detected."
                    ),
                "severity":
                    "high",
                "confidence":
                    90,
                "rule_id":
                    "WINDOWS-POWERSHELL-001",
                "event_time":
                    "2026-07-26T10:00:00+00:00",
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
            },
            {
                "title":
                    "Suspicious identity activity",
                "description":
                    (
                        "A suspicious identity "
                        "event was detected."
                    ),
                "severity":
                    "high",
                "confidence":
                    85,
                "rule_id":
                    "IDENTITY-SIGNIN-001",
                "event_time":
                    "2026-07-26T11:00:00+00:00",
                "event_code":
                    "4624",
                "source_type":
                    "windows_event",
                "mitre_tactic":
                    "Initial Access",
                "mitre_technique_id":
                    "T1078",
                "mitre_technique_name":
                    "Valid Accounts",
            },
        ],
        "mitre_coverage": {
            "tactic_count": 2,
            "technique_count": 2,
            "tactics": [
                "Execution",
                "Initial Access",
            ],
            "techniques": [
                {
                    "tactic":
                        "Execution",
                    "technique_id":
                        "T1059.001",
                    "technique_name":
                        "PowerShell",
                    "finding_count":
                        1,
                    "correlation_count":
                        1,
                    "related_rule_ids": [
                        "WINDOWS-POWERSHELL-001"
                    ],
                },
                {
                    "tactic":
                        "Initial Access",
                    "technique_id":
                        "T1078",
                    "technique_name":
                        "Valid Accounts",
                    "finding_count":
                        1,
                    "correlation_count":
                        0,
                    "related_rule_ids": [
                        "IDENTITY-SIGNIN-001"
                    ],
                },
            ],
        },
        "recommended_actions": [
            {
                "priority":
                    "immediate",
                "title":
                    "Validate affected identity",
                "description":
                    (
                        "Review authentication "
                        "activity and active "
                        "sessions."
                    ),
                "rationale":
                    (
                        "Suspicious identity "
                        "activity was detected."
                    ),
                "related_rule_ids": [
                    "IDENTITY-SIGNIN-001"
                ],
                "related_mitre_technique_ids": [
                    "T1078"
                ],
            }
        ],
        "verified_facts": [
            {
                "statement":
                    (
                        "The case contains twelve "
                        "timeline entries."
                    ),
                "source_type":
                    "forensic_timeline",
                "confidence":
                    100,
            }
        ],
        "assumptions": [],
        "limitations": [
            (
                "Automated findings require "
                "analyst validation."
            )
        ],
    }

    values.update(overrides)

    return AISummarySafeContext(
        **values,
    )


def make_output(
    executive_summary: str = (
        "The case contains 12 timeline entries "
        "and 2 findings requiring analyst "
        "validation."
    ),
    technical_narrative: str = (
        "Event 4688 recorded activity from "
        "203.0.113.50 on WORKSTATION-01. "
        "The stored finding is mapped to "
        "T1059.001 under rule "
        "WINDOWS-POWERSHELL-001."
    ),
    additional_limitations: list[
        str
    ] | None = None,
) -> AISummaryProviderOutput:
    return AISummaryProviderOutput(
        executive_summary=(
            executive_summary
        ),
        technical_narrative=(
            technical_narrative
        ),
        additional_limitations=(
            additional_limitations
            or []
        ),
    )


def issue_codes(
    result,
) -> list[str]:
    return [
        issue.code
        for issue in result.issues
    ]


def test_valid_supported_output_passes():
    result = validate_ai_summary_output(
        make_context(),
        make_output(),
    )

    assert result.is_valid is True
    assert result.issues == []
    assert (
        result.unsupported_entity_count
        == 0
    )
    assert (
        result.unsupported_claim_count
        == 0
    )
    assert (
        result.count_mismatch_count
        == 0
    )


def test_rejects_unsupported_ip_address():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            technical_narrative=(
                "Event 4688 recorded activity "
                "from 198.51.100.77."
            ),
        ),
    )

    assert result.is_valid is False
    assert "unsupported_ip" in (
        issue_codes(result)
    )
    assert (
        result.unsupported_entity_count
        == 1
    )


def test_rejects_unsupported_mitre_technique():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            technical_narrative=(
                "The activity was mapped to "
                "T1003.001."
            ),
        ),
    )

    assert result.is_valid is False
    assert (
        "unsupported_mitre_id"
        in issue_codes(result)
    )


def test_rejects_unsupported_event_code():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            technical_narrative=(
                "Event 9999 was detected in "
                "the investigation."
            ),
        ),
    )

    assert result.is_valid is False
    assert (
        "unsupported_event_code"
        in issue_codes(result)
    )


def test_rejects_unsupported_username():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            technical_narrative=(
                "The activity affected "
                "unknown.user@example.com."
            ),
        ),
    )

    assert result.is_valid is False
    assert (
        "unsupported_username"
        in issue_codes(result)
    )


def test_rejects_unsupported_identifier():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            technical_narrative=(
                "The activity occurred on "
                "SERVER-99."
            ),
        ),
    )

    assert result.is_valid is False
    assert (
        "unsupported_identifier"
        in issue_codes(result)
    )


def test_rejects_incorrect_scope_count():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            executive_summary=(
                "The case contains 20 timeline "
                "entries and 2 findings."
            ),
        ),
    )

    assert result.is_valid is False
    assert (
        "count_mismatch"
        in issue_codes(result)
    )
    assert (
        result.count_mismatch_count
        == 1
    )


def test_rejects_unsupported_high_risk_claim():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            executive_summary=(
                "The investigation confirms "
                "data exfiltration by a "
                "threat actor."
            ),
        ),
    )

    assert result.is_valid is False
    assert (
        "unsupported_high_risk_claim"
        in issue_codes(result)
    )
    assert (
        result.unsupported_claim_count
        == 2
    )


def test_accepts_high_risk_claim_present_in_context():
    context = make_context(
        deterministic_executive_summary=(
            "The stored findings support a "
            "confirmed compromise requiring "
            "analyst review."
        ),
    )

    result = validate_ai_summary_output(
        context,
        make_output(
            executive_summary=(
                "The structured context records "
                "a confirmed compromise "
                "requiring analyst review."
            ),
        ),
    )

    assert result.is_valid is True
    assert (
        result.unsupported_claim_count
        == 0
    )


def test_validates_additional_limitations():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            additional_limitations=[
                (
                    "External context from "
                    "https://unsupported.example "
                    "was not assessed."
                )
            ],
        ),
    )

    assert result.is_valid is False
    assert (
        "unsupported_url"
        in issue_codes(result)
    )


def test_repeated_unsupported_entity_is_reported_once():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            executive_summary=(
                "Activity from 198.51.100.77 "
                "requires review."
            ),
            technical_narrative=(
                "The same 198.51.100.77 "
                "address appeared again."
            ),
        ),
    )

    matching_issues = [
        issue
        for issue in result.issues
        if (
            issue.code
            == "unsupported_ip"
        )
    ]

    assert len(matching_issues) == 2
    assert {
        issue.field_name
        for issue in matching_issues
    } == {
        "executive_summary",
        "technical_narrative",
    }


def test_validation_issues_are_errors():
    result = validate_ai_summary_output(
        make_context(),
        make_output(
            technical_narrative=(
                "Event 7777 was detected."
            ),
        ),
    )

    assert result.is_valid is False

    assert all(
        issue.severity
        == AISummaryValidationSeverity
        .error
        for issue in result.issues
    )