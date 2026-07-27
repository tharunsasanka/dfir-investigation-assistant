import uuid
from datetime import (
    datetime,
    timezone,
)
from types import SimpleNamespace

import pytest

import app.services.investigation_summary_generation_service as generation_service
from app.core.config import Settings
from app.models.case import (
    CaseSeverity,
    CaseStatus,
)
from app.models.investigation_summary import (
    InvestigationSummarySource,
)
from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.schemas.investigation_summary import (
    InvestigationActionPriority,
    InvestigationAssumption,
    InvestigationIncidentScope,
    InvestigationMitreCoverage,
    InvestigationMitreTechnique,
    InvestigationRecommendedAction,
    InvestigationSummaryFinding,
    InvestigationVerifiedFact,
)
from app.services.ai_summary_provider import (
    AISummaryProviderOutput,
    AISummaryProviderResult,
)
from app.services.ai_summary_validation_service import (
    AISummaryValidationError,
)
from app.services.investigation_summary_generation_service import (
    apply_local_ai_generation,
)


BASE_TIME = datetime(
    2026,
    7,
    26,
    10,
    0,
    tzinfo=timezone.utc,
)

CASE_ID = uuid.uuid4()


def make_settings(
    **overrides,
) -> Settings:
    values = {
        "ai_local_enabled": True,
        "ai_local_provider_name":
            "ollama",
        "ai_local_base_url":
            "http://localhost:11434",
        "ai_local_model":
            "qwen2.5:3b",
        "ai_local_allowed_hosts":
            (
                "localhost,"
                "127.0.0.1,"
                "::1,"
                "host.docker.internal,"
                "ollama"
            ),
        "ai_local_timeout_seconds":
            30.0,
        "ai_local_connect_timeout_seconds":
            5.0,
        "ai_local_max_prompt_chars":
            30000,
        "ai_local_max_response_bytes":
            262144,
        "ai_local_temperature":
            0.1,
        "ai_local_fallback_to_deterministic":
            True,
    }

    values.update(overrides)

    return Settings(
        _env_file=None,
        **values,
    )


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
        evidence_ids=[],
    )


def make_findings():
    return [
        InvestigationSummaryFinding(
            title=(
                "Suspicious PowerShell "
                "activity"
            ),
            description=(
                "A suspicious PowerShell "
                "process was recorded."
            ),
            severity=(
                LogEventSeverity.high
            ),
            confidence=90,
            rule_id=(
                "WINDOWS-POWERSHELL-001"
            ),
            event_time=BASE_TIME,
            evidence_id=None,
            parsed_event_id=None,
            security_finding_id=None,
            correlation_id=None,
            event_code="4688",
            source_type="windows_event",
            mitre_tactic="Execution",
            mitre_technique_id=(
                "T1059.001"
            ),
            mitre_technique_name=(
                "PowerShell"
            ),
            indicators={},
        )
    ]


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


def make_actions():
    return [
        InvestigationRecommendedAction(
            priority=(
                InvestigationActionPriority
                .immediate
            ),
            title=(
                "Validate affected system"
            ),
            description=(
                "Review PowerShell activity "
                "on the affected host."
            ),
            rationale=(
                "A high-severity finding "
                "was recorded."
            ),
            related_rule_ids=[
                (
                    "WINDOWS-"
                    "POWERSHELL-001"
                )
            ],
            related_mitre_technique_ids=[
                "T1059.001"
            ],
            related_evidence_ids=[],
        )
    ]


def make_verified_facts():
    return [
        InvestigationVerifiedFact(
            statement=(
                "The case contains twelve "
                "timeline entries."
            ),
            source_type=(
                "forensic_timeline"
            ),
            source_ids=[],
            confidence=100,
        )
    ]


def make_assumptions():
    return [
        InvestigationAssumption(
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
    ]


def make_provider_result(
    executive_summary: str,
    technical_narrative: str,
) -> AISummaryProviderResult:
    return AISummaryProviderResult(
        output=AISummaryProviderOutput(
            executive_summary=(
                executive_summary
            ),
            technical_narrative=(
                technical_narrative
            ),
            additional_limitations=[],
        ),
        provider_name="ollama",
        model_name="qwen2.5:3b",
        prompt_sha256="a" * 64,
        response_sha256="b" * 64,
        prompt_char_count=4000,
        response_byte_count=1200,
        total_duration_ns=2000000,
        prompt_eval_count=250,
        eval_count=80,
    )


def call_generation():
    return apply_local_ai_generation(
        investigation_case=make_case(),
        deterministic_executive_summary=(
            "The deterministic summary "
            "identified one suspicious "
            "PowerShell finding."
        ),
        deterministic_technical_narrative=(
            "Event 4688 was recorded on "
            "WORKSTATION-01 from "
            "203.0.113.50 and mapped to "
            "T1059.001."
        ),
        scope=make_scope(),
        findings=make_findings(),
        mitre_coverage=(
            make_mitre_coverage()
        ),
        recommended_actions=(
            make_actions()
        ),
        verified_facts=(
            make_verified_facts()
        ),
        assumptions=(
            make_assumptions()
        ),
        limitations=[
            (
                "Automated findings require "
                "analyst validation."
            )
        ],
    )


def test_valid_ai_output_passes_validation(
    monkeypatch,
):
    class ValidProvider:
        def generate(
            self,
            _context,
        ):
            return make_provider_result(
                executive_summary=(
                    "The case contains 12 "
                    "timeline entries and one "
                    "finding requiring analyst "
                    "validation."
                ),
                technical_narrative=(
                    "Event 4688 recorded "
                    "PowerShell activity from "
                    "203.0.113.50 on "
                    "WORKSTATION-01. The "
                    "finding is mapped to "
                    "T1059.001 under rule "
                    "WINDOWS-POWERSHELL-001."
                ),
            )

    monkeypatch.setattr(
        generation_service,
        "get_settings",
        lambda: make_settings(),
    )

    monkeypatch.setattr(
        generation_service,
        "create_local_ai_summary_provider",
        lambda settings:
            ValidProvider(),
    )

    (
        executive_summary,
        technical_narrative,
        limitations,
        source,
        provider_name,
        model_name,
        metadata,
    ) = call_generation()

    assert (
        source
        == InvestigationSummarySource
        .local_ai
    )

    assert provider_name == "ollama"

    assert (
        model_name
        == "qwen2.5:3b"
    )

    assert metadata[
        "validation_passed"
    ] is True

    assert metadata[
        "validation_issue_count"
    ] == 0

    assert metadata[
        "validation_unsupported_entity_count"
    ] == 0

    assert metadata[
        "validation_unsupported_claim_count"
    ] == 0

    assert metadata[
        "validation_count_mismatch_count"
    ] == 0

    assert metadata[
        "fallback_applied"
    ] is False

    assert executive_summary.startswith(
        "The case contains 12"
    )

    assert (
        "T1059.001"
        in technical_narrative
    )

    assert len(limitations) == 1


def test_unsupported_ip_triggers_deterministic_fallback(
    monkeypatch,
):
    class InvalidProvider:
        def generate(
            self,
            _context,
        ):
            return make_provider_result(
                executive_summary=(
                    "The case requires "
                    "analyst validation."
                ),
                technical_narrative=(
                    "Event 4688 recorded "
                    "activity from "
                    "198.51.100.77."
                ),
            )

    monkeypatch.setattr(
        generation_service,
        "get_settings",
        lambda: make_settings(
            ai_local_fallback_to_deterministic=(
                True
            )
        ),
    )

    monkeypatch.setattr(
        generation_service,
        "create_local_ai_summary_provider",
        lambda settings:
            InvalidProvider(),
    )

    (
        executive_summary,
        technical_narrative,
        limitations,
        source,
        provider_name,
        model_name,
        metadata,
    ) = call_generation()

    assert (
        source
        == InvestigationSummarySource
        .deterministic
    )

    assert (
        provider_name
        == "deterministic-fallback"
    )

    assert (
        model_name
        == "qwen2.5:3b"
    )

    assert metadata[
        "validation_passed"
    ] is False

    assert metadata[
        "fallback_applied"
    ] is True

    assert metadata[
        "local_ai_used"
    ] is False

    assert metadata[
        "fallback_error_type"
    ] == (
        "AISummaryValidationError"
    )

    assert (
        "unsupported_ip"
        in metadata[
            "validation_issue_codes"
        ]
    )

    assert metadata[
        "validation_unsupported_entity_count"
    ] == 1

    assert executive_summary.startswith(
        "The deterministic summary"
    )

    assert technical_narrative.startswith(
        "Event 4688"
    )

    assert any(
        "deterministic fallback"
        in limitation
        for limitation in limitations
    )


def test_count_mismatch_triggers_fallback(
    monkeypatch,
):
    class InvalidProvider:
        def generate(
            self,
            _context,
        ):
            return make_provider_result(
                executive_summary=(
                    "The case contains 99 "
                    "timeline entries."
                ),
                technical_narrative=(
                    "Event 4688 was recorded "
                    "on WORKSTATION-01."
                ),
            )

    monkeypatch.setattr(
        generation_service,
        "get_settings",
        lambda: make_settings(),
    )

    monkeypatch.setattr(
        generation_service,
        "create_local_ai_summary_provider",
        lambda settings:
            InvalidProvider(),
    )

    (
        _executive_summary,
        _technical_narrative,
        _limitations,
        source,
        _provider_name,
        _model_name,
        metadata,
    ) = call_generation()

    assert (
        source
        == InvestigationSummarySource
        .deterministic
    )

    assert (
        "count_mismatch"
        in metadata[
            "validation_issue_codes"
        ]
    )

    assert metadata[
        "validation_count_mismatch_count"
    ] == 1


def test_validation_error_raises_when_fallback_disabled(
    monkeypatch,
):
    class InvalidProvider:
        def generate(
            self,
            _context,
        ):
            return make_provider_result(
                executive_summary=(
                    "The investigation "
                    "confirms data "
                    "exfiltration."
                ),
                technical_narrative=(
                    "Event 4688 was recorded."
                ),
            )

    monkeypatch.setattr(
        generation_service,
        "get_settings",
        lambda: make_settings(
            ai_local_fallback_to_deterministic=(
                False
            )
        ),
    )

    monkeypatch.setattr(
        generation_service,
        "create_local_ai_summary_provider",
        lambda settings:
            InvalidProvider(),
    )

    with pytest.raises(
        AISummaryValidationError,
        match=(
            "failed factual validation"
        ),
    ) as error_info:
        call_generation()

    issue_codes = {
        issue.code
        for issue
        in error_info
        .value
        .result
        .issues
    }

    assert (
        "unsupported_high_risk_claim"
        in issue_codes
    )