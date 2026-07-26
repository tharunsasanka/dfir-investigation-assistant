import json
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
    InvestigationSummary,
    InvestigationSummarySource,
    InvestigationSummaryStatus,
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
    InvestigationSummaryGenerateRequest,
    InvestigationVerifiedFact,
)
from app.services.ai_summary_provider import (
    AISummaryProviderOutput,
    AISummaryProviderResponseError,
    AISummaryProviderResult,
    AISummaryProviderTimeoutError,
)
from app.services.investigation_summary_generation_service import (
    apply_local_ai_generation,
    build_local_ai_safe_context,
    generate_investigation_summary,
)
from app.services.investigation_summary_service import (
    UnsupportedSummaryProviderError,
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
USER_ID = uuid.uuid4()
EVIDENCE_ID = uuid.uuid4()
PARSED_EVENT_ID = uuid.uuid4()
FINDING_ID = uuid.uuid4()
CORRELATION_ID = uuid.uuid4()


class FakeSession:
    def __init__(self):
        self.summaries: dict[
            uuid.UUID,
            InvestigationSummary,
        ] = {}

        self.added: list[
            InvestigationSummary
        ] = []

        self.commit_count = 0
        self.rollback_count = 0

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

    def rollback(self):
        self.rollback_count += 1

    def refresh(
        self,
        _instance,
    ):
        return None

    def get(
        self,
        model,
        identifier,
    ):
        if (
            model
            is InvestigationSummary
        ):
            return self.summaries.get(
                identifier
            )

        return None


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
            "Suspicious identity activity"
        ),
        description=(
            "Investigation of suspicious "
            "identity and endpoint activity."
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
        security_finding_count=2,
        event_correlation_count=1,
        case_audit_count=1,
        evidence_custody_count=1,
        evidence_count=2,
        critical_count=0,
        high_count=3,
        first_activity_at=BASE_TIME,
        last_activity_at=BASE_TIME,
        affected_hosts=[
            "WORKSTATION-01"
        ],
        affected_usernames=[
            "laura.chen"
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


def make_findings():
    return [
        InvestigationSummaryFinding(
            title=(
                "Suspicious PowerShell "
                "activity"
            ),
            description=(
                "A suspicious PowerShell "
                "command was detected."
            ),
            severity=(
                LogEventSeverity.high
            ),
            confidence=90,
            rule_id=(
                "WINDOWS-POWERSHELL-001"
            ),
            event_time=BASE_TIME,
            evidence_id=EVIDENCE_ID,
            parsed_event_id=(
                PARSED_EVENT_ID
            ),
            security_finding_id=(
                FINDING_ID
            ),
            correlation_id=(
                CORRELATION_ID
            ),
            event_code="4688",
            source_type="windows_event",
            mitre_tactic="Execution",
            mitre_technique_id=(
                "T1059.001"
            ),
            mitre_technique_name=(
                "PowerShell"
            ),
            indicators={
                "raw_event": {
                    "command_line":
                        "must not leave system",
                },
                "process_name":
                    "powershell.exe",
            },
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
                "Contain affected accounts "
                "and systems"
            ),
            description=(
                "Restrict affected identities "
                "and isolate affected systems."
            ),
            rationale=(
                "High-severity activity was "
                "identified."
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
            related_evidence_ids=[
                EVIDENCE_ID
            ],
        )
    ]


def make_verified_facts():
    return [
        InvestigationVerifiedFact(
            statement=(
                "The case contains twelve "
                "unified timeline entries."
            ),
            source_type=(
                "forensic_timeline"
            ),
            source_ids=[
                str(FINDING_ID)
            ],
            confidence=100,
        )
    ]


def make_assumptions():
    return [
        InvestigationAssumption(
            statement=(
                "One event may use its "
                "recorded timestamp."
            ),
            reason=(
                "A distinct source-event "
                "timestamp was unavailable."
            ),
            confidence=85,
        )
    ]


def make_limitations():
    return [
        (
            "Automated findings require "
            "analyst validation."
        )
    ]


def make_provider_result():
    return AISummaryProviderResult(
        output=AISummaryProviderOutput(
            executive_summary=(
                "The structured records "
                "identify suspicious identity "
                "and PowerShell activity that "
                "requires analyst validation."
            ),
            technical_narrative=(
                "The unified timeline records "
                "high-severity PowerShell "
                "activity mapped to T1059.001."
            ),
            additional_limitations=[
                (
                    "Endpoint telemetry outside "
                    "the supplied context was "
                    "not assessed."
                )
            ],
        ),
        provider_name="ollama",
        model_name="qwen2.5:3b",
        prompt_sha256="a" * 64,
        response_sha256="b" * 64,
        prompt_char_count=5000,
        response_byte_count=1500,
        total_duration_ns=2000000,
        prompt_eval_count=300,
        eval_count=100,
    )


def patch_generation_dependencies(
    monkeypatch,
):
    investigation_case = make_case()
    scope = make_scope()
    findings = make_findings()
    coverage = make_mitre_coverage()
    actions = make_actions()
    facts = make_verified_facts()
    assumptions = make_assumptions()
    limitations = make_limitations()

    monkeypatch.setattr(
        generation_service,
        "get_case_or_raise",
        lambda db, case_id:
            investigation_case,
    )

    monkeypatch.setattr(
        generation_service,
        "get_next_version_number",
        lambda db, case_id: 1,
    )

    monkeypatch.setattr(
        generation_service,
        "build_all_timeline_entries",
        lambda db, case_id: [],
    )

    monkeypatch.setattr(
        generation_service,
        "build_incident_scope",
        lambda entries: scope,
    )

    monkeypatch.setattr(
        generation_service,
        "build_summary_findings",
        lambda db, case_id: findings,
    )

    monkeypatch.setattr(
        generation_service,
        "build_mitre_coverage",
        lambda items: coverage,
    )

    monkeypatch.setattr(
        generation_service,
        "build_evidence_references",
        lambda db, case_id: [],
    )

    monkeypatch.setattr(
        generation_service,
        "build_recommended_actions",
        lambda scope_value,
        coverage_value,
        findings_value:
            actions,
    )

    monkeypatch.setattr(
        generation_service,
        "build_verified_facts",
        lambda scope_value,
        findings_value,
        evidence_value:
            facts,
    )

    monkeypatch.setattr(
        generation_service,
        "build_assumptions",
        lambda entries: assumptions,
    )

    monkeypatch.setattr(
        generation_service,
        "build_limitations",
        lambda scope_value,
        findings_value:
            limitations,
    )

    monkeypatch.setattr(
        generation_service,
        "calculate_confidence_score",
        lambda scope_value,
        coverage_value:
            85,
    )

    monkeypatch.setattr(
        generation_service,
        "build_executive_summary",
        lambda case_value,
        scope_value,
        coverage_value:
            "Deterministic executive summary.",
    )

    monkeypatch.setattr(
        generation_service,
        "build_technical_narrative",
        lambda scope_value,
        coverage_value:
            "Deterministic technical narrative.",
    )

    monkeypatch.setattr(
        generation_service,
        "build_source_snapshot",
        lambda case_value,
        scope_value,
        findings_value,
        coverage_value,
        evidence_value: {
            "case": {
                "id": str(CASE_ID),
            },
            "timeline_count": 12,
        },
    )

    return {
        "case": investigation_case,
        "scope": scope,
        "findings": findings,
        "coverage": coverage,
        "actions": actions,
        "facts": facts,
        "assumptions": assumptions,
        "limitations": limitations,
    }


def test_safe_context_excludes_raw_evidence_fields():
    context = build_local_ai_safe_context(
        investigation_case=make_case(),
        deterministic_executive_summary=(
            "Deterministic executive "
            "summary."
        ),
        deterministic_technical_narrative=(
            "Deterministic technical "
            "narrative."
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
        limitations=(
            make_limitations()
        ),
    )

    serialized = json.dumps(
        context.model_dump(
            mode="json"
        ),
        sort_keys=True,
    )

    assert (
        "evidence_id"
        not in serialized
    )

    assert (
        "parsed_event_id"
        not in serialized
    )

    assert (
        "security_finding_id"
        not in serialized
    )

    assert (
        "correlation_id"
        not in serialized
    )

    assert (
        "indicators"
        not in serialized
    )

    assert (
        "raw_event"
        not in serialized
    )

    assert (
        "source_snapshot"
        not in serialized
    )


def test_apply_local_ai_generation_uses_provider_output(
    monkeypatch,
):
    captured = {}

    class FakeProvider:
        def generate(
            self,
            context,
        ):
            captured["context"] = context
            return make_provider_result()

    monkeypatch.setattr(
        generation_service,
        "get_settings",
        lambda: make_settings(),
    )

    monkeypatch.setattr(
        generation_service,
        "create_local_ai_summary_provider",
        lambda settings:
            FakeProvider(),
    )

    (
        executive_summary,
        technical_narrative,
        limitations,
        source,
        provider_name,
        model_name,
        metadata,
    ) = apply_local_ai_generation(
        investigation_case=make_case(),
        deterministic_executive_summary=(
            "Deterministic executive "
            "summary."
        ),
        deterministic_technical_narrative=(
            "Deterministic technical "
            "narrative."
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
        limitations=(
            make_limitations()
        ),
    )

    assert executive_summary.startswith(
        "The structured records"
    )

    assert technical_narrative.endswith(
        "T1059.001."
    )

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
        "local_ai_used"
    ] is True

    assert metadata[
        "fallback_applied"
    ] is False

    assert metadata[
        "prompt_sha256"
    ] == "a" * 64

    assert metadata[
        "response_sha256"
    ] == "b" * 64

    assert (
        len(limitations) == 2
    )

    assert (
        captured["context"]
        .case_id
        == str(CASE_ID)
    )


def test_apply_local_ai_generation_falls_back(
    monkeypatch,
):
    class FailingProvider:
        def generate(
            self,
            _context,
        ):
            raise (
                AISummaryProviderTimeoutError(
                    "The local AI provider "
                    "request timed out."
                )
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
            FailingProvider(),
    )

    (
        executive_summary,
        technical_narrative,
        limitations,
        source,
        provider_name,
        model_name,
        metadata,
    ) = apply_local_ai_generation(
        investigation_case=make_case(),
        deterministic_executive_summary=(
            "Deterministic executive "
            "summary."
        ),
        deterministic_technical_narrative=(
            "Deterministic technical "
            "narrative."
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
        limitations=(
            make_limitations()
        ),
    )

    assert executive_summary == (
        "Deterministic executive summary."
    )

    assert technical_narrative == (
        "Deterministic technical narrative."
    )

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
        "local_ai_used"
    ] is False

    assert metadata[
        "fallback_applied"
    ] is True

    assert metadata[
        "fallback_error_type"
    ] == (
        "AISummaryProviderTimeoutError"
    )

    assert any(
        "deterministic fallback"
        in limitation
        for limitation in limitations
    )


def test_apply_local_ai_generation_raises_when_fallback_disabled(
    monkeypatch,
):
    class FailingProvider:
        def generate(
            self,
            _context,
        ):
            raise (
                AISummaryProviderResponseError(
                    "Provider output was "
                    "invalid."
                )
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
            FailingProvider(),
    )

    with pytest.raises(
        AISummaryProviderResponseError,
        match=(
            "Provider output was invalid"
        ),
    ):
        apply_local_ai_generation(
            investigation_case=make_case(),
            deterministic_executive_summary=(
                "Deterministic executive "
                "summary."
            ),
            deterministic_technical_narrative=(
                "Deterministic technical "
                "narrative."
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
            limitations=(
                make_limitations()
            ),
        )


def test_generate_local_ai_summary_persists_provider_metadata(
    monkeypatch,
):
    patch_generation_dependencies(
        monkeypatch
    )

    monkeypatch.setattr(
        generation_service,
        "apply_local_ai_generation",
        lambda **kwargs: (
            (
                "AI-assisted executive "
                "summary."
            ),
            (
                "AI-assisted technical "
                "narrative."
            ),
            [
                (
                    "Automated findings "
                    "require analyst "
                    "validation."
                )
            ],
            InvestigationSummarySource
            .local_ai,
            "ollama",
            "qwen2.5:3b",
            {
                "local_ai_used": True,
                "fallback_applied": False,
                "prompt_sha256":
                    "a" * 64,
                "response_sha256":
                    "b" * 64,
            },
        ),
    )

    session = FakeSession()

    result = generate_investigation_summary(
        db=session,
        case_id=CASE_ID,
        requested_by_user_id=USER_ID,
        request=(
            InvestigationSummaryGenerateRequest(
                generation_source=(
                    InvestigationSummarySource
                    .local_ai
                ),
                provider_name="ollama",
                model_name="qwen2.5:3b",
                generation_parameters={
                    "temperature": 0.1,
                },
            )
        ),
    )

    assert (
        result.status
        == InvestigationSummaryStatus
        .pending_review
    )

    assert (
        result.generation_source
        == InvestigationSummarySource
        .local_ai
    )

    assert (
        result.provider_name
        == "ollama"
    )

    assert (
        result.model_name
        == "qwen2.5:3b"
    )

    assert (
        result.executive_summary
        == (
            "AI-assisted executive "
            "summary."
        )
    )

    assert (
        result.technical_narrative
        == (
            "AI-assisted technical "
            "narrative."
        )
    )

    assert (
        result.generation_parameters[
            "requested_generation_source"
        ]
        == "local_ai"
    )

    assert (
        result.generation_parameters[
            "effective_generation_source"
        ]
        == "local_ai"
    )

    assert (
        result.generation_parameters[
            "local_ai_used"
        ]
        is True
    )

    assert len(
        result.source_snapshot_sha256
    ) == 64

    assert len(
        result.output_sha256
    ) == 64

    assert session.commit_count == 2
    assert session.rollback_count == 0


def test_generate_local_ai_fallback_persists_deterministic_source(
    monkeypatch,
):
    patch_generation_dependencies(
        monkeypatch
    )

    monkeypatch.setattr(
        generation_service,
        "apply_local_ai_generation",
        lambda **kwargs: (
            (
                "Deterministic executive "
                "summary."
            ),
            (
                "Deterministic technical "
                "narrative."
            ),
            [
                (
                    "Local AI processing was "
                    "unavailable during "
                    "generation."
                )
            ],
            InvestigationSummarySource
            .deterministic,
            "deterministic-fallback",
            "qwen2.5:3b",
            {
                "local_ai_used": False,
                "fallback_applied": True,
                "fallback_error_type":
                    (
                        "AISummaryProvider"
                        "TimeoutError"
                    ),
            },
        ),
    )

    session = FakeSession()

    result = generate_investigation_summary(
        db=session,
        case_id=CASE_ID,
        requested_by_user_id=USER_ID,
        request=(
            InvestigationSummaryGenerateRequest(
                generation_source=(
                    InvestigationSummarySource
                    .local_ai
                ),
                provider_name="ollama",
                model_name="qwen2.5:3b",
            )
        ),
    )

    assert (
        result.generation_source
        == InvestigationSummarySource
        .deterministic
    )

    assert (
        result.provider_name
        == "deterministic-fallback"
    )

    assert (
        result.generation_parameters[
            "requested_generation_source"
        ]
        == "local_ai"
    )

    assert (
        result.generation_parameters[
            "effective_generation_source"
        ]
        == "deterministic"
    )

    assert (
        result.generation_parameters[
            "fallback_applied"
        ]
        is True
    )

    assert (
        result.generation_parameters[
            "local_ai_used"
        ]
        is False
    )

    assert session.commit_count == 2
    assert session.rollback_count == 0


def test_generate_rejects_hosted_ai():
    with pytest.raises(
        UnsupportedSummaryProviderError,
        match=(
            "Only deterministic and "
            "local AI"
        ),
    ):
        generate_investigation_summary(
            db=FakeSession(),
            case_id=CASE_ID,
            requested_by_user_id=(
                USER_ID
            ),
            request=(
                InvestigationSummaryGenerateRequest(
                    generation_source=(
                        InvestigationSummarySource
                        .hosted_ai
                    ),
                    provider_name=(
                        "hosted"
                    ),
                    model_name=(
                        "hosted-model"
                    ),
                )
            ),
        )


def test_generate_marks_summary_failed_on_provider_error(
    monkeypatch,
):
    patch_generation_dependencies(
        monkeypatch
    )

    monkeypatch.setattr(
        generation_service,
        "apply_local_ai_generation",
        lambda **kwargs:
            (_ for _ in ()).throw(
                AISummaryProviderResponseError(
                    "Provider output was "
                    "invalid."
                )
            ),
    )

    session = FakeSession()

    with pytest.raises(
        AISummaryProviderResponseError,
        match=(
            "Provider output was invalid"
        ),
    ):
        generate_investigation_summary(
            db=session,
            case_id=CASE_ID,
            requested_by_user_id=(
                USER_ID
            ),
            request=(
                InvestigationSummaryGenerateRequest(
                    generation_source=(
                        InvestigationSummarySource
                        .local_ai
                    ),
                    provider_name=(
                        "ollama"
                    ),
                    model_name=(
                        "qwen2.5:3b"
                    ),
                )
            ),
        )

    assert session.rollback_count == 1
    assert session.commit_count == 2
    assert len(session.summaries) == 1

    failed_summary = next(
        iter(
            session.summaries.values()
        )
    )

    assert (
        failed_summary.status
        == InvestigationSummaryStatus
        .failed
    )

    assert (
        "Provider output was invalid"
        in failed_summary
        .generation_error
    )

    assert (
        failed_summary
        .generation_completed_at
        is not None
    )