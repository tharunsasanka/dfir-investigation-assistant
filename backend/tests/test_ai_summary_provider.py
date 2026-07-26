import json

import httpx
import pytest

from app.core.config import Settings
from app.services.ai_summary_provider import (
    AISummaryProviderConfigurationError,
    AISummaryProviderDisabledError,
    AISummaryProviderResponseError,
    AISummaryProviderTimeoutError,
    AISummarySafeContext,
    OllamaSummaryProvider,
    build_provider_prompt,
    calculate_text_sha256,
    validate_local_provider_url,
    validate_safe_context_value,
)


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


def make_safe_context(
    **overrides,
) -> AISummarySafeContext:
    values = {
        "case_id":
            "99a012ce-2838-4421-ae64-"
            "6aef10b55fb6",
        "case_title":
            "Suspicious identity activity",
        "case_severity":
            "high",
        "case_status":
            "investigating",
        "deterministic_executive_summary":
            (
                "The stored investigation "
                "records contain suspicious "
                "identity activity requiring "
                "analyst validation."
            ),
        "deterministic_technical_narrative":
            (
                "The unified timeline contains "
                "authentication events and one "
                "high-confidence security "
                "finding."
            ),
        "incident_scope": {
            "total_timeline_entries": 10,
            "security_finding_count": 1,
            "event_correlation_count": 1,
            "evidence_count": 2,
            "affected_hosts": [
                "WORKSTATION-01"
            ],
            "affected_usernames": [
                "laura.chen"
            ],
            "observed_source_ips": [
                "203.0.113.50"
            ],
        },
        "technical_findings": [
            {
                "title":
                    "Suspicious sign-in",
                "description":
                    (
                        "A high-confidence "
                        "sign-in finding was "
                        "recorded."
                    ),
                "severity": "high",
                "confidence": 90,
                "rule_id":
                    "IDENTITY-SIGNIN-001",
                "event_code": "4624",
                "mitre_tactic":
                    "Initial Access",
                "mitre_technique_id":
                    "T1078",
                "mitre_technique_name":
                    "Valid Accounts",
            }
        ],
        "mitre_coverage": {
            "tactic_count": 1,
            "technique_count": 1,
            "tactics": [
                "Initial Access"
            ],
            "techniques": [
                {
                    "tactic":
                        "Initial Access",
                    "technique_id":
                        "T1078",
                    "technique_name":
                        "Valid Accounts",
                    "finding_count": 1,
                    "correlation_count": 1,
                    "related_rule_ids": [
                        "IDENTITY-SIGNIN-001"
                    ],
                }
            ],
        },
        "recommended_actions": [
            {
                "priority":
                    "immediate",
                "title":
                    (
                        "Validate affected "
                        "identity"
                    ),
                "description":
                    (
                        "Review authentication "
                        "activity and active "
                        "sessions."
                    ),
                "rationale":
                    (
                        "A suspicious sign-in "
                        "was identified."
                    ),
                "related_rule_ids": [
                    "IDENTITY-SIGNIN-001"
                ],
                "related_mitre_technique_ids":
                    [
                        "T1078"
                    ],
            }
        ],
        "verified_facts": [
            {
                "statement":
                    (
                        "The case contains ten "
                        "timeline entries."
                    ),
                "source_type":
                    "forensic_timeline",
                "confidence": 100,
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


def test_calculate_text_sha256_is_stable():
    first_hash = (
        calculate_text_sha256(
            "structured context"
        )
    )

    second_hash = (
        calculate_text_sha256(
            b"structured context"
        )
    )

    assert first_hash == second_hash
    assert len(first_hash) == 64


def test_validate_safe_context_blocks_raw_event():
    with pytest.raises(
        AISummaryProviderConfigurationError,
        match=(
            "prohibited raw-evidence field"
        ),
    ):
        validate_safe_context_value(
            {
                "finding": {
                    "raw_event": {
                        "message":
                            "blocked",
                    },
                },
            }
        )


def test_build_provider_prompt_blocks_source_snapshot():
    context = make_safe_context(
        technical_findings=[
            {
                "title":
                    "Unsafe finding",
                "source_snapshot": {
                    "content":
                        "must not leave system",
                },
            }
        ]
    )

    with pytest.raises(
        AISummaryProviderConfigurationError,
        match=(
            "prohibited raw-evidence field"
        ),
    ):
        build_provider_prompt(
            context
        )


def test_validate_local_provider_url_accepts_localhost():
    settings = make_settings(
        ai_local_base_url=(
            "http://localhost:11434/"
        )
    )

    base_url = (
        validate_local_provider_url(
            settings
        )
    )

    assert (
        base_url
        == "http://localhost:11434"
    )


def test_validate_local_provider_url_rejects_external_host():
    settings = make_settings(
        ai_local_base_url=(
            "https://example.com"
        )
    )

    with pytest.raises(
        AISummaryProviderConfigurationError,
        match=(
            "not in "
            "AI_LOCAL_ALLOWED_HOSTS"
        ),
    ):
        validate_local_provider_url(
            settings
        )


def test_provider_rejects_embedded_credentials():
    settings = make_settings(
        ai_local_base_url=(
            "http://user:password@"
            "localhost:11434"
        )
    )

    with pytest.raises(
        AISummaryProviderConfigurationError,
        match=(
            "Credentials are not permitted"
        ),
    ):
        validate_local_provider_url(
            settings
        )


def test_provider_rejects_disabled_configuration():
    settings = make_settings(
        ai_local_enabled=False
    )

    provider = OllamaSummaryProvider(
        settings=settings
    )

    with pytest.raises(
        AISummaryProviderDisabledError,
        match=(
            "Local AI summary generation "
            "is disabled"
        ),
    ):
        provider.generate(
            make_safe_context()
        )


def test_provider_requires_model_name():
    settings = make_settings(
        ai_local_model=""
    )

    provider = OllamaSummaryProvider(
        settings=settings
    )

    with pytest.raises(
        AISummaryProviderConfigurationError,
        match="AI_LOCAL_MODEL",
    ):
        provider.generate(
            make_safe_context()
        )


def test_provider_generates_valid_structured_output():
    captured_request = {}

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        captured_request.update(
            json.loads(
                request.content.decode(
                    "utf-8"
                )
            )
        )

        generated_output = {
            "executive_summary":
                (
                    "The structured records "
                    "identify suspicious "
                    "identity activity requiring "
                    "analyst validation."
                ),
            "technical_narrative":
                (
                    "The timeline records a "
                    "high-confidence sign-in "
                    "finding mapped to T1078."
                ),
            "additional_limitations": [
                (
                    "Endpoint telemetry was "
                    "not represented in the "
                    "provided context."
                )
            ],
        }

        return httpx.Response(
            status_code=200,
            json={
                "model": "qwen2.5:3b",
                "response":
                    json.dumps(
                        generated_output
                    ),
                "done": True,
                "total_duration": 1000000,
                "prompt_eval_count": 250,
                "eval_count": 80,
            },
        )

    provider = OllamaSummaryProvider(
        settings=make_settings(),
        transport=httpx.MockTransport(
            handler
        ),
    )

    result = provider.generate(
        make_safe_context()
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
        result.output
        .executive_summary
        .startswith(
            "The structured records"
        )
    )

    assert (
        result.output
        .technical_narrative
        .endswith("T1078.")
    )

    assert (
        result.output
        .additional_limitations
        == [
            (
                "Endpoint telemetry was "
                "not represented in the "
                "provided context."
            )
        ]
    )

    assert len(
        result.prompt_sha256
    ) == 64

    assert len(
        result.response_sha256
    ) == 64

    assert (
        result.total_duration_ns
        == 1000000
    )

    assert (
        result.prompt_eval_count
        == 250
    )

    assert result.eval_count == 80

    assert (
        captured_request["model"]
        == "qwen2.5:3b"
    )

    assert (
        captured_request["stream"]
        is False
    )

    assert isinstance(
        captured_request["format"],
        dict,
    )

    assert (
        captured_request["options"][
            "temperature"
        ]
        == 0.1
    )

    assert (
        "source_snapshot"
        not in captured_request[
            "prompt"
        ]
    )

    assert (
        "raw_event"
        not in captured_request[
            "prompt"
        ]
    )


def test_provider_rejects_invalid_generated_json():
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            json={
                "model": "qwen2.5:3b",
                "response":
                    "not valid json",
                "done": True,
            },
        )

    provider = OllamaSummaryProvider(
        settings=make_settings(),
        transport=httpx.MockTransport(
            handler
        ),
    )

    with pytest.raises(
        AISummaryProviderResponseError,
        match=(
            "does not match the required "
            "summary schema"
        ),
    ):
        provider.generate(
            make_safe_context()
        )


def test_provider_rejects_missing_generated_text():
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            json={
                "model": "qwen2.5:3b",
                "done": True,
            },
        )

    provider = OllamaSummaryProvider(
        settings=make_settings(),
        transport=httpx.MockTransport(
            handler
        ),
    )

    with pytest.raises(
        AISummaryProviderResponseError,
        match=(
            "did not contain generated text"
        ),
    ):
        provider.generate(
            make_safe_context()
        )


def test_provider_enforces_response_size_limit():
    generated_output = {
        "executive_summary":
            "A" * 5000,
        "technical_narrative":
            "Valid narrative",
        "additional_limitations": [],
    }

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            json={
                "model": "qwen2.5:3b",
                "response":
                    json.dumps(
                        generated_output
                    ),
                "done": True,
            },
        )

    provider = OllamaSummaryProvider(
        settings=make_settings(
            ai_local_max_response_bytes=(
                4096
            )
        ),
        transport=httpx.MockTransport(
            handler
        ),
    )

    with pytest.raises(
        AISummaryProviderResponseError,
        match=(
            "response exceeded the "
            "configured size limit"
        ),
    ):
        provider.generate(
            make_safe_context()
        )


def test_provider_enforces_prompt_size_limit():
    provider = OllamaSummaryProvider(
        settings=make_settings(
            ai_local_max_prompt_chars=(
                1000
            )
        ),
        transport=httpx.MockTransport(
            lambda _request:
                httpx.Response(
                    status_code=200,
                    json={},
                )
        ),
    )

    context = make_safe_context(
        deterministic_executive_summary=(
            "A" * 1200
        )
    )

    with pytest.raises(
        AISummaryProviderConfigurationError,
        match=(
            "prompt exceeds the configured "
            "character limit"
        ),
    ):
        provider.generate(
            context
        )


def test_provider_converts_timeout_error():
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        raise httpx.ReadTimeout(
            "Timed out",
            request=request,
        )

    provider = OllamaSummaryProvider(
        settings=make_settings(),
        transport=httpx.MockTransport(
            handler
        ),
    )

    with pytest.raises(
        AISummaryProviderTimeoutError,
        match="request timed out",
    ):
        provider.generate(
            make_safe_context()
        )