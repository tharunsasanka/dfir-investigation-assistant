import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.main import app


client = TestClient(app)


def test_health_response_has_security_headers():
    response = client.get(
        "/api/v1/health"
    )

    assert response.status_code == 200

    assert (
        response.headers[
            "x-content-type-options"
        ]
        == "nosniff"
    )

    assert (
        response.headers[
            "x-frame-options"
        ]
        == "DENY"
    )

    assert (
        response.headers[
            "referrer-policy"
        ]
        == "no-referrer"
    )

    assert (
        "frame-ancestors 'none'"
        in response.headers[
            "content-security-policy"
        ]
    )

    assert (
        response.headers[
            "cross-origin-opener-policy"
        ]
        == "same-origin"
    )

    assert (
        response.headers[
            "cross-origin-resource-policy"
        ]
        == "same-site"
    )


def test_auth_response_disables_cache():
    response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token":
                "invalid-refresh-token-value",
        },
    )

    assert response.status_code == 401

    assert (
        response.headers[
            "cache-control"
        ]
        == "no-store, max-age=0"
    )

    assert (
        response.headers[
            "pragma"
        ]
        == "no-cache"
    )

    assert (
        response.headers[
            "expires"
        ]
        == "0"
    )


def test_trusted_cors_origin_is_allowed():
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin":
                "http://localhost:5173",
            "Access-Control-Request-Method":
                "POST",
            "Access-Control-Request-Headers":
                "authorization,content-type",
        },
    )

    assert response.status_code == 200

    assert (
        response.headers[
            "access-control-allow-origin"
        ]
        == "http://localhost:5173"
    )


def test_untrusted_cors_origin_is_rejected():
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin":
                "https://untrusted.example",
            "Access-Control-Request-Method":
                "POST",
        },
    )

    assert response.status_code == 400

    assert (
        "access-control-allow-origin"
        not in response.headers
    )


def test_production_rejects_weak_jwt_secret():
    with pytest.raises(
        ValidationError
    ):
        Settings(
            _env_file=None,
            environment="production",
            docs_enabled=False,
            jwt_secret_key=(
                "development-only-change-me"
            ),
            cors_origins=(
                "https://dfir.example"
            ),
            trusted_hosts=(
                "api.dfir.example"
            ),
        )


def test_production_rejects_wildcard_cors():
    with pytest.raises(
        ValidationError
    ):
        Settings(
            _env_file=None,
            environment="production",
            docs_enabled=False,
            jwt_secret_key=(
                "a-unique-production-secret-"
                "containing-more-than-32-characters"
            ),
            cors_origins="*",
            trusted_hosts=(
                "api.dfir.example"
            ),
        )


def test_production_rejects_wildcard_hosts():
    with pytest.raises(
        ValidationError
    ):
        Settings(
            _env_file=None,
            environment="production",
            docs_enabled=False,
            jwt_secret_key=(
                "a-unique-production-secret-"
                "containing-more-than-32-characters"
            ),
            cors_origins=(
                "https://dfir.example"
            ),
            trusted_hosts="*",
        )


def test_valid_production_configuration():
    settings = Settings(
        _env_file=None,
        environment="production",
        docs_enabled=False,
        jwt_secret_key=(
            "a-unique-production-secret-"
            "containing-more-than-32-characters"
        ),
        cors_origins=(
            "https://dfir.example"
        ),
        trusted_hosts=(
            "api.dfir.example"
        ),
        hsts_enabled=True,
    )

    assert (
        settings.environment
        == "production"
    )

    assert (
        settings.api_docs_enabled
        is False
    )

    assert (
        settings.hsts_active
        is True
    )