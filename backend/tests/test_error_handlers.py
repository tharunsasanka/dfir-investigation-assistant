from uuid import UUID

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.error_handlers import (
    GENERIC_INTERNAL_ERROR_MESSAGE,
    unhandled_exception_handler,
)
from app.main import app


settings = get_settings()

SENSITIVE_EXCEPTION_TEXT = (
    "database-password-sensitive-value"
)


def build_error_test_app() -> FastAPI:
    test_app = FastAPI()

    test_app.add_exception_handler(
        Exception,
        unhandled_exception_handler,
    )

    @test_app.get(
        "/failure"
    )
    def trigger_failure():
        raise RuntimeError(
            SENSITIVE_EXCEPTION_TEXT
        )

    return test_app


def test_main_application_registers_handler():
    assert (
        app.exception_handlers[
            Exception
        ]
        is unhandled_exception_handler
    )


def test_unhandled_error_returns_safe_json():
    client = TestClient(
        build_error_test_app(),
        raise_server_exceptions=False,
    )

    response = client.get(
        "/failure"
    )

    assert response.status_code == 500

    response_data = response.json()

    assert response_data["detail"] == (
        GENERIC_INTERNAL_ERROR_MESSAGE
    )

    error_id = response_data[
        "error_id"
    ]

    assert UUID(error_id)

    assert (
        response.headers[
            "x-error-id"
        ]
        == error_id
    )

    assert (
        response.headers[
            "content-type"
        ].startswith(
            "application/json"
        )
    )

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
            "x-content-type-options"
        ]
        == "nosniff"
    )

    assert (
        SENSITIVE_EXCEPTION_TEXT
        not in response.text
    )

    assert (
        "Traceback"
        not in response.text
    )

    assert (
        "RuntimeError"
        not in response.text
    )


def test_error_identifier_is_cors_exposed():
    assert (
        "X-Error-ID"
        in settings.cors_exposed_header_list
    )
