from collections.abc import Generator
from uuid import uuid4

import pytest
from fastapi.testclient import (
    TestClient,
)
from sqlalchemy import (
    delete,
    select,
)

from app.core.config import (
    get_settings,
)
from app.db.session import (
    SessionLocal,
)
from app.models.authentication import (
    LoginRateLimit,
)
from app.models.user import User
from app.schemas.user import (
    UserCreate,
)
from app.services.user_service import (
    create_user,
)


settings = get_settings()


@pytest.fixture
def auth_user() -> Generator[
    dict[str, str],
    None,
    None,
]:
    email = (
        f"auth-test-"
        f"{uuid4().hex}"
        "@example.com"
    )

    password = (
        "SecureTest123!"
    )

    db = SessionLocal()

    try:
        db.execute(
            delete(
                LoginRateLimit
            )
        )

        db.commit()

        create_user(
            db=db,
            user_data=UserCreate(
                email=email,
                full_name=(
                    "Authentication "
                    "Test User"
                ),
                password=password,
            ),
        )

        yield {
            "email": email,
            "password": password,
        }

    finally:
        user = db.scalar(
            select(
                User
            ).where(
                User.email == email
            )
        )

        if user is not None:
            db.delete(user)

        db.execute(
            delete(
                LoginRateLimit
            )
        )

        db.commit()
        db.close()


def login_user(
    client: TestClient,
    auth_user: dict[str, str],
) -> dict:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email":
                auth_user["email"],
            "password":
                auth_user["password"],
        },
    )

    assert (
        response.status_code
        == 200
    ), response.text

    return response.json()


def test_login_and_current_user(
    client: TestClient,
    auth_user: dict[str, str],
) -> None:
    unauthenticated_response = (
        client.get(
            "/api/v1/auth/me"
        )
    )

    assert (
        unauthenticated_response
        .status_code
        == 401
    )

    login_data = login_user(
        client,
        auth_user,
    )

    assert (
        login_data["token_type"]
        == "bearer"
    )

    assert login_data[
        "access_token"
    ]

    assert login_data[
        "refresh_token"
    ]

    assert (
        login_data["expires_in"]
        == settings
        .access_token_expire_minutes
        * 60
    )

    assert (
        login_data["user"]["email"]
        == auth_user["email"]
    )

    access_token = (
        login_data[
            "access_token"
        ]
    )

    response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization":
                f"Bearer {access_token}",
        },
    )

    assert (
        response.status_code
        == 200
    ), response.text

    assert (
        response.json()["email"]
        == auth_user["email"]
    )


def test_refresh_rotates_token_pair(
    client: TestClient,
    auth_user: dict[str, str],
) -> None:
    login_data = login_user(
        client,
        auth_user,
    )

    original_refresh_token = (
        login_data[
            "refresh_token"
        ]
    )

    response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token":
                original_refresh_token,
        },
    )

    assert (
        response.status_code
        == 200
    ), response.text

    rotated_data = (
        response.json()
    )

    assert rotated_data[
        "access_token"
    ]

    assert rotated_data[
        "refresh_token"
    ]

    assert (
        rotated_data[
            "refresh_token"
        ]
        != original_refresh_token
    )

    current_user_response = (
        client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": (
                    "Bearer "
                    f"{rotated_data['access_token']}"
                )
            },
        )
    )

    assert (
        current_user_response
        .status_code
        == 200
    )


def test_refresh_reuse_revokes_session(
    client: TestClient,
    auth_user: dict[str, str],
) -> None:
    login_data = login_user(
        client,
        auth_user,
    )

    original_refresh_token = (
        login_data[
            "refresh_token"
        ]
    )

    first_refresh = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token":
                original_refresh_token,
        },
    )

    assert (
        first_refresh.status_code
        == 200
    )

    rotated_data = (
        first_refresh.json()
    )

    reuse_response = (
        client.post(
            "/api/v1/auth/refresh",
            json={
                "refresh_token":
                    original_refresh_token,
            },
        )
    )

    assert (
        reuse_response.status_code
        == 401
    )

    access_response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": (
                "Bearer "
                f"{rotated_data['access_token']}"
            )
        },
    )

    assert (
        access_response.status_code
        == 401
    )

    rotated_refresh_response = (
        client.post(
            "/api/v1/auth/refresh",
            json={
                "refresh_token": (
                    rotated_data[
                        "refresh_token"
                    ]
                )
            },
        )
    )

    assert (
        rotated_refresh_response
        .status_code
        == 401
    )


def test_logout_revokes_access_and_refresh(
    client: TestClient,
    auth_user: dict[str, str],
) -> None:
    login_data = login_user(
        client,
        auth_user,
    )

    logout_response = (
        client.post(
            "/api/v1/auth/logout",
            json={
                "refresh_token": (
                    login_data[
                        "refresh_token"
                    ]
                )
            },
        )
    )

    assert (
        logout_response.status_code
        == 200
    )

    assert (
        logout_response.json()[
            "message"
        ]
        == (
            "The authentication "
            "session was ended."
        )
    )

    access_response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": (
                "Bearer "
                f"{login_data['access_token']}"
            )
        },
    )

    assert (
        access_response.status_code
        == 401
    )

    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": (
                login_data[
                    "refresh_token"
                ]
            )
        },
    )

    assert (
        refresh_response.status_code
        == 401
    )


def test_invalid_login_credentials(
    client: TestClient,
    auth_user: dict[str, str],
) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email":
                auth_user["email"],
            "password": (
                "IncorrectPassword123!"
            ),
        },
    )

    assert (
        response.status_code
        == 401
    )

    assert (
        response.json()["detail"]
        == (
            "The email address or "
            "password is incorrect."
        )
    )


def test_login_rate_limit(
    client: TestClient,
) -> None:
    original_attempt_limit = (
        settings
        .login_rate_limit_attempts
    )

    db = SessionLocal()

    try:
        settings.login_rate_limit_attempts = 3

        db.execute(
            delete(
                LoginRateLimit
            )
        )

        db.commit()

        for _ in range(2):
            response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": (
                        "missing-rate-test"
                        "@example.com"
                    ),
                    "password": (
                        "IncorrectPassword123!"
                    ),
                },
            )

            assert (
                response.status_code
                == 401
            )

        blocked_response = (
            client.post(
                "/api/v1/auth/login",
                json={
                    "email": (
                        "missing-rate-test"
                        "@example.com"
                    ),
                    "password": (
                        "IncorrectPassword123!"
                    ),
                },
            )
        )

        assert (
            blocked_response
            .status_code
            == 429
        )

        assert (
            int(
                blocked_response
                .headers[
                    "Retry-After"
                ]
            )
            >= 1
        )

        repeated_response = (
            client.post(
                "/api/v1/auth/login",
                json={
                    "email": (
                        "missing-rate-test"
                        "@example.com"
                    ),
                    "password": (
                        "IncorrectPassword123!"
                    ),
                },
            )
        )

        assert (
            repeated_response
            .status_code
            == 429
        )

    finally:
        settings.login_rate_limit_attempts = (
            original_attempt_limit
        )

        db.execute(
            delete(
                LoginRateLimit
            )
        )

        db.commit()
        db.close()