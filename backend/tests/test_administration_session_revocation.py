from collections.abc import Generator
from dataclasses import dataclass
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.db.session import SessionLocal
from app.models.authentication import (
    LoginRateLimit,
)
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.user_service import (
    create_user,
)


@dataclass(frozen=True)
class SessionRevocationEnvironment:
    admin_email: str
    admin_password: str
    user_id: str
    user_email: str
    user_password: str


@pytest.fixture
def session_revocation_environment() -> Generator[
    SessionRevocationEnvironment,
    None,
    None,
]:
    token = uuid4().hex

    admin_email = (
        f"session-admin-{token}"
        "@example.com"
    )

    user_email = (
        f"session-user-{token}"
        "@example.com"
    )

    admin_password = (
        "SessionAdmin123!"
    )

    user_password = (
        "SessionUser123!"
    )

    db = SessionLocal()

    try:
        db.execute(
            delete(
                LoginRateLimit
            )
        )

        admin = create_user(
            db=db,
            user_data=UserCreate(
                email=admin_email,
                full_name=(
                    "Session Test Admin"
                ),
                password=admin_password,
            ),
            is_superuser=True,
        )

        user = create_user(
            db=db,
            user_data=UserCreate(
                email=user_email,
                full_name=(
                    "Session Test User"
                ),
                password=user_password,
            ),
        )

        yield SessionRevocationEnvironment(
            admin_email=admin.email,
            admin_password=admin_password,
            user_id=str(user.id),
            user_email=user.email,
            user_password=user_password,
        )

    finally:
        db.rollback()
        db.expire_all()

        users = list(
            db.scalars(
                select(
                    User
                ).where(
                    User.email.in_(
                        [
                            admin_email,
                            user_email,
                        ]
                    )
                )
            ).all()
        )

        for user in users:
            db.delete(user)

        db.execute(
            delete(
                LoginRateLimit
            )
        )

        db.commit()
        db.close()


def login(
    client: TestClient,
    email: str,
    password: str,
) -> dict:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert response.status_code == 200, (
        response.text
    )

    return response.json()


def access_headers(
    session: dict,
) -> dict[str, str]:
    return {
        "Authorization": (
            "Bearer "
            f"{session['access_token']}"
        )
    }


def assert_session_revoked(
    client: TestClient,
    session: dict,
) -> None:
    access_response = client.get(
        "/api/v1/auth/me",
        headers=access_headers(
            session
        ),
    )

    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": (
                session[
                    "refresh_token"
                ]
            )
        },
    )

    assert access_response.status_code == 401
    assert refresh_response.status_code == 401


def test_password_change_revokes_all_sessions(
    client: TestClient,
    session_revocation_environment:
        SessionRevocationEnvironment,
) -> None:
    environment = (
        session_revocation_environment
    )

    session_one = login(
        client,
        environment.user_email,
        environment.user_password,
    )

    session_two = login(
        client,
        environment.user_email,
        environment.user_password,
    )

    new_password = (
        "ChangedSession456!"
    )

    response = client.post(
        "/api/v1/profile/password",
        headers=access_headers(
            session_one
        ),
        json={
            "current_password": (
                environment.user_password
            ),
            "new_password": new_password,
            "confirm_password": (
                new_password
            ),
        },
    )

    assert response.status_code == 200, (
        response.text
    )

    assert_session_revoked(
        client,
        session_one,
    )

    assert_session_revoked(
        client,
        session_two,
    )

    old_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": (
                environment.user_email
            ),
            "password": (
                environment.user_password
            ),
        },
    )

    new_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": (
                environment.user_email
            ),
            "password": new_password,
        },
    )

    assert old_login.status_code == 401
    assert new_login.status_code == 200


def test_account_deactivation_revokes_all_sessions(
    client: TestClient,
    session_revocation_environment:
        SessionRevocationEnvironment,
) -> None:
    environment = (
        session_revocation_environment
    )

    session_one = login(
        client,
        environment.user_email,
        environment.user_password,
    )

    session_two = login(
        client,
        environment.user_email,
        environment.user_password,
    )

    admin_session = login(
        client,
        environment.admin_email,
        environment.admin_password,
    )

    response = client.patch(
        (
            "/api/v1/users/"
            f"{environment.user_id}"
        ),
        headers=access_headers(
            admin_session
        ),
        json={
            "is_active": False,
        },
    )

    assert response.status_code == 200, (
        response.text
    )

    assert response.json()[
        "is_active"
    ] is False

    assert_session_revoked(
        client,
        session_one,
    )

    assert_session_revoked(
        client,
        session_two,
    )

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": (
                environment.user_email
            ),
            "password": (
                environment.user_password
            ),
        },
    )

    assert login_response.status_code == 403


def test_administrator_password_reset_revokes_sessions(
    client: TestClient,
    session_revocation_environment:
        SessionRevocationEnvironment,
) -> None:
    environment = (
        session_revocation_environment
    )

    session_one = login(
        client,
        environment.user_email,
        environment.user_password,
    )

    session_two = login(
        client,
        environment.user_email,
        environment.user_password,
    )

    admin_session = login(
        client,
        environment.admin_email,
        environment.admin_password,
    )

    new_password = (
        "AdministratorReset789!"
    )

    response = client.patch(
        (
            "/api/v1/users/"
            f"{environment.user_id}"
        ),
        headers=access_headers(
            admin_session
        ),
        json={
            "password": new_password,
        },
    )

    assert response.status_code == 200, (
        response.text
    )

    assert_session_revoked(
        client,
        session_one,
    )

    assert_session_revoked(
        client,
        session_two,
    )

    old_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": (
                environment.user_email
            ),
            "password": (
                environment.user_password
            ),
        },
    )

    new_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": (
                environment.user_email
            ),
            "password": new_password,
        },
    )

    assert old_login.status_code == 401
    assert new_login.status_code == 200