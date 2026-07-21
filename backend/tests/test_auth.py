from collections.abc import Generator
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.user_service import create_user


settings = get_settings()


@pytest.fixture
def auth_user() -> Generator[dict[str, str], None, None]:
    email = f"auth-test-{uuid4().hex}@example.com"
    password = "SecureTest123!"

    db = SessionLocal()

    try:
        create_user(
            db=db,
            user_data=UserCreate(
                email=email,
                full_name="Authentication Test User",
                password=password,
            ),
        )

        yield {
            "email": email,
            "password": password,
        }

    finally:
        user = db.scalar(
            select(User).where(User.email == email)
        )

        if user is not None:
            db.delete(user)
            db.commit()

        db.close()


def test_login_and_current_user(
    client: TestClient,
    auth_user: dict[str, str],
) -> None:
    unauthenticated_response = client.get(
        "/api/v1/auth/me"
    )

    assert unauthenticated_response.status_code == 401

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": auth_user["email"],
            "password": auth_user["password"],
        },
    )

    assert login_response.status_code == 200, login_response.text

    login_data = login_response.json()

    assert login_data["token_type"] == "bearer"
    assert login_data["access_token"]
    assert login_data["refresh_token"]
    assert login_data["expires_in"] == (
        settings.access_token_expire_minutes * 60
    )
    assert login_data["user"]["email"] == auth_user["email"]
    assert login_data["user"]["is_active"] is True

    access_token = login_data["access_token"]

    current_user_response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )

    assert current_user_response.status_code == 200, (
        current_user_response.text
    )

    current_user = current_user_response.json()

    assert current_user["email"] == auth_user["email"]
    assert current_user["is_active"] is True
    assert current_user["is_superuser"] is False


def test_refresh_access_token(
    client: TestClient,
    auth_user: dict[str, str],
) -> None:
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": auth_user["email"],
            "password": auth_user["password"],
        },
    )

    assert login_response.status_code == 200, login_response.text

    login_data = login_response.json()
    refresh_token = login_data["refresh_token"]

    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={
            "refresh_token": refresh_token,
        },
    )

    assert refresh_response.status_code == 200, refresh_response.text

    refresh_data = refresh_response.json()

    assert refresh_data["token_type"] == "bearer"
    assert refresh_data["access_token"]
    assert refresh_data["expires_in"] == (
        settings.access_token_expire_minutes * 60
    )

    current_user_response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": (
                f"Bearer {refresh_data['access_token']}"
            ),
        },
    )

    assert current_user_response.status_code == 200, (
        current_user_response.text
    )

    current_user_data = current_user_response.json()

    assert current_user_data["email"] == auth_user["email"]


def test_invalid_login_credentials(
    client: TestClient,
    auth_user: dict[str, str],
) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": auth_user["email"],
            "password": "IncorrectPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "The email address or password is incorrect."
    )