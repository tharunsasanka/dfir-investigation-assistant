from collections.abc import Generator
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.case import Case
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.user_service import create_user


@pytest.fixture
def deletion_admin() -> Generator[
    dict[str, str],
    None,
    None,
]:
    unique_value = uuid4().hex

    email = (
        f"case-delete-{unique_value}"
        "@example.com"
    )

    password = "SecureDelete123!"

    case_title = (
        f"Deletion Test Case {unique_value}"
    )

    db = SessionLocal()

    try:
        create_user(
            db=db,
            user_data=UserCreate(
                email=email,
                full_name=(
                    "Case Deletion Test Admin"
                ),
                password=password,
            ),
            is_superuser=True,
        )

    finally:
        db.close()

    yield {
        "email": email,
        "password": password,
        "case_title": case_title,
    }

    cleanup_db = SessionLocal()

    try:
        investigation_case = (
            cleanup_db.scalar(
                select(Case).where(
                    Case.title == case_title
                )
            )
        )

        if investigation_case is not None:
            cleanup_db.delete(
                investigation_case
            )
            cleanup_db.commit()

        user = cleanup_db.scalar(
            select(User).where(
                User.email == email
            )
        )

        if user is not None:
            cleanup_db.delete(user)
            cleanup_db.commit()

    finally:
        cleanup_db.close()


def test_case_soft_deletion(
    client: TestClient,
    deletion_admin: dict[str, str],
) -> None:
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": deletion_admin["email"],
            "password": (
                deletion_admin["password"]
            ),
        },
    )

    assert login_response.status_code == 200

    access_token = (
        login_response.json()[
            "access_token"
        ]
    )

    headers = {
        "Authorization": (
            f"Bearer {access_token}"
        ),
    }

    create_response = client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "title": (
                deletion_admin["case_title"]
            ),
            "description": (
                "Temporary automated deletion "
                "verification record."
            ),
            "severity": "medium",
        },
    )

    assert create_response.status_code == 201

    case_id = create_response.json()["id"]

    summary_before = client.get(
        "/api/v1/dashboard/case-summary",
        headers=headers,
    )

    assert summary_before.status_code == 200

    delete_response = client.delete(
        f"/api/v1/cases/{case_id}",
        headers=headers,
    )

    assert delete_response.status_code == 204

    detail_response = client.get(
        f"/api/v1/cases/{case_id}",
        headers=headers,
    )

    assert detail_response.status_code == 404

    list_response = client.get(
        "/api/v1/cases",
        headers=headers,
        params={
            "search": (
                deletion_admin["case_title"]
            ),
        },
    )

    assert list_response.status_code == 200
    assert list_response.json()["total"] == 0

    summary_after = client.get(
        "/api/v1/dashboard/case-summary",
        headers=headers,
    )

    assert summary_after.status_code == 200

    assert (
        summary_after.json()["total_cases"]
        == summary_before.json()[
            "total_cases"
        ] - 1
    )

    db = SessionLocal()

    try:
        archived_case = db.get(
            Case,
            case_id,
        )

        assert archived_case is not None
        assert archived_case.is_deleted is True
        assert archived_case.deleted_at is not None
        assert (
            archived_case.deleted_by_user_id
            is not None
        )

    finally:
        db.close()