from collections.abc import Generator
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.db.session import SessionLocal
from app.models.case import Case
from app.models.case_audit import CaseAuditEvent
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.user_service import create_user


@pytest.fixture
def audit_admin() -> Generator[
    dict[str, str],
    None,
    None,
]:
    unique_value = uuid4().hex

    email = (
        f"audit-admin-{unique_value}"
        "@example.com"
    )

    password = "SecureAudit123!"

    case_title = (
        f"Audit History Case {unique_value}"
    )

    db = SessionLocal()

    try:
        create_user(
            db=db,
            user_data=UserCreate(
                email=email,
                full_name=(
                    "Audit History Test Admin"
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
        investigation_case = cleanup_db.scalar(
            select(Case).where(
                Case.title == case_title,
            )
        )

        if investigation_case is not None:
            cleanup_db.execute(
                delete(CaseAuditEvent).where(
                    CaseAuditEvent.case_id
                    == investigation_case.id,
                )
            )

            cleanup_db.delete(
                investigation_case,
            )

            cleanup_db.flush()

        user = cleanup_db.scalar(
            select(User).where(
                User.email == email,
            )
        )

        if user is not None:
            cleanup_db.delete(user)

        cleanup_db.commit()

    except Exception:
        cleanup_db.rollback()
        raise

    finally:
        cleanup_db.close()


def test_case_audit_history(
    client: TestClient,
    audit_admin: dict[str, str],
) -> None:
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": audit_admin["email"],
            "password": (
                audit_admin["password"]
            ),
        },
    )

    assert login_response.status_code == 200

    access_token = login_response.json()[
        "access_token"
    ]

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
                audit_admin["case_title"]
            ),
            "description": (
                "Temporary automated audit "
                "history verification record."
            ),
            "severity": "medium",
        },
    )

    assert create_response.status_code == 201

    case_id = create_response.json()["id"]

    update_response = client.patch(
        f"/api/v1/cases/{case_id}",
        headers=headers,
        json={
            "severity": "high",
            "status": "investigating",
        },
    )

    assert update_response.status_code == 200

    initial_audit_response = client.get(
        (
            f"/api/v1/cases/{case_id}"
            "/audit-events"
        ),
        headers=headers,
    )

    assert (
        initial_audit_response.status_code
        == 200
    )

    initial_data = (
        initial_audit_response.json()
    )

    assert initial_data["total"] == 2

    initial_events = initial_data["items"]

    assert [
        event["event_type"]
        for event in initial_events
    ] == [
        "updated",
        "created",
    ]

    updated_event = initial_events[0]

    assert (
        updated_event["changes"]["before"][
            "severity"
        ]
        == "medium"
    )

    assert (
        updated_event["changes"]["after"][
            "severity"
        ]
        == "high"
    )

    assert (
        updated_event["changes"]["before"][
            "status"
        ]
        == "open"
    )

    assert (
        updated_event["changes"]["after"][
            "status"
        ]
        == "investigating"
    )

    created_event = initial_events[1]

    assert (
        created_event["actor_email"]
        == audit_admin["email"]
    )

    assert (
        created_event["changes"]["after"][
            "title"
        ]
        == audit_admin["case_title"]
    )

    archive_response = client.delete(
        f"/api/v1/cases/{case_id}",
        headers=headers,
    )

    assert archive_response.status_code == 204

    final_audit_response = client.get(
        (
            f"/api/v1/cases/{case_id}"
            "/audit-events"
        ),
        headers=headers,
    )

    assert (
        final_audit_response.status_code
        == 200
    )

    final_data = final_audit_response.json()

    assert final_data["total"] == 3

    final_events = final_data["items"]

    assert [
        event["event_type"]
        for event in final_events
    ] == [
        "archived",
        "updated",
        "created",
    ]

    archived_event = final_events[0]

    assert (
        archived_event["actor_email"]
        == audit_admin["email"]
    )

    assert (
        archived_event["changes"]["before"][
            "is_deleted"
        ]
        is False
    )

    assert (
        archived_event["changes"]["after"][
            "is_deleted"
        ]
        is True
    )

    assert (
        archived_event["changes"]["after"][
            "deleted_at"
        ]
        is not None
    )

    assert (
        archived_event["changes"]["after"][
            "deleted_by_user_id"
        ]
        is not None
    )