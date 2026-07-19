import hashlib
from collections.abc import Generator
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.evidence_storage import (
    get_evidence_path,
    remove_evidence_file,
)
from app.services.user_service import create_user


@pytest.fixture
def tamper_test_admin() -> Generator[
    dict[str, str],
    None,
    None,
]:
    unique_value = uuid4().hex

    email = (
        f"tamper-admin-{unique_value}"
        "@example.com"
    )

    password = "SecureTamper123!"

    case_title = (
        f"Evidence Tamper Test {unique_value}"
    )

    db = SessionLocal()

    try:
        create_user(
            db=db,
            user_data=UserCreate(
                email=email,
                full_name=(
                    "Evidence Tamper Test "
                    "Administrator"
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
            evidence_items = list(
                cleanup_db.scalars(
                    select(Evidence).where(
                        Evidence.case_id
                        == investigation_case.id,
                    )
                ).all()
            )

            for evidence_item in evidence_items:
                remove_evidence_file(
                    case_id=evidence_item.case_id,
                    stored_filename=(
                        evidence_item.stored_filename
                    ),
                )

                cleanup_db.delete(
                    evidence_item,
                )

            cleanup_db.flush()

            cleanup_db.delete(
                investigation_case,
            )

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


def test_evidence_tampering_is_detected(
    client: TestClient,
    tamper_test_admin: dict[str, str],
) -> None:
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": (
                tamper_test_admin["email"]
            ),
            "password": (
                tamper_test_admin["password"]
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

    case_response = client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "title": (
                tamper_test_admin["case_title"]
            ),
            "description": (
                "Temporary case used to verify "
                "evidence tamper detection."
            ),
            "severity": "high",
        },
    )

    assert case_response.status_code == 201

    case_id = case_response.json()["id"]

    original_content = (
        b"2026-07-19T12:30:00Z "
        b"user=alice action=login\n"
    )

    tampered_content = (
        b"2026-07-19T12:30:00Z "
        b"user=admin action=login\n"
    )

    assert (
        len(original_content)
        == len(tampered_content)
    )

    expected_original_hash = (
        hashlib.sha256(
            original_content,
        ).hexdigest()
    )

    expected_tampered_hash = (
        hashlib.sha256(
            tampered_content,
        ).hexdigest()
    )

    assert (
        expected_original_hash
        != expected_tampered_hash
    )

    upload_response = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=headers,
        data={
            "evidence_type": "log",
            "description": (
                "Temporary authentication log "
                "for tamper-detection testing."
            ),
            "source": (
                "Automated integrity test"
            ),
        },
        files={
            "file": (
                "authentication.log",
                original_content,
                "text/plain",
            ),
        },
    )

    assert upload_response.status_code == 201

    uploaded_evidence = upload_response.json()

    assert (
        uploaded_evidence["sha256"]
        == expected_original_hash
    )

    evidence_id = uploaded_evidence["id"]

    db = SessionLocal()

    try:
        stored_evidence = db.get(
            Evidence,
            UUID(evidence_id),
        )

        assert stored_evidence is not None

        evidence_path = get_evidence_path(
            stored_evidence.case_id,
            stored_evidence.stored_filename,
        )

        assert evidence_path.is_file()

        evidence_path.write_bytes(
            tampered_content,
        )

    finally:
        db.close()

    integrity_response = client.post(
        (
            f"/api/v1/evidence/{evidence_id}"
            "/verify-integrity"
        ),
        headers=headers,
    )

    assert (
        integrity_response.status_code
        == 200
    )

    integrity_result = (
        integrity_response.json()
    )

    assert (
        integrity_result["matches"]
        is False
    )

    assert (
        integrity_result[
            "expected_sha256"
        ]
        == expected_original_hash
    )

    assert (
        integrity_result[
            "actual_sha256"
        ]
        == expected_tampered_hash
    )

    assert (
        integrity_result[
            "expected_size_bytes"
        ]
        == len(original_content)
    )

    assert (
        integrity_result[
            "actual_size_bytes"
        ]
        == len(tampered_content)
    )

    custody_response = client.get(
        (
            f"/api/v1/evidence/{evidence_id}"
            "/custody-events"
        ),
        headers=headers,
    )

    assert custody_response.status_code == 200

    custody_events = custody_response.json()[
        "items"
    ]

    event_types = [
        event["event_type"]
        for event in custody_events
    ]

    assert (
        "integrity_failed"
        in event_types
    )

    failed_event = next(
        event
        for event in custody_events
        if event["event_type"]
        == "integrity_failed"
    )

    assert (
        failed_event["details"]["matches"]
        is False
    )

    assert (
        failed_event["details"][
            "expected_sha256"
        ]
        == expected_original_hash
    )

    assert (
        failed_event["details"][
            "actual_sha256"
        ]
        == expected_tampered_hash
    )

    assert (
        failed_event["actor_email"]
        == tamper_test_admin["email"]
    )