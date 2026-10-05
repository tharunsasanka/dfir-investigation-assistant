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
def evidence_admin() -> Generator[
    dict[str, str],
    None,
    None,
]:
    unique_value = uuid4().hex

    email = (
        f"evidence-admin-{unique_value}"
        "@example.com"
    )

    password = "SecureEvidence123!"

    case_title = (
        f"Evidence Test Case {unique_value}"
    )

    db = SessionLocal()

    try:
        create_user(
            db=db,
            user_data=UserCreate(
                email=email,
                full_name=(
                    "Evidence Test Administrator"
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


def test_secure_evidence_management(
    client: TestClient,
    evidence_admin: dict[str, str],
) -> None:
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": evidence_admin["email"],
            "password": (
                evidence_admin["password"]
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
                evidence_admin["case_title"]
            ),
            "description": (
                "Temporary automated evidence "
                "management verification case."
            ),
            "severity": "medium",
        },
    )

    assert case_response.status_code == 201

    case_id = case_response.json()["id"]

    file_content = (
        b"2026-07-19T12:30:00Z "
        b"PowerShell process started\n"
        b"Host=WORKSTATION-01 "
        b"Process=powershell.exe\n"
    )

    expected_sha256 = hashlib.sha256(
        file_content,
    ).hexdigest()

    upload_response = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=headers,
        data={
            "evidence_type": "log",
            "description": (
                "PowerShell process event log "
                "used for automated verification."
            ),
            "source": (
                "Windows endpoint collection"
            ),
        },
        files={
            "file": (
                "powershell-security.log",
                file_content,
                "text/plain",
            ),
        },
    )

    assert upload_response.status_code == 201

    uploaded_evidence = upload_response.json()

    assert (
        uploaded_evidence[
            "original_filename"
        ]
        == "powershell-security.log"
    )

    assert (
        uploaded_evidence["size_bytes"]
        == len(file_content)
    )

    assert (
        uploaded_evidence["sha256"]
        == expected_sha256
    )

    assert (
        uploaded_evidence["evidence_type"]
        == "log"
    )

    assert (
        uploaded_evidence["case_id"]
        == case_id
    )

    evidence_id = uploaded_evidence["id"]

    list_response = client.get(
        f"/api/v1/cases/{case_id}/evidence",
        headers=headers,
    )

    assert list_response.status_code == 200

    list_data = list_response.json()

    assert list_data["total"] == 1
    assert len(list_data["items"]) == 1

    assert (
        list_data["items"][0]["id"]
        == evidence_id
    )

    detail_response = client.get(
        f"/api/v1/evidence/{evidence_id}",
        headers=headers,
    )

    assert detail_response.status_code == 200

    assert (
        detail_response.json()["sha256"]
        == expected_sha256
    )

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

    integrity_data = (
        integrity_response.json()
    )

    assert integrity_data["matches"] is True

    assert (
        integrity_data["expected_sha256"]
        == expected_sha256
    )

    assert (
        integrity_data["actual_sha256"]
        == expected_sha256
    )

    assert (
        integrity_data[
            "expected_size_bytes"
        ]
        == len(file_content)
    )

    assert (
        integrity_data[
            "actual_size_bytes"
        ]
        == len(file_content)
    )

    content_response = client.get(
        (
            f"/api/v1/evidence/{evidence_id}"
            "/content"
        ),
        headers=headers,
    )

    assert content_response.status_code == 200
    assert content_response.content == file_content

    assert (
        content_response.headers[
            "content-type"
        ]
        == "application/octet-stream"
    )

    content_disposition = (
        content_response.headers[
            "content-disposition"
        ]
    )

    assert content_disposition.lower().startswith(
        "attachment;"
    )

    assert (
        "powershell-security.log"
        in content_disposition
    )

    assert (
        "inline"
        not in content_disposition.lower()
    )

    assert (
        content_response.headers[
            "cache-control"
        ]
        == "no-store, private"
    )

    assert (
        content_response.headers[
            "pragma"
        ]
        == "no-cache"
    )

    assert (
        content_response.headers[
            "x-content-type-options"
        ]
        == "nosniff"
    )

    custody_response = client.get(
        (
            f"/api/v1/evidence/{evidence_id}"
            "/custody-events"
        ),
        headers=headers,
    )

    assert custody_response.status_code == 200

    custody_data = custody_response.json()

    assert custody_data["total"] == 3

    event_types = {
        event["event_type"]
        for event in custody_data["items"]
    }

    assert "uploaded" in event_types
    assert "integrity_verified" in event_types
    assert "accessed" in event_types

    db = SessionLocal()

    try:
        stored_evidence = db.get(
            Evidence,
            UUID(evidence_id),
        )

        assert stored_evidence is not None

        assert (
            stored_evidence.sha256
            == expected_sha256
        )

        assert (
            stored_evidence.size_bytes
            == len(file_content)
        )

        assert (
            stored_evidence.original_filename
            == "powershell-security.log"
        )

        assert (
            stored_evidence.stored_filename
            != stored_evidence.original_filename
        )

        stored_path = get_evidence_path(
            stored_evidence.case_id,
            stored_evidence.stored_filename,
        )

        assert stored_path.is_file()

        assert (
            stored_path.read_bytes()
            == file_content
        )

    finally:
        db.close()