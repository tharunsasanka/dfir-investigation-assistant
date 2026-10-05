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
def evidence_security_admin() -> Generator[
    dict[str, str],
    None,
    None,
]:
    unique_value = uuid4().hex

    email = (
        f"evidence-security-{unique_value}"
        "@example.com"
    )

    password = "SecureUpload123!"

    case_title = (
        f"Evidence Security Test {unique_value}"
    )

    db = SessionLocal()

    try:
        create_user(
            db=db,
            user_data=UserCreate(
                email=email,
                full_name=(
                    "Evidence Security Test "
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


def authenticate_and_create_case(
    *,
    client: TestClient,
    account: dict[str, str],
) -> tuple[dict[str, str], str]:
    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": account["email"],
            "password": account["password"],
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
            "title": account["case_title"],
            "description": (
                "Temporary case for evidence "
                "upload security validation."
            ),
            "severity": "medium",
        },
    )

    assert case_response.status_code == 201

    return headers, case_response.json()["id"]


def test_path_traversal_filename_is_neutralized(
    client: TestClient,
    evidence_security_admin: dict[str, str],
) -> None:
    headers, case_id = (
        authenticate_and_create_case(
            client=client,
            account=evidence_security_admin,
        )
    )

    file_content = (
        b"Safe evidence upload security test.\n"
    )

    upload_response = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=headers,
        data={
            "evidence_type": "log",
            "description": (
                "Filename normalization test."
            ),
            "source": (
                "Automated security test"
            ),
        },
        files={
            "file": (
                "../../suspicious.log",
                file_content,
                "text/plain",
            ),
        },
    )

    assert upload_response.status_code == 201

    uploaded = upload_response.json()

    assert (
        uploaded["original_filename"]
        == "suspicious.log"
    )

    evidence_id = UUID(uploaded["id"])

    download_response = client.get(
        (
            f"/api/v1/evidence/"
            f"{evidence_id}/content"
        ),
        headers=headers,
    )

    assert download_response.status_code == 200

    assert (
        download_response.content
        == file_content
    )

    assert (
        download_response.headers[
            "content-type"
        ]
        == "application/octet-stream"
    )

    content_disposition = (
        download_response.headers[
            "content-disposition"
        ]
    )

    assert content_disposition.lower().startswith(
        "attachment;"
    )

    assert (
        "suspicious.log"
        in content_disposition
    )

    assert (
        "../"
        not in content_disposition
    )

    assert (
        "..\\"
        not in content_disposition
    )

    assert (
        "inline"
        not in content_disposition.lower()
    )

    db = SessionLocal()

    try:
        stored_evidence = db.get(
            Evidence,
            evidence_id,
        )

        assert stored_evidence is not None

        assert (
            stored_evidence.original_filename
            == "suspicious.log"
        )

        assert "/" not in (
            stored_evidence.stored_filename
        )

        assert "\\" not in (
            stored_evidence.stored_filename
        )

        assert (
            stored_evidence.stored_filename
            == evidence_id.hex
        )

        stored_path = get_evidence_path(
            stored_evidence.case_id,
            stored_evidence.stored_filename,
        )

        assert stored_path.is_file()
        assert stored_path.read_bytes() == file_content

    finally:
        db.close()


def test_empty_evidence_file_is_rejected(
    client: TestClient,
    evidence_security_admin: dict[str, str],
) -> None:
    headers, case_id = (
        authenticate_and_create_case(
            client=client,
            account=evidence_security_admin,
        )
    )

    upload_response = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=headers,
        data={
            "evidence_type": "log",
            "description": (
                "Empty-file rejection test."
            ),
            "source": (
                "Automated security test"
            ),
        },
        files={
            "file": (
                "empty.log",
                b"",
                "text/plain",
            ),
        },
    )

    assert upload_response.status_code == 400

    assert upload_response.json()["detail"] == (
        "Empty evidence files are not accepted."
    )

    db = SessionLocal()

    try:
        evidence_count = len(
            list(
                db.scalars(
                    select(Evidence).where(
                        Evidence.case_id
                        == UUID(case_id),
                    )
                ).all()
            )
        )

        assert evidence_count == 0

    finally:
        db.close()


def test_oversized_evidence_file_is_rejected(
    client: TestClient,
    evidence_security_admin: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers, case_id = (
        authenticate_and_create_case(
            client=client,
            account=evidence_security_admin,
        )
    )

    monkeypatch.setenv(
        "EVIDENCE_MAX_UPLOAD_BYTES",
        "32",
    )

    oversized_content = b"A" * 33

    upload_response = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        headers=headers,
        data={
            "evidence_type": "log",
            "description": (
                "Upload-size enforcement test."
            ),
            "source": (
                "Automated security test"
            ),
        },
        files={
            "file": (
                "oversized.log",
                oversized_content,
                "text/plain",
            ),
        },
    )

    assert upload_response.status_code == 413

    assert upload_response.json()["detail"] == (
        "The evidence file exceeds "
        "the configured upload limit."
    )

    db = SessionLocal()

    try:
        evidence_count = len(
            list(
                db.scalars(
                    select(Evidence).where(
                        Evidence.case_id
                        == UUID(case_id),
                    )
                ).all()
            )
        )

        assert evidence_count == 0

    finally:
        db.close()