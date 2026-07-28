from collections.abc import Generator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.user_service import create_user


@dataclass(frozen=True)
class AdministrationEnvironment:
    token: str
    admin_email: str
    admin_password: str
    standard_email: str
    standard_password: str
    role_id: str
    permission_id: str


@pytest.fixture
def administration_environment() -> Generator[
    AdministrationEnvironment,
    None,
    None,
]:
    token = uuid4().hex

    admin_email = (
        f"administration-admin-{token}@example.com"
    )
    admin_password = "AdministrationAdmin123!"

    standard_email = (
        f"administration-user-{token}@example.com"
    )
    standard_password = "AdministrationUser123!"

    db = SessionLocal()

    permission = Permission(
        name=f"test.permission.{token}",
        description="Temporary administration test permission.",
    )

    role = Role(
        name=f"test_role_{token}",
        description="Temporary administration test role.",
        permissions=[permission],
    )

    try:
        db.add(role)
        db.commit()
        db.refresh(role)
        db.refresh(permission)

        create_user(
            db=db,
            user_data=UserCreate(
                email=admin_email,
                full_name="Administration Test Admin",
                password=admin_password,
            ),
            is_superuser=True,
        )

        create_user(
            db=db,
            user_data=UserCreate(
                email=standard_email,
                full_name="Administration Standard User",
                password=standard_password,
            ),
        )

        yield AdministrationEnvironment(
            token=token,
            admin_email=admin_email,
            admin_password=admin_password,
            standard_email=standard_email,
            standard_password=standard_password,
            role_id=str(role.id),
            permission_id=str(permission.id),
        )

    finally:
        db.rollback()
        db.expire_all()

        users = list(
            db.scalars(
                select(User).where(
                    User.email.ilike(
                        f"%{token}%"
                    )
                )
            ).all()
        )

        for user in users:
            db.delete(user)

        db.flush()

        stored_role = db.get(
            Role,
            role.id,
        )

        if stored_role is not None:
            db.delete(stored_role)
            db.flush()

        stored_permission = db.get(
            Permission,
            permission.id,
        )

        if stored_permission is not None:
            db.delete(stored_permission)

        db.commit()
        db.close()


def login_headers(
    client: TestClient,
    email: str,
    password: str,
) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert response.status_code == 200, response.text

    access_token = response.json()["access_token"]

    return {
        "Authorization": f"Bearer {access_token}",
    }


def test_administration_routes_require_authentication(
    client: TestClient,
) -> None:
    users_response = client.get(
        "/api/v1/users"
    )

    roles_response = client.get(
        "/api/v1/roles"
    )

    permissions_response = client.get(
        "/api/v1/permissions"
    )

    profile_response = client.patch(
        "/api/v1/profile",
        json={
            "full_name": "Updated User",
        },
    )

    password_response = client.post(
        "/api/v1/profile/password",
        json={
            "current_password": "CurrentPassword123!",
            "new_password": "NewPassword456!",
            "confirm_password": "NewPassword456!",
        },
    )

    assert users_response.status_code == 401
    assert roles_response.status_code == 401
    assert permissions_response.status_code == 401
    assert profile_response.status_code == 401
    assert password_response.status_code == 401


def test_standard_user_cannot_access_administration(
    client: TestClient,
    administration_environment: AdministrationEnvironment,
) -> None:
    environment = administration_environment

    headers = login_headers(
        client,
        environment.standard_email,
        environment.standard_password,
    )

    users_response = client.get(
        "/api/v1/users",
        headers=headers,
    )

    roles_response = client.get(
        "/api/v1/roles",
        headers=headers,
    )

    permissions_response = client.get(
        "/api/v1/permissions",
        headers=headers,
    )

    create_response = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": (
                f"forbidden-{environment.token}"
                "@example.com"
            ),
            "full_name": "Forbidden User",
            "password": "ForbiddenUser123!",
            "role_ids": [],
        },
    )

    assert users_response.status_code == 403
    assert roles_response.status_code == 403
    assert permissions_response.status_code == 403
    assert create_response.status_code == 403


def test_superuser_can_list_roles_and_permissions(
    client: TestClient,
    administration_environment: AdministrationEnvironment,
) -> None:
    environment = administration_environment

    headers = login_headers(
        client,
        environment.admin_email,
        environment.admin_password,
    )

    roles_response = client.get(
        "/api/v1/roles",
        headers=headers,
        params={
            "is_active": True,
        },
    )

    permissions_response = client.get(
        "/api/v1/permissions",
        headers=headers,
        params={
            "is_active": True,
        },
    )

    assert roles_response.status_code == 200, (
        roles_response.text
    )

    assert permissions_response.status_code == 200, (
        permissions_response.text
    )

    roles_data = roles_response.json()
    permissions_data = permissions_response.json()

    role_ids = {
        item["id"]
        for item in roles_data["items"]
    }

    permission_ids = {
        item["id"]
        for item in permissions_data["items"]
    }

    assert environment.role_id in role_ids
    assert environment.permission_id in permission_ids
    assert roles_data["total"] == len(
        roles_data["items"]
    )
    assert permissions_data["total"] == len(
        permissions_data["items"]
    )


def test_superuser_can_manage_user_lifecycle(
    client: TestClient,
    administration_environment: AdministrationEnvironment,
) -> None:
    environment = administration_environment

    headers = login_headers(
        client,
        environment.admin_email,
        environment.admin_password,
    )

    managed_email = (
        f"managed-{environment.token}@example.com"
    )

    create_response = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": managed_email.upper(),
            "full_name": "Managed Investigation User",
            "password": "ManagedUser123!",
            "role_ids": [
                environment.role_id,
            ],
        },
    )

    assert create_response.status_code == 201, (
        create_response.text
    )

    created_user = create_response.json()
    user_id = created_user["id"]

    assert created_user["email"] == managed_email
    assert created_user["full_name"] == (
        "Managed Investigation User"
    )
    assert created_user["is_active"] is True
    assert created_user["is_superuser"] is False
    assert len(created_user["roles"]) == 1
    assert created_user["roles"][0]["id"] == (
        environment.role_id
    )

    list_response = client.get(
        "/api/v1/users",
        headers=headers,
        params={
            "search": (
                f"managed-{environment.token}"
            ),
            "page": 1,
            "page_size": 10,
        },
    )

    assert list_response.status_code == 200, (
        list_response.text
    )

    listed_users = list_response.json()

    assert listed_users["total"] == 1
    assert listed_users["page"] == 1
    assert listed_users["page_size"] == 10
    assert listed_users["pages"] == 1
    assert listed_users["items"][0]["id"] == user_id

    read_response = client.get(
        f"/api/v1/users/{user_id}",
        headers=headers,
    )

    assert read_response.status_code == 200, (
        read_response.text
    )

    assert read_response.json()["email"] == managed_email

    update_response = client.patch(
        f"/api/v1/users/{user_id}",
        headers=headers,
        json={
            "full_name": "Updated Managed User",
            "role_ids": [],
        },
    )

    assert update_response.status_code == 200, (
        update_response.text
    )

    updated_user = update_response.json()

    assert updated_user["full_name"] == (
        "Updated Managed User"
    )
    assert updated_user["roles"] == []

    db = SessionLocal()

    try:
        stored_user = db.get(
            User,
            UUID(user_id),
        )

        assert stored_user is not None

        stored_user.failed_login_attempts = 5
        stored_user.locked_until = (
            datetime.now(timezone.utc)
            + timedelta(minutes=30)
        )

        db.commit()

    finally:
        db.close()

    unlock_response = client.post(
        f"/api/v1/users/{user_id}/unlock",
        headers=headers,
    )

    assert unlock_response.status_code == 200, (
        unlock_response.text
    )

    unlock_data = unlock_response.json()

    assert unlock_data["user"]["id"] == user_id
    assert unlock_data["user"]["failed_login_attempts"] == 0
    assert unlock_data["user"]["locked_until"] is None
    assert unlock_data["unlocked_at"]
    assert unlock_data["message"] == (
        "The user account was unlocked successfully."
    )


def test_user_administration_validation_errors(
    client: TestClient,
    administration_environment: AdministrationEnvironment,
) -> None:
    environment = administration_environment

    headers = login_headers(
        client,
        environment.admin_email,
        environment.admin_password,
    )

    duplicate_response = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": environment.standard_email,
            "full_name": "Duplicate User",
            "password": "DuplicateUser123!",
            "role_ids": [],
        },
    )

    missing_role_response = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": (
                f"missing-role-{environment.token}"
                "@example.com"
            ),
            "full_name": "Missing Role User",
            "password": "MissingRole123!",
            "role_ids": [
                str(uuid4()),
            ],
        },
    )

    missing_user_response = client.get(
        f"/api/v1/users/{uuid4()}",
        headers=headers,
    )

    assert duplicate_response.status_code == 409
    assert duplicate_response.json()["detail"] == (
        "A user with this email address already exists."
    )

    assert missing_role_response.status_code == 400
    assert "Roles not found:" in (
        missing_role_response.json()["detail"]
    )

    assert missing_user_response.status_code == 404
    assert missing_user_response.json()["detail"] == (
        "The requested user does not exist."
    )


def test_user_can_update_profile_and_change_password(
    client: TestClient,
    administration_environment: AdministrationEnvironment,
) -> None:
    environment = administration_environment

    headers = login_headers(
        client,
        environment.standard_email,
        environment.standard_password,
    )

    profile_response = client.patch(
        "/api/v1/profile",
        headers=headers,
        json={
            "full_name": "Updated Standard User",
        },
    )

    assert profile_response.status_code == 200, (
        profile_response.text
    )

    assert profile_response.json()["full_name"] == (
        "Updated Standard User"
    )

    incorrect_password_response = client.post(
        "/api/v1/profile/password",
        headers=headers,
        json={
            "current_password": "IncorrectPassword123!",
            "new_password": "UpdatedPassword456!",
            "confirm_password": "UpdatedPassword456!",
        },
    )

    assert incorrect_password_response.status_code == 400
    assert incorrect_password_response.json()["detail"] == (
        "The current password is incorrect."
    )

    reused_password_response = client.post(
        "/api/v1/profile/password",
        headers=headers,
        json={
            "current_password": environment.standard_password,
            "new_password": environment.standard_password,
            "confirm_password": environment.standard_password,
        },
    )

    assert reused_password_response.status_code == 400
    assert reused_password_response.json()["detail"] == (
        "The new password must be different "
        "from the current password."
    )

    mismatch_response = client.post(
        "/api/v1/profile/password",
        headers=headers,
        json={
            "current_password": environment.standard_password,
            "new_password": "UpdatedPassword456!",
            "confirm_password": "DifferentPassword789!",
        },
    )

    assert mismatch_response.status_code == 422

    new_password = "UpdatedPassword456!"

    change_response = client.post(
        "/api/v1/profile/password",
        headers=headers,
        json={
            "current_password": environment.standard_password,
            "new_password": new_password,
            "confirm_password": new_password,
        },
    )

    assert change_response.status_code == 200, (
        change_response.text
    )

    assert change_response.json()["message"] == (
        "Password changed successfully."
    )

    old_login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": environment.standard_email,
            "password": environment.standard_password,
        },
    )

    new_login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": environment.standard_email,
            "password": new_password,
        },
    )

    assert old_login_response.status_code == 401
    assert new_login_response.status_code == 200