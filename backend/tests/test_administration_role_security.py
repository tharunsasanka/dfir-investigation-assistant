from collections.abc import Generator
from dataclasses import dataclass
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.schemas.user import UserCreate
from app.services.user_service import (
    create_user,
)


@dataclass(frozen=True)
class RoleSecurityEnvironment:
    admin_email: str
    admin_password: str
    manager_email: str
    manager_password: str
    manager_role_id: str
    inactive_role_id: str
    target_user_id: str


@pytest.fixture
def role_security_environment() -> Generator[
    RoleSecurityEnvironment,
    None,
    None,
]:
    token = uuid4().hex

    admin_email = (
        f"role-security-admin-{token}"
        "@example.com"
    )

    manager_email = (
        f"role-security-manager-{token}"
        "@example.com"
    )

    target_email = (
        f"role-security-target-{token}"
        "@example.com"
    )

    admin_password = (
        "RoleSecurityAdmin123!"
    )

    manager_password = (
        "RoleSecurityManager123!"
    )

    target_password = (
        "RoleSecurityTarget123!"
    )

    db = SessionLocal()

    users_manage_permission = (
        db.scalar(
            select(
                Permission
            ).where(
                Permission.name
                == "users.manage"
            )
        )
    )

    assert (
        users_manage_permission
        is not None
    )

    manager_role = Role(
        name=(
            f"role_security_manager_"
            f"{token}"
        ),
        description=(
            "Temporary users manager "
            "without role-management access."
        ),
        is_active=True,
        permissions=[
            users_manage_permission
        ],
    )

    inactive_role = Role(
        name=(
            f"role_security_inactive_"
            f"{token}"
        ),
        description=(
            "Temporary inactive role."
        ),
        is_active=False,
    )

    try:
        db.add_all(
            [
                manager_role,
                inactive_role,
            ]
        )

        db.commit()
        db.refresh(manager_role)
        db.refresh(inactive_role)

        admin = create_user(
            db=db,
            user_data=UserCreate(
                email=admin_email,
                full_name=(
                    "Role Security Admin"
                ),
                password=admin_password,
            ),
            is_superuser=True,
        )

        manager = create_user(
            db=db,
            user_data=UserCreate(
                email=manager_email,
                full_name=(
                    "Role Security Manager"
                ),
                password=manager_password,
                role_ids=[
                    manager_role.id
                ],
            ),
        )

        target = create_user(
            db=db,
            user_data=UserCreate(
                email=target_email,
                full_name=(
                    "Role Security Target"
                ),
                password=target_password,
            ),
        )

        yield RoleSecurityEnvironment(
            admin_email=admin.email,
            admin_password=admin_password,
            manager_email=manager.email,
            manager_password=(
                manager_password
            ),
            manager_role_id=str(
                manager_role.id
            ),
            inactive_role_id=str(
                inactive_role.id
            ),
            target_user_id=str(
                target.id
            ),
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
                            manager_email,
                            target_email,
                        ]
                    )
                )
            ).all()
        )

        for user in users:
            db.delete(user)

        db.flush()

        for role_id in (
            manager_role.id,
            inactive_role.id,
        ):
            stored_role = db.get(
                Role,
                role_id,
            )

            if stored_role is not None:
                db.delete(
                    stored_role
                )

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

    assert response.status_code == 200, (
        response.text
    )

    return {
        "Authorization": (
            "Bearer "
            f"{response.json()['access_token']}"
        )
    }


def test_users_manager_can_update_non_role_fields(
    client: TestClient,
    role_security_environment:
        RoleSecurityEnvironment,
) -> None:
    environment = (
        role_security_environment
    )

    headers = login_headers(
        client,
        environment.manager_email,
        environment.manager_password,
    )

    response = client.patch(
        (
            "/api/v1/users/"
            f"{environment.target_user_id}"
        ),
        headers=headers,
        json={
            "full_name":
                "Updated Security Target",
        },
    )

    assert response.status_code == 200, (
        response.text
    )

    assert response.json()[
        "full_name"
    ] == "Updated Security Target"


def test_users_manager_cannot_modify_roles(
    client: TestClient,
    role_security_environment:
        RoleSecurityEnvironment,
) -> None:
    environment = (
        role_security_environment
    )

    headers = login_headers(
        client,
        environment.manager_email,
        environment.manager_password,
    )

    response = client.patch(
        (
            "/api/v1/users/"
            f"{environment.target_user_id}"
        ),
        headers=headers,
        json={
            "role_ids": []
        },
    )

    assert response.status_code == 403

    assert response.json()["detail"] == (
        "Role assignment requires "
        "the roles.manage permission."
    )


def test_users_manager_cannot_create_privileged_user(
    client: TestClient,
    role_security_environment:
        RoleSecurityEnvironment,
) -> None:
    environment = (
        role_security_environment
    )

    headers = login_headers(
        client,
        environment.manager_email,
        environment.manager_password,
    )

    response = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": (
                f"unauthorised-role-"
                f"{uuid4().hex}"
                "@example.com"
            ),
            "full_name":
                "Unauthorised Role User",
            "password":
                "UnauthorisedRole123!",
            "role_ids": [
                environment.manager_role_id
            ],
        },
    )

    assert response.status_code == 403


def test_inactive_role_cannot_be_assigned(
    client: TestClient,
    role_security_environment:
        RoleSecurityEnvironment,
) -> None:
    environment = (
        role_security_environment
    )

    headers = login_headers(
        client,
        environment.admin_email,
        environment.admin_password,
    )

    create_response = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": (
                f"inactive-role-{uuid4().hex}"
                "@example.com"
            ),
            "full_name":
                "Inactive Role User",
            "password":
                "InactiveRoleUser123!",
            "role_ids": [
                environment.inactive_role_id
            ],
        },
    )

    update_response = client.patch(
        (
            "/api/v1/users/"
            f"{environment.target_user_id}"
        ),
        headers=headers,
        json={
            "role_ids": [
                environment.inactive_role_id
            ]
        },
    )

    assert create_response.status_code == 400
    assert update_response.status_code == 400

    assert (
        "Inactive roles cannot be assigned:"
        in create_response.json()["detail"]
    )

    assert (
        "Inactive roles cannot be assigned:"
        in update_response.json()["detail"]
    )
