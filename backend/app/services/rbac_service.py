from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.rbac_defaults import (
    PERMISSIONS,
    ROLE_DESCRIPTIONS,
    ROLE_PERMISSIONS,
)
from app.models.permission import Permission
from app.models.role import Role


def seed_default_rbac(db: Session) -> dict[str, int]:
    """Create or update the platform's default permissions and roles."""

    permissions_by_name: dict[str, Permission] = {}

    try:
        for permission_name, description in PERMISSIONS:
            permission = db.scalar(
                select(Permission).where(
                    Permission.name == permission_name
                )
            )

            if permission is None:
                permission = Permission(
                    name=permission_name,
                    description=description,
                    is_active=True,
                )
                db.add(permission)
            else:
                permission.description = description
                permission.is_active = True

            permissions_by_name[permission_name] = permission

        db.flush()

        for role_name, permission_names in ROLE_PERMISSIONS.items():
            role = db.scalar(
                select(Role).where(Role.name == role_name)
            )

            if role is None:
                role = Role(
                    name=role_name,
                    description=ROLE_DESCRIPTIONS[role_name],
                    is_active=True,
                )
                db.add(role)
            else:
                role.description = ROLE_DESCRIPTIONS[role_name]
                role.is_active = True

            role.permissions = [
                permissions_by_name[permission_name]
                for permission_name in permission_names
            ]

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "permissions": len(PERMISSIONS),
        "roles": len(ROLE_PERMISSIONS),
    }