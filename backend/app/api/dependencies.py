import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.security import decode_token
from app.db.session import get_db
from app.models.role import Role
from app.models.user import User


bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Return the active user identified by a valid access token."""

    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise credentials_error

    try:
        payload = decode_token(
            credentials.credentials,
            expected_type="access",
        )

        subject = payload.get("sub")

        if not subject:
            raise credentials_error

        user_id = uuid.UUID(subject)

    except (InvalidTokenError, TypeError, ValueError) as error:
        raise credentials_error from error

    statement = (
        select(User)
        .options(
            selectinload(User.roles).selectinload(Role.permissions)
        )
        .where(User.id == user_id)
    )

    user = db.scalar(statement)

    if user is None:
        raise credentials_error

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This user account is inactive.",
        )

    return user
def get_permission_names(user: User) -> set[str]:
    """Return all active permission names assigned to a user."""

    permission_names: set[str] = set()

    for role in user.roles:
        if not role.is_active:
            continue

        for permission in role.permissions:
            if permission.is_active:
                permission_names.add(permission.name)

    return permission_names


def require_permission(permission_name: str):
    """Create a dependency that requires one specific permission."""

    def permission_dependency(
        current_user: Annotated[
            User,
            Depends(get_current_user),
        ],
    ) -> User:
        if current_user.is_superuser:
            return current_user

        user_permissions = get_permission_names(current_user)

        if permission_name not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "You do not have permission to perform "
                    "this action."
                ),
            )

        return current_user

    return permission_dependency