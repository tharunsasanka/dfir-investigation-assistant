import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.role import Role
from app.models.user import User
from app.schemas.user import UserCreate


class UserServiceError(Exception):
    """Base exception for user-management failures."""


class EmailAlreadyExistsError(UserServiceError):
    """Raised when another user already uses the email address."""


class RoleNotFoundError(UserServiceError):
    """Raised when one or more requested roles do not exist."""

    def __init__(self, missing_role_ids: set[uuid.UUID]) -> None:
        self.missing_role_ids = missing_role_ids
        super().__init__(
            f"Roles not found: {', '.join(map(str, missing_role_ids))}"
        )


def create_user(
    db: Session,
    user_data: UserCreate,
    *,
    is_superuser: bool = False,
) -> User:
    """Create a user with a securely hashed password and optional roles."""

    normalized_email = str(user_data.email).strip().lower()

    existing_user = db.scalar(
        select(User).where(User.email == normalized_email)
    )

    if existing_user is not None:
        raise EmailAlreadyExistsError(
            "A user with this email address already exists."
        )

    roles: list[Role] = []

    if user_data.role_ids:
        roles = list(
            db.scalars(
                select(Role).where(Role.id.in_(user_data.role_ids))
            ).all()
        )

        requested_ids = set(user_data.role_ids)
        found_ids = {role.id for role in roles}
        missing_ids = requested_ids - found_ids

        if missing_ids:
            raise RoleNotFoundError(missing_ids)

    user = User(
        email=normalized_email,
        full_name=user_data.full_name.strip(),
        hashed_password=hash_password(user_data.password),
        is_superuser=is_superuser,
        roles=roles,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user