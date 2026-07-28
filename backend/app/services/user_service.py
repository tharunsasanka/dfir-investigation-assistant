import uuid
from datetime import datetime, timezone

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.security import (
    hash_password,
    verify_password,
)
from app.models.role import Role
from app.models.user import User
from app.schemas.administration import (
    PasswordChangeRequest,
    ProfileUpdateRequest,
)
from app.schemas.user import (
    UserCreate,
    UserUpdate,
)
from app.services.session_revocation_service import (
    revoke_user_sessions,
)


class UserServiceError(Exception):
    pass


class EmailAlreadyExistsError(UserServiceError):
    pass


class RoleNotFoundError(UserServiceError):
    def __init__(
        self,
        missing_role_ids: set[uuid.UUID],
    ) -> None:
        self.missing_role_ids = missing_role_ids

        super().__init__(
            "Roles not found: "
            + ", ".join(
                sorted(
                    str(role_id)
                    for role_id in missing_role_ids
                )
            )
        )


class UserNotFoundError(UserServiceError):
    pass


class InvalidCurrentPasswordError(UserServiceError):
    pass


class PasswordReuseError(UserServiceError):
    pass


def get_user_with_roles(
    db: Session,
    user_id: uuid.UUID,
) -> User | None:
    statement = (
        select(User)
        .options(
            selectinload(
                User.roles
            ).selectinload(
                Role.permissions
            )
        )
        .where(
            User.id == user_id
        )
    )

    return db.scalar(statement)


def list_users(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 20,
    search: str | None = None,
    is_active: bool | None = None,
) -> tuple[list[User], int]:
    filters = []

    normalized_search = (
        search.strip()
        if search
        else ""
    )

    if normalized_search:
        search_pattern = (
            f"%{normalized_search}%"
        )

        filters.append(
            or_(
                User.email.ilike(
                    search_pattern
                ),
                User.full_name.ilike(
                    search_pattern
                ),
            )
        )

    if is_active is not None:
        filters.append(
            User.is_active
            == is_active
        )

    count_statement = (
        select(
            func.count(
                User.id
            )
        )
        .select_from(User)
    )

    if filters:
        count_statement = (
            count_statement.where(
                *filters
            )
        )

    total = int(
        db.scalar(
            count_statement
        )
        or 0
    )

    statement = (
        select(User)
        .options(
            selectinload(
                User.roles
            ).selectinload(
                Role.permissions
            )
        )
        .order_by(
            User.created_at.desc(),
            User.email.asc(),
        )
        .offset(
            (page - 1)
            * page_size
        )
        .limit(page_size)
    )

    if filters:
        statement = (
            statement.where(
                *filters
            )
        )

    users = list(
        db.scalars(
            statement
        ).all()
    )

    return users, total


def _load_roles(
    db: Session,
    role_ids: list[uuid.UUID],
) -> list[Role]:
    unique_role_ids = list(
        dict.fromkeys(
            role_ids
        )
    )

    if not unique_role_ids:
        return []

    roles = list(
        db.scalars(
            select(Role).where(
                Role.id.in_(
                    unique_role_ids
                )
            )
        ).all()
    )

    roles_by_id = {
        role.id: role
        for role in roles
    }

    missing_role_ids = (
        set(unique_role_ids)
        - set(roles_by_id)
    )

    if missing_role_ids:
        raise RoleNotFoundError(
            missing_role_ids
        )

    return [
        roles_by_id[role_id]
        for role_id
        in unique_role_ids
    ]


def _ensure_email_available(
    db: Session,
    email: str,
    *,
    excluded_user_id: uuid.UUID | None = None,
) -> str:
    normalized_email = (
        email.strip().lower()
    )

    statement = (
        select(User)
        .where(
            User.email
            == normalized_email
        )
    )

    if excluded_user_id is not None:
        statement = (
            statement.where(
                User.id
                != excluded_user_id
            )
        )

    existing_user = db.scalar(
        statement
    )

    if existing_user is not None:
        raise EmailAlreadyExistsError(
            "A user with this email address already exists."
        )

    return normalized_email


def create_user(
    db: Session,
    user_data: UserCreate,
    *,
    is_superuser: bool = False,
) -> User:
    normalized_email = (
        _ensure_email_available(
            db,
            str(
                user_data.email
            ),
        )
    )

    roles = _load_roles(
        db,
        user_data.role_ids,
    )

    user = User(
        email=normalized_email,
        full_name=(
            user_data.full_name
            .strip()
        ),
        hashed_password=(
            hash_password(
                user_data.password
            )
        ),
        is_superuser=(
            is_superuser
        ),
        roles=roles,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    loaded_user = (
        get_user_with_roles(
            db,
            user.id,
        )
    )

    return (
        loaded_user
        or user
    )


def update_user(
    db: Session,
    user_id: uuid.UUID,
    user_data: UserUpdate,
) -> User:
    user = get_user_with_roles(
        db,
        user_id,
    )

    if user is None:
        raise UserNotFoundError(
            "The requested user does not exist."
        )

    updates = (
        user_data.model_dump(
            exclude_unset=True
        )
    )

    was_active = user.is_active
    password_changed = False

    email = updates.get(
        "email"
    )

    if email is not None:
        user.email = (
            _ensure_email_available(
                db,
                str(email),
                excluded_user_id=(
                    user.id
                ),
            )
        )

    full_name = updates.get(
        "full_name"
    )

    if full_name is not None:
        user.full_name = (
            full_name.strip()
        )

    password = updates.get(
        "password"
    )

    if password is not None:
        user.hashed_password = (
            hash_password(
                password
            )
        )

        password_changed = True

    is_active = updates.get(
        "is_active"
    )

    if is_active is not None:
        user.is_active = (
            is_active
        )

    account_deactivated = (
        was_active
        and is_active is False
    )

    is_superuser = updates.get(
        "is_superuser"
    )

    if is_superuser is not None:
        user.is_superuser = (
            is_superuser
        )

    role_ids = updates.get(
        "role_ids"
    )

    if role_ids is not None:
        user.roles = _load_roles(
            db,
            role_ids,
        )

    user.updated_at = (
        datetime.now(
            timezone.utc
        )
    )

    if account_deactivated:
        revoke_user_sessions(
            db,
            user.id,
            "account_deactivated",
        )

    elif password_changed:
        revoke_user_sessions(
            db,
            user.id,
            "administrator_password_reset",
        )

    db.commit()
    db.refresh(user)

    loaded_user = (
        get_user_with_roles(
            db,
            user.id,
        )
    )

    if loaded_user is None:
        raise UserNotFoundError(
            "The updated user could not be loaded."
        )

    return loaded_user


def unlock_user(
    db: Session,
    user_id: uuid.UUID,
) -> User:
    user = get_user_with_roles(
        db,
        user_id,
    )

    if user is None:
        raise UserNotFoundError(
            "The requested user does not exist."
        )

    user.failed_login_attempts = 0
    user.locked_until = None
    user.updated_at = (
        datetime.now(
            timezone.utc
        )
    )

    db.commit()
    db.refresh(user)

    loaded_user = (
        get_user_with_roles(
            db,
            user.id,
        )
    )

    if loaded_user is None:
        raise UserNotFoundError(
            "The unlocked user could not be loaded."
        )

    return loaded_user

def update_profile(
    db: Session,
    user_id: uuid.UUID,
    profile_data: ProfileUpdateRequest,
) -> User:
    user = get_user_with_roles(
        db,
        user_id,
    )

    if user is None:
        raise UserNotFoundError(
            "The authenticated user does not exist."
        )

    user.full_name = (
        profile_data.full_name
        .strip()
    )

    user.updated_at = (
        datetime.now(
            timezone.utc
        )
    )

    db.commit()
    db.refresh(user)

    loaded_user = (
        get_user_with_roles(
            db,
            user.id,
        )
    )

    if loaded_user is None:
        raise UserNotFoundError(
            "The updated profile could not be loaded."
        )

    return loaded_user


def change_password(
    db: Session,
    user_id: uuid.UUID,
    password_data: PasswordChangeRequest,
) -> User:
    user = get_user_with_roles(
        db,
        user_id,
    )

    if user is None:
        raise UserNotFoundError(
            "The authenticated user does not exist."
        )

    if not verify_password(
        password_data.current_password,
        user.hashed_password,
    ):
        raise InvalidCurrentPasswordError(
            "The current password is incorrect."
        )

    if verify_password(
        password_data.new_password,
        user.hashed_password,
    ):
        raise PasswordReuseError(
            "The new password must be different from the current password."
        )

    user.hashed_password = (
        hash_password(
            password_data.new_password
        )
    )

    user.failed_login_attempts = 0
    user.locked_until = None
    user.updated_at = (
        datetime.now(
            timezone.utc
        )
    )

    revoke_user_sessions(
        db,
        user.id,
        "password_changed",
    )

    db.commit()
    db.refresh(user)

    loaded_user = (
        get_user_with_roles(
            db,
            user.id,
        )
    )

    if loaded_user is None:
        raise UserNotFoundError(
            "The user could not be loaded after changing the password."
        )

    return loaded_user
