from datetime import (
    datetime,
    timedelta,
    timezone,
)

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import (
    hash_password,
    verify_password,
)
from app.models.user import User


settings = get_settings()

DUMMY_PASSWORD_HASH = hash_password(
    "TimingProtectionPassword123!"
)


class AuthenticationError(Exception):
    pass


class InvalidCredentialsError(
    AuthenticationError
):
    pass


class InactiveAccountError(
    AuthenticationError
):
    pass


class AccountLockedError(
    AuthenticationError
):
    def __init__(
        self,
        locked_until: datetime,
    ) -> None:
        self.locked_until = locked_until

        super().__init__(
            "The account is temporarily "
            "locked."
        )


def get_user_by_email(
    db: Session,
    email: str,
) -> User | None:
    normalized_email = (
        email.strip().lower()
    )

    statement = select(
        User
    ).where(
        User.email
        == normalized_email
    )

    return db.scalar(
        statement
    )


def record_failed_login(
    db: Session,
    user: User,
) -> None:
    user.failed_login_attempts += 1

    if (
        user.failed_login_attempts
        >= settings
        .max_failed_login_attempts
    ):
        user.locked_until = (
            datetime.now(
                timezone.utc
            )
            + timedelta(
                minutes=(
                    settings
                    .login_lockout_minutes
                )
            )
        )

    db.add(user)
    db.commit()
    db.refresh(user)


def record_successful_login(
    db: Session,
    user: User,
) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(
        timezone.utc
    )

    db.add(user)
    db.commit()
    db.refresh(user)


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> User:
    user = get_user_by_email(
        db,
        email,
    )

    if user is None:
        verify_password(
            password,
            DUMMY_PASSWORD_HASH,
        )

        raise InvalidCredentialsError(
            "The email address or "
            "password is incorrect."
        )

    if not user.is_active:
        raise InactiveAccountError(
            "This user account is "
            "inactive."
        )

    now = datetime.now(
        timezone.utc
    )

    if user.locked_until is not None:
        locked_until = (
            user.locked_until
        )

        if locked_until.tzinfo is None:
            locked_until = (
                locked_until.replace(
                    tzinfo=timezone.utc
                )
            )

        if locked_until > now:
            raise AccountLockedError(
                locked_until
            )

        user.locked_until = None
        user.failed_login_attempts = 0

        db.add(user)
        db.commit()
        db.refresh(user)

    if not verify_password(
        password,
        user.hashed_password,
    ):
        record_failed_login(
            db,
            user,
        )

        if (
            user.locked_until
            is not None
        ):
            raise AccountLockedError(
                user.locked_until
            )

        raise InvalidCredentialsError(
            "The email address or "
            "password is incorrect."
        )

    record_successful_login(
        db,
        user,
    )

    return user