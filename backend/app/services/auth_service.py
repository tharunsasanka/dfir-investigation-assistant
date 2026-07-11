from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import verify_password
from app.models.user import User


settings = get_settings()


class AuthenticationError(Exception):
    """Base exception for authentication failures."""


class InvalidCredentialsError(AuthenticationError):
    """Raised when an email address or password is incorrect."""


class InactiveAccountError(AuthenticationError):
    """Raised when the user account has been disabled."""


class AccountLockedError(AuthenticationError):
    """Raised when too many failed login attempts lock an account."""

    def __init__(self, locked_until: datetime) -> None:
        self.locked_until = locked_until
        super().__init__(
            f"Account is locked until {locked_until.isoformat()}."
        )


def get_user_by_email(db: Session, email: str) -> User | None:
    """Find a user using a normalized email address."""

    normalized_email = email.strip().lower()

    statement = select(User).where(User.email == normalized_email)
    return db.scalar(statement)


def _record_failed_login(db: Session, user: User) -> None:
    """Increase the failed-login count and lock the account if necessary."""

    user.failed_login_attempts += 1

    if user.failed_login_attempts >= settings.max_failed_login_attempts:
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=settings.login_lockout_minutes
        )

    db.add(user)
    db.commit()
    db.refresh(user)


def _record_successful_login(db: Session, user: User) -> None:
    """Clear login failures and record the latest successful login."""

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)

    db.add(user)
    db.commit()
    db.refresh(user)


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> User:
    """Validate user credentials and update account-login information."""

    user = get_user_by_email(db, email)

    if user is None:
        raise InvalidCredentialsError(
            "The email address or password is incorrect."
        )

    if not user.is_active:
        raise InactiveAccountError(
            "This user account is inactive."
        )

    now = datetime.now(timezone.utc)

    if user.locked_until is not None:
        locked_until = user.locked_until

        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        if locked_until > now:
            raise AccountLockedError(locked_until)

        user.locked_until = None
        user.failed_login_attempts = 0
        db.add(user)
        db.commit()
        db.refresh(user)

    if not verify_password(password, user.hashed_password):
        _record_failed_login(db, user)

        if user.locked_until is not None:
            raise AccountLockedError(user.locked_until)

        raise InvalidCredentialsError(
            "The email address or password is incorrect."
        )

    _record_successful_login(db, user)
    return user