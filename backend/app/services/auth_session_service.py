import hashlib
import hmac
import uuid
from dataclasses import dataclass
from datetime import (
    datetime,
    timedelta,
    timezone,
)

from fastapi import Request
from jwt import InvalidTokenError
from sqlalchemy import (
    select,
    update,
)
from sqlalchemy.orm import (
    Session,
    selectinload,
)

from app.core.config import get_settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_token,
)
from app.models.authentication import (
    AuthRefreshToken,
    AuthSession,
)
from app.models.role import Role
from app.models.user import User


settings = get_settings()


class InvalidRefreshTokenError(
    Exception
):
    pass


class RefreshTokenReuseError(
    InvalidRefreshTokenError
):
    pass


class InvalidAccessSessionError(
    Exception
):
    pass


@dataclass(frozen=True)
class IssuedAuthTokens:
    access_token: str
    refresh_token: str


def ensure_utc(
    value: datetime,
) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


def request_ip_hash(
    request: Request,
) -> str:
    client_host = (
        request.client.host
        if request.client
        else "unknown"
    )

    return hashlib.sha256(
        client_host.encode(
            "utf-8"
        )
    ).hexdigest()


def request_user_agent(
    request: Request,
) -> str:
    return (
        request.headers.get(
            "user-agent",
            "",
        )
        .strip()[:500]
    )


def parse_uuid_claim(
    payload: dict,
    claim_name: str,
) -> uuid.UUID:
    value = payload.get(
        claim_name
    )

    if not value:
        raise InvalidRefreshTokenError(
            "The token is missing a "
            "required claim."
        )

    try:
        return uuid.UUID(
            str(value)
        )
    except ValueError as error:
        raise InvalidRefreshTokenError(
            "The token contains an "
            "invalid claim."
        ) from error


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

    return db.scalar(
        statement
    )


def revoke_session(
    db: Session,
    session: AuthSession,
    reason: str,
    timestamp: datetime | None = None,
) -> None:
    revoked_at = (
        timestamp
        or datetime.now(
            timezone.utc
        )
    )

    if session.revoked_at is None:
        session.revoked_at = revoked_at
        session.revoke_reason = (
            reason[:100]
        )

        db.add(session)

    db.execute(
        update(
            AuthRefreshToken
        )
        .where(
            AuthRefreshToken.session_id
            == session.id,
            AuthRefreshToken.revoked_at
            .is_(None),
        )
        .values(
            revoked_at=revoked_at
        )
    )


def create_auth_session(
    db: Session,
    user: User,
    request: Request,
) -> IssuedAuthTokens:
    now = datetime.now(
        timezone.utc
    )

    expires_at = (
        now
        + timedelta(
            days=(
                settings
                .refresh_token_expire_days
            )
        )
    )

    session = AuthSession(
        user_id=user.id,
        created_at=now,
        expires_at=expires_at,
        revoked_at=None,
        revoke_reason="",
        created_ip_hash=(
            request_ip_hash(
                request
            )
        ),
        user_agent=(
            request_user_agent(
                request
            )
        ),
    )

    try:
        db.add(session)
        db.flush()

        created_refresh_token = (
            create_refresh_token(
                subject=str(
                    user.id
                ),
                session_id=(
                    session.id
                ),
                expires_at=(
                    expires_at
                ),
            )
        )

        refresh_record = (
            AuthRefreshToken(
                session_id=(
                    session.id
                ),
                jti=(
                    created_refresh_token
                    .jti
                ),
                token_hash=hash_token(
                    created_refresh_token
                    .token
                ),
                issued_at=(
                    created_refresh_token
                    .issued_at
                ),
                expires_at=(
                    created_refresh_token
                    .expires_at
                ),
                used_at=None,
                revoked_at=None,
                replaced_by_jti=None,
            )
        )

        db.add(
            refresh_record
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return IssuedAuthTokens(
        access_token=(
            create_access_token(
                subject=str(
                    user.id
                ),
                session_id=(
                    session.id
                ),
            )
        ),
        refresh_token=(
            created_refresh_token
            .token
        ),
    )


def rotate_refresh_token(
    db: Session,
    raw_refresh_token: str,
) -> IssuedAuthTokens:
    try:
        payload = decode_token(
            raw_refresh_token,
            expected_type="refresh",
        )

        user_id = parse_uuid_claim(
            payload,
            "sub",
        )

        session_id = parse_uuid_claim(
            payload,
            "sid",
        )

        token_jti = parse_uuid_claim(
            payload,
            "jti",
        )

    except (
        InvalidTokenError,
        InvalidRefreshTokenError,
        TypeError,
    ) as error:
        raise InvalidRefreshTokenError(
            "The refresh token is "
            "invalid or expired."
        ) from error

    now = datetime.now(
        timezone.utc
    )

    session = db.scalar(
        select(
            AuthSession
        )
        .where(
            AuthSession.id
            == session_id
        )
        .with_for_update()
    )

    if (
        session is None
        or session.user_id
        != user_id
    ):
        raise InvalidRefreshTokenError(
            "The refresh token is "
            "invalid or expired."
        )

    if (
        session.revoked_at
        is not None
        or ensure_utc(
            session.expires_at
        ) <= now
    ):
        raise InvalidRefreshTokenError(
            "The authentication "
            "session is no longer active."
        )

    refresh_record = db.scalar(
        select(
            AuthRefreshToken
        )
        .where(
            AuthRefreshToken.jti
            == token_jti
        )
        .with_for_update()
    )

    if (
        refresh_record is None
        or refresh_record.session_id
        != session.id
    ):
        revoke_session(
            db,
            session,
            "unknown_refresh_token",
            now,
        )

        db.commit()

        raise InvalidRefreshTokenError(
            "The refresh token is "
            "invalid or expired."
        )

    supplied_hash = hash_token(
        raw_refresh_token
    )

    if not hmac.compare_digest(
        refresh_record.token_hash,
        supplied_hash,
    ):
        revoke_session(
            db,
            session,
            "refresh_token_hash_mismatch",
            now,
        )

        db.commit()

        raise InvalidRefreshTokenError(
            "The refresh token is "
            "invalid or expired."
        )

    if (
        refresh_record.used_at
        is not None
        or refresh_record.revoked_at
        is not None
    ):
        revoke_session(
            db,
            session,
            "refresh_token_reuse_detected",
            now,
        )

        db.commit()

        raise RefreshTokenReuseError(
            "Refresh-token reuse was "
            "detected."
        )

    if (
        ensure_utc(
            refresh_record.expires_at
        )
        <= now
    ):
        refresh_record.revoked_at = now

        revoke_session(
            db,
            session,
            "refresh_token_expired",
            now,
        )

        db.add(
            refresh_record
        )

        db.commit()

        raise InvalidRefreshTokenError(
            "The refresh token is "
            "invalid or expired."
        )

    user = get_user_with_roles(
        db,
        user_id,
    )

    if (
        user is None
        or not user.is_active
    ):
        revoke_session(
            db,
            session,
            "user_inactive",
            now,
        )

        db.commit()

        raise InvalidRefreshTokenError(
            "The authentication "
            "session is no longer active."
        )

    created_refresh_token = (
        create_refresh_token(
            subject=str(
                user.id
            ),
            session_id=(
                session.id
            ),
            expires_at=(
                session.expires_at
            ),
        )
    )

    refresh_record.used_at = now
    refresh_record.replaced_by_jti = (
        created_refresh_token.jti
    )

    replacement_record = (
        AuthRefreshToken(
            session_id=session.id,
            jti=(
                created_refresh_token
                .jti
            ),
            token_hash=hash_token(
                created_refresh_token
                .token
            ),
            issued_at=(
                created_refresh_token
                .issued_at
            ),
            expires_at=(
                created_refresh_token
                .expires_at
            ),
            used_at=None,
            revoked_at=None,
            replaced_by_jti=None,
        )
    )

    try:
        db.add(
            refresh_record
        )

        db.add(
            replacement_record
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return IssuedAuthTokens(
        access_token=(
            create_access_token(
                subject=str(
                    user.id
                ),
                session_id=(
                    session.id
                ),
            )
        ),
        refresh_token=(
            created_refresh_token
            .token
        ),
    )


def revoke_auth_session(
    db: Session,
    raw_refresh_token: str,
) -> bool:
    try:
        payload = decode_token(
            raw_refresh_token,
            expected_type="refresh",
        )

        user_id = parse_uuid_claim(
            payload,
            "sub",
        )

        session_id = parse_uuid_claim(
            payload,
            "sid",
        )

    except (
        InvalidTokenError,
        InvalidRefreshTokenError,
        TypeError,
    ):
        return False

    session = db.scalar(
        select(
            AuthSession
        )
        .where(
            AuthSession.id
            == session_id
        )
        .with_for_update()
    )

    if (
        session is None
        or session.user_id
        != user_id
    ):
        return False

    try:
        revoke_session(
            db,
            session,
            "user_logout",
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return True


def validate_access_session(
    db: Session,
    user_id: uuid.UUID,
    session_id: uuid.UUID,
) -> None:
    session = db.scalar(
        select(
            AuthSession
        ).where(
            AuthSession.id
            == session_id,
            AuthSession.user_id
            == user_id,
        )
    )

    now = datetime.now(
        timezone.utc
    )

    if (
        session is None
        or session.revoked_at
        is not None
        or ensure_utc(
            session.expires_at
        ) <= now
    ):
        raise InvalidAccessSessionError(
            "The authentication "
            "session is no longer active."
        )