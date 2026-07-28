import hashlib
import uuid
from dataclasses import dataclass
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from typing import (
    Any,
    Literal,
)

import jwt
from jwt import InvalidTokenError
from pwdlib import PasswordHash

from app.core.config import get_settings


settings = get_settings()
password_hash = PasswordHash.recommended()

TokenType = Literal[
    "access",
    "refresh",
]


@dataclass(frozen=True)
class CreatedRefreshToken:
    token: str
    jti: uuid.UUID
    session_id: uuid.UUID
    issued_at: datetime
    expires_at: datetime


def hash_password(
    password: str,
) -> str:
    return password_hash.hash(
        password
    )


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(
        plain_password,
        hashed_password,
    )


def hash_token(
    token: str,
) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


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


def create_access_token(
    subject: str,
    session_id: uuid.UUID,
) -> str:
    now = datetime.now(
        timezone.utc
    )

    payload = {
        "sub": subject,
        "sid": str(session_id),
        "type": "access",
        "iat": now,
        "nbf": now,
        "exp": (
            now
            + timedelta(
                minutes=(
                    settings
                    .access_token_expire_minutes
                )
            )
        ),
        "jti": str(
            uuid.uuid4()
        ),
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=(
            settings.jwt_algorithm
        ),
    )


def create_refresh_token(
    subject: str,
    session_id: uuid.UUID,
    expires_at: datetime,
) -> CreatedRefreshToken:
    now = datetime.now(
        timezone.utc
    )

    normalized_expiry = ensure_utc(
        expires_at
    )

    jti = uuid.uuid4()

    payload = {
        "sub": subject,
        "sid": str(session_id),
        "type": "refresh",
        "iat": now,
        "nbf": now,
        "exp": normalized_expiry,
        "jti": str(jti),
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=(
            settings.jwt_algorithm
        ),
    )

    return CreatedRefreshToken(
        token=token,
        jti=jti,
        session_id=session_id,
        issued_at=now,
        expires_at=normalized_expiry,
    )


def decode_token(
    token: str,
    expected_type: TokenType | None = None,
) -> dict[str, Any]:
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[
            settings.jwt_algorithm
        ],
    )

    if (
        expected_type
        and payload.get("type")
        != expected_type
    ):
        raise InvalidTokenError(
            f"Expected a {expected_type} token."
        )

    return payload