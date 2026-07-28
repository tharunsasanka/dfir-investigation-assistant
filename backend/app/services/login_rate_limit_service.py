import hashlib
import math
from datetime import (
    datetime,
    timedelta,
    timezone,
)

from fastapi import Request
from sqlalchemy import (
    delete,
    select,
)
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.authentication import (
    LoginRateLimit,
)


settings = get_settings()


class LoginRateLimitExceededError(
    Exception
):
    def __init__(
        self,
        retry_after_seconds: int,
    ) -> None:
        self.retry_after_seconds = max(
            1,
            retry_after_seconds,
        )

        super().__init__(
            "Too many authentication "
            "attempts."
        )


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


def get_request_key(
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


def get_retry_after(
    blocked_until: datetime,
    now: datetime,
) -> int:
    return max(
        1,
        math.ceil(
            (
                ensure_utc(
                    blocked_until
                )
                - now
            ).total_seconds()
        ),
    )


def enforce_login_rate_limit(
    db: Session,
    request: Request,
) -> None:
    key_hash = get_request_key(
        request
    )

    now = datetime.now(
        timezone.utc
    )

    bucket = db.scalar(
        select(
            LoginRateLimit
        )
        .where(
            LoginRateLimit.key_hash
            == key_hash
        )
        .with_for_update()
    )

    if bucket is None:
        return

    if (
        bucket.blocked_until
        is not None
    ):
        blocked_until = ensure_utc(
            bucket.blocked_until
        )

        if blocked_until > now:
            raise (
                LoginRateLimitExceededError(
                    get_retry_after(
                        blocked_until,
                        now,
                    )
                )
            )

    window_started_at = ensure_utc(
        bucket.window_started_at
    )

    window_end = (
        window_started_at
        + timedelta(
            seconds=(
                settings
                .login_rate_limit_window_seconds
            )
        )
    )

    if (
        window_end <= now
        or (
            bucket.blocked_until
            is not None
            and ensure_utc(
                bucket.blocked_until
            ) <= now
        )
    ):
        bucket.failed_attempts = 0
        bucket.window_started_at = now
        bucket.blocked_until = None
        bucket.updated_at = now

        db.add(bucket)
        db.commit()


def record_failed_login_attempt(
    db: Session,
    request: Request,
) -> None:
    key_hash = get_request_key(
        request
    )

    now = datetime.now(
        timezone.utc
    )

    bucket = db.scalar(
        select(
            LoginRateLimit
        )
        .where(
            LoginRateLimit.key_hash
            == key_hash
        )
        .with_for_update()
    )

    if bucket is None:
        bucket = LoginRateLimit(
            key_hash=key_hash,
            failed_attempts=0,
            window_started_at=now,
            blocked_until=None,
            updated_at=now,
        )

    else:
        if (
            bucket.blocked_until
            is not None
            and ensure_utc(
                bucket.blocked_until
            ) > now
        ):
            raise (
                LoginRateLimitExceededError(
                    get_retry_after(
                        bucket.blocked_until,
                        now,
                    )
                )
            )

        window_started_at = ensure_utc(
            bucket.window_started_at
        )

        window_end = (
            window_started_at
            + timedelta(
                seconds=(
                    settings
                    .login_rate_limit_window_seconds
                )
            )
        )

        if window_end <= now:
            bucket.failed_attempts = 0
            bucket.window_started_at = now
            bucket.blocked_until = None

    bucket.failed_attempts += 1
    bucket.updated_at = now

    if (
        bucket.failed_attempts
        >= settings
        .login_rate_limit_attempts
    ):
        bucket.blocked_until = (
            now
            + timedelta(
                seconds=(
                    settings
                    .login_rate_limit_block_seconds
                )
            )
        )

    db.add(bucket)
    db.commit()
    db.refresh(bucket)

    if (
        bucket.blocked_until
        is not None
    ):
        raise (
            LoginRateLimitExceededError(
                get_retry_after(
                    bucket.blocked_until,
                    now,
                )
            )
        )


def clear_login_rate_limit(
    db: Session,
    request: Request,
) -> None:
    key_hash = get_request_key(
        request
    )

    db.execute(
        delete(
            LoginRateLimit
        ).where(
            LoginRateLimit.key_hash
            == key_hash
        )
    )

    db.commit()