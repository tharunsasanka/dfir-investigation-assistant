import uuid
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.authentication import (
    AuthRefreshToken,
    AuthSession,
)


def revoke_user_sessions(
    db: Session,
    user_id: uuid.UUID,
    reason: str,
    timestamp: datetime | None = None,
) -> int:
    revoked_at = (
        timestamp
        or datetime.now(
            timezone.utc
        )
    )

    revoke_reason = (
        reason.strip()[:100]
        or "security_event"
    )

    session_ids = list(
        db.scalars(
            select(
                AuthSession.id
            )
            .where(
                AuthSession.user_id
                == user_id,
                AuthSession.revoked_at
                .is_(None),
            )
            .with_for_update()
        ).all()
    )

    if not session_ids:
        return 0

    db.execute(
        update(
            AuthSession
        )
        .where(
            AuthSession.id.in_(
                session_ids
            ),
            AuthSession.revoked_at
            .is_(None),
        )
        .values(
            revoked_at=revoked_at,
            revoke_reason=(
                revoke_reason
            ),
        )
    )

    db.execute(
        update(
            AuthRefreshToken
        )
        .where(
            AuthRefreshToken.session_id
            .in_(
                session_ids
            ),
            AuthRefreshToken.revoked_at
            .is_(None),
        )
        .values(
            revoked_at=revoked_at
        )
    )

    return len(session_ids)