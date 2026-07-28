import uuid
from datetime import (
    datetime,
    timezone,
)

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from app.db.session import Base


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    __table_args__ = (
        Index(
            "ix_auth_sessions_user_revoked",
            "user_id",
            "revoked_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(
            timezone.utc
        ),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    revoked_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    revoke_reason: Mapped[str] = mapped_column(
        String(100),
        default="",
        nullable=False,
    )

    created_ip_hash: Mapped[str] = mapped_column(
        String(64),
        default="",
        nullable=False,
    )

    user_agent: Mapped[str] = mapped_column(
        String(500),
        default="",
        nullable=False,
    )

    user = relationship(
        "User",
        back_populates="auth_sessions",
    )

    refresh_tokens = relationship(
        "AuthRefreshToken",
        back_populates="session",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class AuthRefreshToken(Base):
    __tablename__ = (
        "auth_refresh_tokens"
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )

    session_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        ForeignKey(
            "auth_sessions.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    jti: Mapped[uuid.UUID] = mapped_column(
        unique=True,
        nullable=False,
        index=True,
    )

    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    used_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revoked_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    replaced_by_jti: Mapped[
        uuid.UUID | None
    ] = mapped_column(
        nullable=True,
    )

    session = relationship(
        "AuthSession",
        back_populates="refresh_tokens",
    )


class LoginRateLimit(Base):
    __tablename__ = (
        "login_rate_limits"
    )

    key_hash: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    failed_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    window_started_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    blocked_until: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(
            timezone.utc
        ),
        nullable=False,
    )