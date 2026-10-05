from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "f2b9c7d4a611"
down_revision: str | None = (
    "a8f3c1d7e2b4"
)
branch_labels: (
    str
    | Sequence[str]
    | None
) = None
depends_on: (
    str
    | Sequence[str]
    | None
) = None


def upgrade() -> None:
    op.create_table(
        "auth_sessions",
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.Column(
            "revoked_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=True,
        ),
        sa.Column(
            "revoke_reason",
            sa.String(
                length=100
            ),
            nullable=False,
        ),
        sa.Column(
            "created_ip_hash",
            sa.String(
                length=64
            ),
            nullable=False,
        ),
        sa.Column(
            "user_agent",
            sa.String(
                length=500
            ),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            [
                "user_id",
            ],
            [
                "users.id",
            ],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "id"
        ),
    )

    op.create_index(
        "ix_auth_sessions_user_id",
        "auth_sessions",
        [
            "user_id",
        ],
        unique=False,
    )

    op.create_index(
        "ix_auth_sessions_expires_at",
        "auth_sessions",
        [
            "expires_at",
        ],
        unique=False,
    )

    op.create_index(
        "ix_auth_sessions_revoked_at",
        "auth_sessions",
        [
            "revoked_at",
        ],
        unique=False,
    )

    op.create_index(
        "ix_auth_sessions_user_revoked",
        "auth_sessions",
        [
            "user_id",
            "revoked_at",
        ],
        unique=False,
    )

    op.create_table(
        "auth_refresh_tokens",
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "session_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "jti",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "token_hash",
            sa.String(
                length=64
            ),
            nullable=False,
        ),
        sa.Column(
            "issued_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.Column(
            "used_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=True,
        ),
        sa.Column(
            "revoked_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=True,
        ),
        sa.Column(
            "replaced_by_jti",
            sa.Uuid(),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            [
                "session_id",
            ],
            [
                "auth_sessions.id",
            ],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "id"
        ),
        sa.UniqueConstraint(
            "jti"
        ),
        sa.UniqueConstraint(
            "token_hash"
        ),
    )

    op.create_index(
        "ix_auth_refresh_tokens_session_id",
        "auth_refresh_tokens",
        [
            "session_id",
        ],
        unique=False,
    )

    op.create_index(
        "ix_auth_refresh_tokens_jti",
        "auth_refresh_tokens",
        [
            "jti",
        ],
        unique=True,
    )

    op.create_index(
        "ix_auth_refresh_tokens_token_hash",
        "auth_refresh_tokens",
        [
            "token_hash",
        ],
        unique=True,
    )

    op.create_index(
        "ix_auth_refresh_tokens_expires_at",
        "auth_refresh_tokens",
        [
            "expires_at",
        ],
        unique=False,
    )

    op.create_table(
        "login_rate_limits",
        sa.Column(
            "key_hash",
            sa.String(
                length=64
            ),
            nullable=False,
        ),
        sa.Column(
            "failed_attempts",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "window_started_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.Column(
            "blocked_until",
            sa.DateTime(
                timezone=True
            ),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint(
            "key_hash"
        ),
    )

    op.create_index(
        "ix_login_rate_limits_blocked_until",
        "login_rate_limits",
        [
            "blocked_until",
        ],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_login_rate_limits_blocked_until",
        table_name=(
            "login_rate_limits"
        ),
    )

    op.drop_table(
        "login_rate_limits"
    )

    op.drop_index(
        "ix_auth_refresh_tokens_expires_at",
        table_name=(
            "auth_refresh_tokens"
        ),
    )

    op.drop_index(
        "ix_auth_refresh_tokens_token_hash",
        table_name=(
            "auth_refresh_tokens"
        ),
    )

    op.drop_index(
        "ix_auth_refresh_tokens_jti",
        table_name=(
            "auth_refresh_tokens"
        ),
    )

    op.drop_index(
        "ix_auth_refresh_tokens_session_id",
        table_name=(
            "auth_refresh_tokens"
        ),
    )

    op.drop_table(
        "auth_refresh_tokens"
    )

    op.drop_index(
        "ix_auth_sessions_user_revoked",
        table_name=(
            "auth_sessions"
        ),
    )

    op.drop_index(
        "ix_auth_sessions_revoked_at",
        table_name=(
            "auth_sessions"
        ),
    )

    op.drop_index(
        "ix_auth_sessions_expires_at",
        table_name=(
            "auth_sessions"
        ),
    )

    op.drop_index(
        "ix_auth_sessions_user_id",
        table_name=(
            "auth_sessions"
        ),
    )

    op.drop_table(
        "auth_sessions"
    )