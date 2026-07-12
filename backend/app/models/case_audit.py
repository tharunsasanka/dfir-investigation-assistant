import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class CaseAuditEventType(str, enum.Enum):
    created = "created"
    updated = "updated"
    archived = "archived"


class CaseAuditEvent(Base):
    __tablename__ = "case_audit_events"

    __table_args__ = (
        Index(
            "ix_case_audit_events_case_created_at",
            "case_id",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "cases.id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    event_type: Mapped[CaseAuditEventType] = mapped_column(
        Enum(CaseAuditEventType),
        nullable=False,
        index=True,
    )

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    actor_email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    actor_full_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    changes: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    user_agent: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )