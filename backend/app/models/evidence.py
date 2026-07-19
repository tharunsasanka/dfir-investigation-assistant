import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    BigInteger,
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


class EvidenceType(str, enum.Enum):
    log = "log"
    disk_image = "disk_image"
    memory_dump = "memory_dump"
    network_capture = "network_capture"
    document = "document"
    image = "image"
    archive = "archive"
    other = "other"


class EvidenceCustodyEventType(str, enum.Enum):
    uploaded = "uploaded"
    accessed = "accessed"
    integrity_verified = "integrity_verified"
    integrity_failed = "integrity_failed"


class Evidence(Base):
    __tablename__ = "evidence"

    __table_args__ = (
        Index(
            "ix_evidence_case_created_at",
            "case_id",
            "created_at",
        ),
        Index(
            "ix_evidence_case_sha256",
            "case_id",
            "sha256",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "cases.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    stored_filename: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
    )

    content_type: Mapped[str] = mapped_column(
        String(255),
        default="application/octet-stream",
        nullable=False,
    )

    size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    evidence_type: Mapped[EvidenceType] = mapped_column(
        Enum(EvidenceType),
        default=EvidenceType.other,
        nullable=False,
        index=True,
    )

    description: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(500),
        default="",
        nullable=False,
    )

    collected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    uploaded_by_user_id: Mapped[uuid.UUID | None] = (
        mapped_column(
            Uuid(as_uuid=True),
            ForeignKey(
                "users.id",
                ondelete="SET NULL",
            ),
            nullable=True,
        )
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class EvidenceCustodyEvent(Base):
    __tablename__ = "evidence_custody_events"

    __table_args__ = (
        Index(
            "ix_evidence_custody_evidence_created",
            "evidence_id",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "evidence.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    event_type: Mapped[
        EvidenceCustodyEventType
    ] = mapped_column(
        Enum(EvidenceCustodyEventType),
        nullable=False,
        index=True,
    )

    actor_user_id: Mapped[uuid.UUID | None] = (
        mapped_column(
            Uuid(as_uuid=True),
            ForeignKey(
                "users.id",
                ondelete="SET NULL",
            ),
            nullable=True,
        )
    )

    actor_email: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    actor_full_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    details: Mapped[dict[str, Any]] = mapped_column(
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