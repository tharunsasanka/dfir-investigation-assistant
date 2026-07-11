import enum
import uuid
from datetime import datetime
from sqlalchemy import DateTime, Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.session import Base


class CaseSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class CaseStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    review = "review"
    closed = "closed"


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(160), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[CaseSeverity] = mapped_column(Enum(CaseSeverity), default=CaseSeverity.medium)
    status: Mapped[CaseStatus] = mapped_column(Enum(CaseStatus), default=CaseStatus.open)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
