from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.evidence import (
    Evidence,
    EvidenceCustodyEvent,
    EvidenceCustodyEventType,
)
from app.models.user import User


def record_evidence_custody_event(
    *,
    db: Session,
    evidence: Evidence,
    actor: User,
    event_type: EvidenceCustodyEventType,
    request: Request,
    details: dict[str, Any],
) -> EvidenceCustodyEvent:
    ip_address = (
        request.client.host
        if request.client is not None
        else None
    )

    user_agent = request.headers.get(
        "user-agent"
    )

    event = EvidenceCustodyEvent(
        evidence_id=evidence.id,
        event_type=event_type,
        actor_user_id=actor.id,
        actor_email=actor.email,
        actor_full_name=actor.full_name,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.add(event)

    return event