from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.case_audit import (
    CaseAuditEvent,
    CaseAuditEventType,
)
from app.models.user import User


def case_snapshot(
    investigation_case: Case,
) -> dict[str, Any]:
    return {
        "id": str(investigation_case.id),
        "title": investigation_case.title,
        "description": investigation_case.description,
        "severity": investigation_case.severity.value,
        "status": investigation_case.status.value,
        "is_deleted": investigation_case.is_deleted,
        "deleted_at": (
            investigation_case.deleted_at.isoformat()
            if investigation_case.deleted_at
            else None
        ),
        "deleted_by_user_id": (
            str(investigation_case.deleted_by_user_id)
            if investigation_case.deleted_by_user_id
            else None
        ),
        "created_at": (
            investigation_case.created_at.isoformat()
            if investigation_case.created_at
            else None
        ),
        "updated_at": (
            investigation_case.updated_at.isoformat()
            if investigation_case.updated_at
            else None
        ),
    }


def record_case_audit_event(
    *,
    db: Session,
    investigation_case: Case,
    actor: User,
    event_type: CaseAuditEventType,
    changes: dict[str, Any],
    request: Request,
) -> CaseAuditEvent:
    ip_address = (
        request.client.host
        if request.client is not None
        else None
    )

    user_agent = request.headers.get(
        "user-agent"
    )

    event = CaseAuditEvent(
        case_id=investigation_case.id,
        event_type=event_type,
        actor_user_id=actor.id,
        actor_email=actor.email,
        actor_full_name=actor.full_name,
        changes=changes,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    db.add(event)

    return event