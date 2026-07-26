import uuid
from datetime import datetime
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import (
    require_permission,
)
from app.db.session import get_db
from app.models.case import Case
from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.models.user import User
from app.schemas.forensic_timeline import (
    ForensicTimelineEntryType,
    ForensicTimelineResponse,
    ForensicTimelineSortOrder,
)
from app.services.forensic_timeline_service import (
    get_case_forensic_timeline,
)


router = APIRouter(
    tags=["forensic-timeline"],
)


TimelineReadUser = Annotated[
    User,
    Depends(
        require_permission(
            "cases.read",
        )
    ),
]


def get_active_case(
    db: Session,
    case_id: uuid.UUID,
) -> Case | None:
    return db.scalar(
        select(Case).where(
            Case.id == case_id,
            Case.is_deleted.is_(False),
        )
    )


@router.get(
    "/cases/{case_id}/forensic-timeline",
    response_model=ForensicTimelineResponse,
)
def list_case_forensic_timeline(
    case_id: uuid.UUID,
    _current_user: TimelineReadUser,
    db: Session = Depends(get_db),
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
    search: str | None = Query(
        default=None,
        max_length=255,
    ),
    entry_type: list[
        ForensicTimelineEntryType
    ] | None = Query(
        default=None,
    ),
    severity: LogEventSeverity | None = Query(
        default=None,
    ),
    evidence_id: uuid.UUID | None = Query(
        default=None,
    ),
    start_time: datetime | None = Query(
        default=None,
    ),
    end_time: datetime | None = Query(
        default=None,
    ),
    sort_order: ForensicTimelineSortOrder = Query(
        default=(
            ForensicTimelineSortOrder
            .descending
        ),
    ),
) -> ForensicTimelineResponse:
    investigation_case = get_active_case(
        db,
        case_id,
    )

    if investigation_case is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Case not found",
        )

    if (
        start_time is not None
        and end_time is not None
        and start_time > end_time
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail=(
                "Start time cannot be later "
                "than end time."
            ),
        )

    entry_types = (
        set(entry_type)
        if entry_type
        else None
    )

    return get_case_forensic_timeline(
        db=db,
        case_id=case_id,
        page=page,
        page_size=page_size,
        search=search,
        entry_types=entry_types,
        severity=severity,
        evidence_id=evidence_id,
        start_time=start_time,
        end_time=end_time,
        sort_order=sort_order,
    )