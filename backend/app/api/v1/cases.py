import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.dependencies import require_permission
from app.db.session import get_db
from app.models.case import (
    Case,
    CaseSeverity,
    CaseStatus,
)
from app.models.case_audit import (
    CaseAuditEvent,
    CaseAuditEventType,
)
from app.models.user import User
from app.schemas.case import (
    CaseCreate,
    CaseListResponse,
    CaseRead,
    CaseUpdate,
)
from app.schemas.case_audit import (
    CaseAuditEventListResponse,
    CaseAuditEventRead,
)
from app.services.case_audit_service import (
    case_snapshot,
    record_case_audit_event,
)


router = APIRouter(
    prefix="/cases",
    tags=["cases"],
)


CreateAuthorizedUser = Annotated[
    User,
    Depends(
        require_permission("cases.create")
    ),
]

UpdateAuthorizedUser = Annotated[
    User,
    Depends(
        require_permission("cases.update")
    ),
]

DeleteAuthorizedUser = Annotated[
    User,
    Depends(
        require_permission("cases.delete")
    ),
]


def get_active_case(
    db: Session,
    case_id: uuid.UUID,
) -> Case | None:
    statement = select(Case).where(
        Case.id == case_id,
        Case.is_deleted.is_(False),
    )

    return db.scalar(statement)


@router.get(
    "",
    response_model=CaseListResponse,
    dependencies=[
        Depends(
            require_permission("cases.read")
        ),
    ],
)
def list_cases(
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    search: str | None = Query(
        default=None,
        max_length=160,
    ),
    severity: CaseSeverity | None = None,
    case_status: CaseStatus | None = Query(
        default=None,
        alias="status",
    ),
) -> CaseListResponse:
    filters = [
        Case.is_deleted.is_(False),
    ]

    normalized_search = (
        search.strip()
        if search is not None
        else ""
    )

    if normalized_search:
        search_pattern = (
            f"%{normalized_search}%"
        )

        filters.append(
            or_(
                Case.title.ilike(
                    search_pattern
                ),
                Case.description.ilike(
                    search_pattern
                ),
            )
        )

    if severity is not None:
        filters.append(
            Case.severity == severity
        )

    if case_status is not None:
        filters.append(
            Case.status == case_status
        )

    total = int(
        db.scalar(
            select(
                func.count(Case.id)
            ).where(*filters)
        )
        or 0
    )

    offset = (
        page - 1
    ) * page_size

    statement = (
        select(Case)
        .where(*filters)
        .order_by(
            Case.created_at.desc(),
            Case.id.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )

    cases = list(
        db.scalars(statement).all()
    )

    pages = (
        (
            total
            + page_size
            - 1
        )
        // page_size
        if total > 0
        else 0
    )

    return CaseListResponse(
        items=[
            CaseRead.model_validate(
                investigation_case
            )
            for investigation_case in cases
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post(
    "",
    response_model=CaseRead,
    status_code=status.HTTP_201_CREATED,
)
def create_case(
    payload: CaseCreate,
    request: Request,
    current_user: CreateAuthorizedUser,
    db: Session = Depends(get_db),
) -> Case:
    case_data = payload.model_dump()

    case_data["title"] = (
        case_data["title"].strip()
    )

    case_data["description"] = (
        case_data["description"].strip()
    )

    investigation_case = Case(
        **case_data
    )

    try:
        db.add(investigation_case)
        db.flush()

        record_case_audit_event(
            db=db,
            investigation_case=investigation_case,
            actor=current_user,
            event_type=(
                CaseAuditEventType.created
            ),
            changes={
                "after": case_snapshot(
                    investigation_case
                ),
            },
            request=request,
        )

        db.commit()
        db.refresh(investigation_case)

    except Exception:
        db.rollback()
        raise

    return investigation_case


@router.get(
    "/{case_id}/audit-events",
    response_model=CaseAuditEventListResponse,
    dependencies=[
        Depends(
            require_permission("cases.read")
        ),
        Depends(
            require_permission("audit.read")
        ),
    ],
)
def list_case_audit_events(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
) -> CaseAuditEventListResponse:
    investigation_case = db.get(
        Case,
        case_id,
    )

    if investigation_case is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Case not found",
        )

    total = int(
        db.scalar(
            select(
                func.count(
                    CaseAuditEvent.id
                )
            ).where(
                CaseAuditEvent.case_id
                == case_id
            )
        )
        or 0
    )

    offset = (
        page - 1
    ) * page_size

    statement = (
        select(CaseAuditEvent)
        .where(
            CaseAuditEvent.case_id
            == case_id
        )
        .order_by(
            CaseAuditEvent.created_at.desc(),
            CaseAuditEvent.id.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )

    events = list(
        db.scalars(statement).all()
    )

    pages = (
        (
            total
            + page_size
            - 1
        )
        // page_size
        if total > 0
        else 0
    )

    return CaseAuditEventListResponse(
        items=[
            CaseAuditEventRead.model_validate(
                event
            )
            for event in events
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get(
    "/{case_id}",
    response_model=CaseRead,
    dependencies=[
        Depends(
            require_permission("cases.read")
        ),
    ],
)
def get_case(
    case_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> Case:
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

    return investigation_case


@router.patch(
    "/{case_id}",
    response_model=CaseRead,
)
def update_case(
    case_id: uuid.UUID,
    payload: CaseUpdate,
    request: Request,
    current_user: UpdateAuthorizedUser,
    db: Session = Depends(get_db),
) -> Case:
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

    before_snapshot = case_snapshot(
        investigation_case
    )

    update_data = payload.model_dump(
        exclude_unset=True,
    )

    if "title" in update_data:
        update_data["title"] = (
            update_data["title"].strip()
        )

    if "description" in update_data:
        update_data["description"] = (
            update_data[
                "description"
            ].strip()
        )

    for field_name, field_value in (
        update_data.items()
    ):
        setattr(
            investigation_case,
            field_name,
            field_value,
        )

    try:
        db.add(investigation_case)
        db.flush()

        after_snapshot = case_snapshot(
            investigation_case
        )

        changed_fields = set(
            update_data.keys()
        )

        record_case_audit_event(
            db=db,
            investigation_case=investigation_case,
            actor=current_user,
            event_type=(
                CaseAuditEventType.updated
            ),
            changes={
                "before": {
                    field_name:
                    before_snapshot[field_name]
                    for field_name
                    in changed_fields
                },
                "after": {
                    field_name:
                    after_snapshot[field_name]
                    for field_name
                    in changed_fields
                },
            },
            request=request,
        )

        db.commit()
        db.refresh(investigation_case)

    except Exception:
        db.rollback()
        raise

    return investigation_case


@router.delete(
    "/{case_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def delete_case(
    case_id: uuid.UUID,
    request: Request,
    current_user: DeleteAuthorizedUser,
    db: Session = Depends(get_db),
) -> Response:
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

    before_snapshot = case_snapshot(
        investigation_case
    )

    investigation_case.is_deleted = True
    investigation_case.deleted_at = (
        datetime.now(timezone.utc)
    )
    investigation_case.deleted_by_user_id = (
        current_user.id
    )

    try:
        db.add(investigation_case)
        db.flush()

        after_snapshot = case_snapshot(
            investigation_case
        )

        archive_fields = {
            "is_deleted",
            "deleted_at",
            "deleted_by_user_id",
        }

        record_case_audit_event(
            db=db,
            investigation_case=investigation_case,
            actor=current_user,
            event_type=(
                CaseAuditEventType.archived
            ),
            changes={
                "before": {
                    field_name:
                    before_snapshot[field_name]
                    for field_name
                    in archive_fields
                },
                "after": {
                    field_name:
                    after_snapshot[field_name]
                    for field_name
                    in archive_fields
                },
            },
            request=request,
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return Response(
        status_code=(
            status.HTTP_204_NO_CONTENT
        )
    )