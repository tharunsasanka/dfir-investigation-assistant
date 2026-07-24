import uuid
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy import (
    func,
    or_,
    select,
)
from sqlalchemy.orm import Session

from app.api.dependencies import (
    require_permission,
)
from app.db.session import get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.log_ingestion import (
    LogEventSeverity,
    LogIngestionJob,
    LogIngestionStatus,
    ParsedLogEvent,
)
from app.models.user import User
from app.schemas.log_ingestion import (
    LogIngestionJobHistoryItem,
    LogIngestionJobListResponse,
    LogIngestionJobRead,
    LogIngestionRequest,
    ParsedLogEventListResponse,
    ParsedLogEventRead,
)
from app.services.evidence_storage import (
    get_evidence_path,
)
from app.services.log_ingestion_service import (
    run_log_ingestion,
)


router = APIRouter(
    tags=["log-ingestion"],
)


LogReadUser = Annotated[
    User,
    Depends(
        require_permission(
            "cases.read",
        )
    ),
]


LogWriteUser = Annotated[
    User,
    Depends(
        require_permission(
            "cases.update",
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


def get_active_evidence(
    db: Session,
    evidence_id: uuid.UUID,
) -> Evidence | None:
    statement = (
        select(Evidence)
        .join(
            Case,
            Case.id == Evidence.case_id,
        )
        .where(
            Evidence.id == evidence_id,
            Case.is_deleted.is_(False),
        )
    )

    return db.scalar(statement)


@router.post(
    "/evidence/{evidence_id}/ingest-logs",
    response_model=LogIngestionJobRead,
    status_code=status.HTTP_201_CREATED,
)
def ingest_evidence_logs(
    evidence_id: uuid.UUID,
    payload: LogIngestionRequest,
    current_user: LogWriteUser,
    db: Session = Depends(get_db),
) -> LogIngestionJob:
    evidence = get_active_evidence(
        db,
        evidence_id,
    )

    if evidence is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Evidence not found",
        )

    evidence_path = get_evidence_path(
        evidence.case_id,
        evidence.stored_filename,
    )

    if not evidence_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=(
                "The stored evidence file is missing."
            ),
        )

    job = LogIngestionJob(
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        requested_format=payload.log_format,
        requested_by_user_id=current_user.id,
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    return run_log_ingestion(
        db=db,
        job=job,
        evidence=evidence,
        evidence_path=evidence_path,
    )


@router.get(
    "/log-ingestion-jobs/{job_id}",
    response_model=LogIngestionJobRead,
)
def get_log_ingestion_job(
    job_id: uuid.UUID,
    _current_user: LogReadUser,
    db: Session = Depends(get_db),
) -> LogIngestionJob:
    job = db.get(
        LogIngestionJob,
        job_id,
    )

    if job is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Log ingestion job not found"
            ),
        )

    investigation_case = get_active_case(
        db,
        job.case_id,
    )

    if investigation_case is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Log ingestion job not found"
            ),
        )

    return job


@router.get(
    "/cases/{case_id}/log-ingestion-jobs",
    response_model=LogIngestionJobListResponse,
)
def list_case_log_ingestion_jobs(
    case_id: uuid.UUID,
    _current_user: LogReadUser,
    db: Session = Depends(get_db),
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    job_status: LogIngestionStatus | None = Query(
        default=None,
        alias="status",
    ),
    evidence_id: uuid.UUID | None = Query(
        default=None,
    ),
) -> LogIngestionJobListResponse:
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

    filters = [
        LogIngestionJob.case_id == case_id,
    ]

    if job_status is not None:
        filters.append(
            LogIngestionJob.status
            == job_status
        )

    if evidence_id is not None:
        filters.append(
            LogIngestionJob.evidence_id
            == evidence_id
        )

    total = int(
        db.scalar(
            select(
                func.count(
                    LogIngestionJob.id,
                )
            ).where(*filters)
        )
        or 0
    )

    offset = (
        page - 1
    ) * page_size

    statement = (
        select(
            LogIngestionJob,
            Evidence.original_filename,
            User.email,
        )
        .join(
            Evidence,
            Evidence.id
            == LogIngestionJob.evidence_id,
        )
        .outerjoin(
            User,
            User.id
            == LogIngestionJob
            .requested_by_user_id,
        )
        .where(*filters)
        .order_by(
            LogIngestionJob.created_at.desc(),
            LogIngestionJob.id.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )

    rows = db.execute(
        statement
    ).all()

    items = [
        LogIngestionJobHistoryItem(
            **LogIngestionJobRead
            .model_validate(job)
            .model_dump(),
            evidence_filename=(
                evidence_filename
            ),
            requested_by_email=(
                requested_by_email
            ),
        )
        for (
            job,
            evidence_filename,
            requested_by_email,
        ) in rows
    ]

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

    return LogIngestionJobListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get(
    "/cases/{case_id}/log-events",
    response_model=ParsedLogEventListResponse,
)
def list_case_log_events(
    case_id: uuid.UUID,
    _current_user: LogReadUser,
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
    severity: LogEventSeverity | None = Query(
        default=None,
    ),
    evidence_id: uuid.UUID | None = Query(
        default=None,
    ),
) -> ParsedLogEventListResponse:
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

    filters = [
        ParsedLogEvent.case_id == case_id,
    ]

    normalized_search = (
        search.strip()
        if search is not None
        else ""
    )

    if normalized_search:
        pattern = (
            f"%{normalized_search}%"
        )

        filters.append(
            or_(
                ParsedLogEvent.message.ilike(
                    pattern,
                ),
                ParsedLogEvent.host.ilike(
                    pattern,
                ),
                ParsedLogEvent.username.ilike(
                    pattern,
                ),
                ParsedLogEvent.process_name.ilike(
                    pattern,
                ),
                ParsedLogEvent.source_ip.ilike(
                    pattern,
                ),
                ParsedLogEvent.destination_ip.ilike(
                    pattern,
                ),
                ParsedLogEvent.event_code.ilike(
                    pattern,
                ),
            )
        )

    if severity is not None:
        filters.append(
            ParsedLogEvent.severity
            == severity
        )

    if evidence_id is not None:
        filters.append(
            ParsedLogEvent.evidence_id
            == evidence_id
        )

    total = int(
        db.scalar(
            select(
                func.count(
                    ParsedLogEvent.id,
                )
            ).where(*filters)
        )
        or 0
    )

    offset = (
        page - 1
    ) * page_size

    statement = (
        select(ParsedLogEvent)
        .where(*filters)
        .order_by(
            ParsedLogEvent.event_time
            .desc()
            .nullslast(),
            ParsedLogEvent.event_index.desc(),
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

    return ParsedLogEventListResponse(
        items=[
            ParsedLogEventRead.model_validate(
                event,
            )
            for event in events
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )