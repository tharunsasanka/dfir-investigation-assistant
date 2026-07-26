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
    exists,
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
from app.models.event_correlation import (
    EventCorrelation,
    EventCorrelationMember,
    EventCorrelationType,
)
from app.models.log_ingestion import (
    LogEventSeverity,
    ParsedLogEvent,
)
from app.models.user import User
from app.schemas.event_correlation import (
    EventCorrelationDetailRead,
    EventCorrelationListResponse,
    EventCorrelationMemberEventRead,
    EventCorrelationRead,
    EventCorrelationRunResponse,
)
from app.services.event_correlation_service import (
    run_case_event_correlation,
)


router = APIRouter(
    tags=["event-correlations"],
)


CorrelationReadUser = Annotated[
    User,
    Depends(
        require_permission(
            "cases.read",
        )
    ),
]


CorrelationWriteUser = Annotated[
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


@router.post(
    "/cases/{case_id}/event-correlations/run",
    response_model=EventCorrelationRunResponse,
    status_code=status.HTTP_200_OK,
)
def run_case_correlations(
    case_id: uuid.UUID,
    _current_user: CorrelationWriteUser,
    db: Session = Depends(get_db),
) -> EventCorrelationRunResponse:
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

    return run_case_event_correlation(
        db=db,
        case_id=case_id,
    )


@router.get(
    "/event-correlations/{correlation_id}",
    response_model=EventCorrelationDetailRead,
)
def get_event_correlation(
    correlation_id: uuid.UUID,
    _current_user: CorrelationReadUser,
    db: Session = Depends(get_db),
) -> EventCorrelationDetailRead:
    correlation = db.get(
        EventCorrelation,
        correlation_id,
    )

    if correlation is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Event correlation not found",
        )

    investigation_case = get_active_case(
        db,
        correlation.case_id,
    )

    if investigation_case is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail="Event correlation not found",
        )

    statement = (
        select(
            EventCorrelationMember,
            ParsedLogEvent,
        )
        .join(
            ParsedLogEvent,
            ParsedLogEvent.id
            == EventCorrelationMember
            .parsed_event_id,
        )
        .where(
            EventCorrelationMember
            .correlation_id
            == correlation.id
        )
        .order_by(
            EventCorrelationMember
            .position.asc(),
            EventCorrelationMember
            .id.asc(),
        )
    )

    rows = db.execute(
        statement
    ).all()

    members = [
        EventCorrelationMemberEventRead(
            membership_id=member.id,
            parsed_event_id=event.id,
            evidence_id=event.evidence_id,
            event_time=event.event_time,
            position=member.position,
            relationship=(
                member.relationship
            ),
            source_type=event.source_type,
            event_code=event.event_code,
            severity=event.severity,
            host=event.host,
            username=event.username,
            process_name=(
                event.process_name
            ),
            source_ip=event.source_ip,
            destination_ip=(
                event.destination_ip
            ),
            message=event.message,
            matched_values=(
                member.matched_values
            ),
        )
        for member, event in rows
    ]

    correlation_data = (
        EventCorrelationRead
        .model_validate(
            correlation
        )
        .model_dump()
    )

    return EventCorrelationDetailRead(
        **correlation_data,
        members=members,
    )


@router.get(
    "/cases/{case_id}/event-correlations",
    response_model=EventCorrelationListResponse,
)
def list_case_event_correlations(
    case_id: uuid.UUID,
    _current_user: CorrelationReadUser,
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
    search: str | None = Query(
        default=None,
        max_length=255,
    ),
    severity: LogEventSeverity | None = Query(
        default=None,
    ),
    correlation_type: EventCorrelationType | None = Query(
        default=None,
    ),
    min_confidence: int | None = Query(
        default=None,
        ge=0,
        le=100,
    ),
    max_confidence: int | None = Query(
        default=None,
        ge=0,
        le=100,
    ),
    evidence_id: uuid.UUID | None = Query(
        default=None,
    ),
    rule_id: str | None = Query(
        default=None,
        max_length=100,
    ),
    mitre_tactic: str | None = Query(
        default=None,
        max_length=100,
    ),
    mitre_technique_id: str | None = Query(
        default=None,
        max_length=50,
    ),
) -> EventCorrelationListResponse:
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
        min_confidence is not None
        and max_confidence is not None
        and min_confidence
        > max_confidence
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail=(
                "Minimum confidence cannot "
                "exceed maximum confidence."
            ),
        )

    filters = [
        EventCorrelation.case_id
        == case_id,
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
                EventCorrelation.title.ilike(
                    pattern,
                ),
                EventCorrelation.description.ilike(
                    pattern,
                ),
                EventCorrelation.rule_id.ilike(
                    pattern,
                ),
                EventCorrelation
                .correlation_key
                .ilike(
                    pattern,
                ),
                EventCorrelation
                .mitre_tactic
                .ilike(
                    pattern,
                ),
                EventCorrelation
                .mitre_technique_id
                .ilike(
                    pattern,
                ),
                EventCorrelation
                .mitre_technique_name
                .ilike(
                    pattern,
                ),
            )
        )

    if severity is not None:
        filters.append(
            EventCorrelation.severity
            == severity
        )

    if correlation_type is not None:
        filters.append(
            EventCorrelation
            .correlation_type
            == correlation_type
        )

    if min_confidence is not None:
        filters.append(
            EventCorrelation.confidence
            >= min_confidence
        )

    if max_confidence is not None:
        filters.append(
            EventCorrelation.confidence
            <= max_confidence
        )

    if evidence_id is not None:
        filters.append(
            exists(
                select(
                    EventCorrelationMember.id
                ).where(
                    EventCorrelationMember
                    .correlation_id
                    == EventCorrelation.id,
                    EventCorrelationMember
                    .evidence_id
                    == evidence_id,
                )
            )
        )

    normalized_rule_id = (
        rule_id.strip()
        if rule_id is not None
        else ""
    )

    if normalized_rule_id:
        filters.append(
            EventCorrelation.rule_id
            == normalized_rule_id
        )

    normalized_tactic = (
        mitre_tactic.strip()
        if mitre_tactic is not None
        else ""
    )

    if normalized_tactic:
        filters.append(
            EventCorrelation
            .mitre_tactic
            .ilike(
                normalized_tactic
            )
        )

    normalized_technique_id = (
        mitre_technique_id.strip()
        if mitre_technique_id
        is not None
        else ""
    )

    if normalized_technique_id:
        filters.append(
            EventCorrelation
            .mitre_technique_id
            .ilike(
                normalized_technique_id
            )
        )

    total = int(
        db.scalar(
            select(
                func.count(
                    EventCorrelation.id,
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
            EventCorrelation
        )
        .where(*filters)
        .order_by(
            EventCorrelation.severity.desc(),
            EventCorrelation.confidence.desc(),
            EventCorrelation
            .window_start
            .desc()
            .nullslast(),
            EventCorrelation.created_at.desc(),
            EventCorrelation.id.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )

    correlations = list(
        db.scalars(
            statement
        ).all()
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

    return EventCorrelationListResponse(
        items=[
            EventCorrelationRead
            .model_validate(
                correlation
            )
            for correlation
            in correlations
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )