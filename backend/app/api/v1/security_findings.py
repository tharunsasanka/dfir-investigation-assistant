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
from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.models.security_finding import (
    SecurityFinding,
)
from app.models.user import User
from app.schemas.security_finding import (
    SecurityFindingListResponse,
    SecurityFindingRead,
)


router = APIRouter(
    tags=["security-findings"],
)


SecurityFindingReadUser = Annotated[
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
    "/security-findings/{finding_id}",
    response_model=SecurityFindingRead,
)
def get_security_finding(
    finding_id: uuid.UUID,
    _current_user: SecurityFindingReadUser,
    db: Session = Depends(get_db),
) -> SecurityFinding:
    statement = (
        select(SecurityFinding)
        .join(
            Case,
            Case.id
            == SecurityFinding.case_id,
        )
        .where(
            SecurityFinding.id
            == finding_id,
            Case.is_deleted.is_(False),
        )
    )

    finding = db.scalar(statement)

    if finding is None:
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=(
                "Security finding not found"
            ),
        )

    return finding


@router.get(
    "/cases/{case_id}/security-findings",
    response_model=SecurityFindingListResponse,
)
def list_case_security_findings(
    case_id: uuid.UUID,
    _current_user: SecurityFindingReadUser,
    db: Session = Depends(get_db),
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=25,
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
    minimum_confidence: int | None = Query(
        default=None,
        alias="min_confidence",
        ge=0,
        le=100,
    ),
    maximum_confidence: int | None = Query(
        default=None,
        alias="max_confidence",
        ge=0,
        le=100,
    ),
    evidence_id: uuid.UUID | None = Query(
        default=None,
    ),
    ingestion_job_id: uuid.UUID | None = Query(
        default=None,
    ),
    rule_id: str | None = Query(
        default=None,
        max_length=100,
    ),
    source_type: str | None = Query(
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
) -> SecurityFindingListResponse:
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
        minimum_confidence is not None
        and maximum_confidence is not None
        and minimum_confidence
        > maximum_confidence
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail=(
                "min_confidence cannot be "
                "greater than max_confidence"
            ),
        )

    filters = [
        SecurityFinding.case_id
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
                SecurityFinding.title.ilike(
                    pattern,
                ),
                SecurityFinding.description.ilike(
                    pattern,
                ),
                SecurityFinding.rule_id.ilike(
                    pattern,
                ),
                SecurityFinding.event_code.ilike(
                    pattern,
                ),
                SecurityFinding.source_type.ilike(
                    pattern,
                ),
                SecurityFinding.mitre_tactic.ilike(
                    pattern,
                ),
                SecurityFinding
                .mitre_technique_id
                .ilike(
                    pattern,
                ),
                SecurityFinding
                .mitre_technique_name
                .ilike(
                    pattern,
                ),
            )
        )

    if severity is not None:
        filters.append(
            SecurityFinding.severity
            == severity
        )

    if minimum_confidence is not None:
        filters.append(
            SecurityFinding.confidence
            >= minimum_confidence
        )

    if maximum_confidence is not None:
        filters.append(
            SecurityFinding.confidence
            <= maximum_confidence
        )

    if evidence_id is not None:
        filters.append(
            SecurityFinding.evidence_id
            == evidence_id
        )

    if ingestion_job_id is not None:
        filters.append(
            SecurityFinding
            .ingestion_job_id
            == ingestion_job_id
        )

    normalized_rule_id = (
        rule_id.strip()
        if rule_id is not None
        else ""
    )

    if normalized_rule_id:
        filters.append(
            SecurityFinding.rule_id.ilike(
                normalized_rule_id,
            )
        )

    normalized_source_type = (
        source_type.strip()
        if source_type is not None
        else ""
    )

    if normalized_source_type:
        filters.append(
            SecurityFinding.source_type.ilike(
                normalized_source_type,
            )
        )

    normalized_tactic = (
        mitre_tactic.strip()
        if mitre_tactic is not None
        else ""
    )

    if normalized_tactic:
        filters.append(
            SecurityFinding.mitre_tactic.ilike(
                normalized_tactic,
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
            SecurityFinding
            .mitre_technique_id
            .ilike(
                normalized_technique_id,
            )
        )

    total = int(
        db.scalar(
            select(
                func.count(
                    SecurityFinding.id,
                )
            ).where(*filters)
        )
        or 0
    )

    offset = (
        page - 1
    ) * page_size

    statement = (
        select(SecurityFinding)
        .where(*filters)
        .order_by(
            SecurityFinding.event_time
            .desc()
            .nullslast(),
            SecurityFinding.confidence.desc(),
            SecurityFinding.created_at.desc(),
            SecurityFinding.id.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )

    findings = list(
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

    return SecurityFindingListResponse(
        items=[
            SecurityFindingRead
            .model_validate(
                finding
            )
            for finding in findings
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )