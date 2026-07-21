from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import require_permission
from app.db.session import get_db
from app.models.case import (
    Case,
    CaseSeverity,
    CaseStatus,
)
from app.schemas.dashboard import DashboardCaseSummary


router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)


@router.get(
    "/case-summary",
    response_model=DashboardCaseSummary,
    dependencies=[
        Depends(
            require_permission("cases.read")
        ),
    ],
)
def get_case_summary(
    db: Session = Depends(get_db),
) -> DashboardCaseSummary:
    statement = (
        select(
            func.count(Case.id),
            func.count(Case.id).filter(
                Case.status
                != CaseStatus.closed
            ),
            func.count(Case.id).filter(
                Case.severity
                == CaseSeverity.critical,
                Case.status
                != CaseStatus.closed,
            ),
            func.count(Case.id).filter(
                Case.status
                == CaseStatus.review
            ),
            func.count(Case.id).filter(
                Case.status
                == CaseStatus.closed
            ),
            func.max(Case.updated_at),
        )
        .where(
            Case.is_deleted.is_(False)
        )
    )

    result = db.execute(
        statement
    ).one()

    return DashboardCaseSummary(
        total_cases=int(
            result[0] or 0
        ),
        active_cases=int(
            result[1] or 0
        ),
        critical_active_cases=int(
            result[2] or 0
        ),
        review_cases=int(
            result[3] or 0
        ),
        closed_cases=int(
            result[4] or 0
        ),
        latest_case_updated_at=result[5],
    )