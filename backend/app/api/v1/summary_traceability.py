import uuid
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session

from app.api.dependencies import require_permission
from app.db.session import get_db
from app.models.summary_traceability import (
    InvestigationSummaryTraceabilityReport,
)
from app.models.user import User
from app.schemas.summary_traceability_response import (
    InvestigationSummaryTraceabilityResponse,
    SummaryTraceabilityIntegrityResponse,
)
from app.services.summary_traceability_persistence_service import (
    SummaryTraceabilityIntegrityError,
)
from app.services.summary_traceability_query_service import (
    InvestigationSummaryNotFoundError,
    SummaryTraceabilityCaseNotFoundError,
    SummaryTraceabilityQueryError,
    SummaryTraceabilityReportNotFoundError,
    get_summary_traceability_report,
    verify_summary_traceability_integrity,
)


router = APIRouter(
    tags=["summary-traceability"],
)


SummaryTraceabilityReadUser = Annotated[
    User,
    Depends(
        require_permission(
            "cases.read",
        )
    ),
]


def raise_traceability_http_error(
    error: Exception,
) -> None:
    if isinstance(
        error,
        InvestigationSummaryNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        SummaryTraceabilityReportNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        SummaryTraceabilityCaseNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        (
            SummaryTraceabilityIntegrityError,
            SummaryTraceabilityQueryError,
        ),
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from error

    raise error


@router.get(
    "/investigation-summaries/{summary_id}/traceability",
    response_model=InvestigationSummaryTraceabilityResponse,
)
def read_summary_traceability(
    summary_id: uuid.UUID,
    _current_user: SummaryTraceabilityReadUser,
    db: Session = Depends(get_db),
) -> InvestigationSummaryTraceabilityReport:
    try:
        return get_summary_traceability_report(
            db=db,
            investigation_summary_id=summary_id,
        )

    except (
        InvestigationSummaryNotFoundError,
        SummaryTraceabilityReportNotFoundError,
        SummaryTraceabilityQueryError,
    ) as error:
        raise_traceability_http_error(error)

    raise RuntimeError(
        "Unexpected traceability retrieval state."
    )


@router.get(
    "/investigation-summaries/{summary_id}/traceability/integrity",
    response_model=SummaryTraceabilityIntegrityResponse,
)
def read_summary_traceability_integrity(
    summary_id: uuid.UUID,
    _current_user: SummaryTraceabilityReadUser,
    db: Session = Depends(get_db),
) -> SummaryTraceabilityIntegrityResponse:
    try:
        return verify_summary_traceability_integrity(
            db=db,
            investigation_summary_id=summary_id,
        )

    except (
        InvestigationSummaryNotFoundError,
        SummaryTraceabilityReportNotFoundError,
        SummaryTraceabilityCaseNotFoundError,
        SummaryTraceabilityIntegrityError,
        SummaryTraceabilityQueryError,
    ) as error:
        raise_traceability_http_error(error)

    raise RuntimeError(
        "Unexpected traceability integrity state."
    )