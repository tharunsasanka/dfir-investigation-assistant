import uuid
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.orm import Session

from app.api.dependencies import (
    require_permission,
)
from app.db.session import get_db
from app.models.investigation_summary import (
    InvestigationSummary,
)
from app.models.user import User
from app.schemas.investigation_summary import (
    InvestigationSummaryGenerateRequest,
    InvestigationSummaryListResponse,
    InvestigationSummaryResponse,
    InvestigationSummaryRevisionRequest,
    InvestigationSummaryReviewRequest,
)
from app.services.investigation_summary_generation_service import (
    generate_investigation_summary,
)
from app.services.investigation_summary_service import (
    InvestigationSummaryNotFoundError,
    InvestigationSummaryStateError,
    UnsupportedSummaryProviderError,
    create_analyst_revision,
    get_investigation_summary,
    list_case_investigation_summaries,
    review_investigation_summary,
)


router = APIRouter(
    tags=["investigation-summaries"],
)


InvestigationSummaryReadUser = Annotated[
    User,
    Depends(
        require_permission(
            "cases.read",
        )
    ),
]


InvestigationSummaryWriteUser = Annotated[
    User,
    Depends(
        require_permission(
            "cases.update",
        )
    ),
]


def raise_service_http_error(
    error: Exception,
) -> None:
    if isinstance(
        error,
        InvestigationSummaryNotFoundError,
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND
            ),
            detail=str(error),
        ) from error

    if isinstance(
        error,
        InvestigationSummaryStateError,
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_409_CONFLICT
            ),
            detail=str(error),
        ) from error

    if isinstance(
        error,
        UnsupportedSummaryProviderError,
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail=str(error),
        ) from error

    raise error


@router.post(
    "/cases/{case_id}/investigation-summaries/generate",
    response_model=InvestigationSummaryResponse,
    status_code=status.HTTP_201_CREATED,
)
def generate_case_investigation_summary(
    case_id: uuid.UUID,
    payload: InvestigationSummaryGenerateRequest,
    current_user: InvestigationSummaryWriteUser,
    db: Session = Depends(get_db),
) -> InvestigationSummary:
    try:
        return generate_investigation_summary(
            db=db,
            case_id=case_id,
            requested_by_user_id=(
                current_user.id
            ),
            request=payload,
        )

    except (
        InvestigationSummaryNotFoundError,
        InvestigationSummaryStateError,
        UnsupportedSummaryProviderError,
    ) as error:
        raise_service_http_error(
            error
        )

    raise RuntimeError(
        "Unexpected summary generation state."
    )


@router.get(
    "/cases/{case_id}/investigation-summaries",
    response_model=InvestigationSummaryListResponse,
)
def list_case_summary_versions(
    case_id: uuid.UUID,
    _current_user: InvestigationSummaryReadUser,
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
) -> InvestigationSummaryListResponse:
    try:
        return list_case_investigation_summaries(
            db=db,
            case_id=case_id,
            page=page,
            page_size=page_size,
        )

    except InvestigationSummaryNotFoundError as error:
        raise_service_http_error(
            error
        )

    raise RuntimeError(
        "Unexpected summary list state."
    )


@router.get(
    "/investigation-summaries/{summary_id}",
    response_model=InvestigationSummaryResponse,
)
def read_investigation_summary(
    summary_id: uuid.UUID,
    _current_user: InvestigationSummaryReadUser,
    db: Session = Depends(get_db),
) -> InvestigationSummary:
    try:
        return get_investigation_summary(
            db=db,
            summary_id=summary_id,
        )

    except InvestigationSummaryNotFoundError as error:
        raise_service_http_error(
            error
        )

    raise RuntimeError(
        "Unexpected summary retrieval state."
    )


@router.post(
    "/investigation-summaries/{summary_id}/review",
    response_model=InvestigationSummaryResponse,
)
def review_summary(
    summary_id: uuid.UUID,
    payload: InvestigationSummaryReviewRequest,
    current_user: InvestigationSummaryWriteUser,
    db: Session = Depends(get_db),
) -> InvestigationSummary:
    try:
        return review_investigation_summary(
            db=db,
            summary_id=summary_id,
            reviewed_by_user_id=(
                current_user.id
            ),
            decision=payload.decision,
            review_notes=(
                payload.review_notes
            ),
        )

    except (
        InvestigationSummaryNotFoundError,
        InvestigationSummaryStateError,
    ) as error:
        raise_service_http_error(
            error
        )

    raise RuntimeError(
        "Unexpected summary review state."
    )


@router.post(
    "/investigation-summaries/{summary_id}/revisions",
    response_model=InvestigationSummaryResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_summary_revision(
    summary_id: uuid.UUID,
    payload: InvestigationSummaryRevisionRequest,
    current_user: InvestigationSummaryWriteUser,
    db: Session = Depends(get_db),
) -> InvestigationSummary:
    try:
        return create_analyst_revision(
            db=db,
            summary_id=summary_id,
            requested_by_user_id=(
                current_user.id
            ),
            request=payload,
        )

    except (
        InvestigationSummaryNotFoundError,
        InvestigationSummaryStateError,
    ) as error:
        raise_service_http_error(
            error
        )

    raise RuntimeError(
        "Unexpected summary revision state."
    )