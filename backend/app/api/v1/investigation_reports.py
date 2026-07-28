from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Response,
    status,
)
from sqlalchemy.orm import Session

from app.api.dependencies import require_permission
from app.db.session import get_db
from app.models.user import User
from app.schemas.investigation_report import (
    InvestigationReportFormat,
    InvestigationReportGenerationRequest,
)
from app.services.investigation_report_export_service import (
    InvestigationReportFormatError,
    export_investigation_report_json,
)
from app.services.investigation_report_pdf_service import (
    export_investigation_report_pdf,
)
from app.services.investigation_report_service import (
    InvestigationReportCaseMismatchError,
    InvestigationReportError,
    InvestigationReportIntegrityError,
)
from app.services.summary_traceability_persistence_service import (
    SummaryTraceabilityIntegrityError,
)
from app.services.summary_traceability_query_service import (
    InvestigationSummaryNotFoundError,
    SummaryTraceabilityCaseNotFoundError,
    SummaryTraceabilityQueryError,
    SummaryTraceabilityReportNotFoundError,
)


router = APIRouter(
    prefix="/investigation-reports",
    tags=["investigation-reports"],
)


InvestigationReportReadUser = Annotated[
    User,
    Depends(
        require_permission(
            "cases.read",
        )
    ),
]


def raise_report_http_error(
    error: Exception,
) -> None:
    if isinstance(
        error,
        (
            InvestigationSummaryNotFoundError,
            SummaryTraceabilityCaseNotFoundError,
            SummaryTraceabilityReportNotFoundError,
        ),
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        InvestigationReportFormatError,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        (
            InvestigationReportCaseMismatchError,
            InvestigationReportIntegrityError,
            SummaryTraceabilityIntegrityError,
            SummaryTraceabilityQueryError,
        ),
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        InvestigationReportError,
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(error),
        ) from error

    raise error


@router.post(
    "/export",
    response_class=Response,
)
def export_investigation_report(
    request: InvestigationReportGenerationRequest,
    current_user: InvestigationReportReadUser,
    db: Session = Depends(get_db),
) -> Response:
    try:
        if (
            request.format
            == InvestigationReportFormat.pdf
        ):
            artifact = (
                export_investigation_report_pdf(
                    db=db,
                    request=request,
                    generated_by_user_id=(
                        current_user.id
                    ),
                )
            )

        elif (
            request.format
            == InvestigationReportFormat.json
        ):
            artifact = (
                export_investigation_report_json(
                    db=db,
                    request=request,
                    generated_by_user_id=(
                        current_user.id
                    ),
                )
            )

        else:
            raise InvestigationReportFormatError(
                "The requested report format "
                "is not supported."
            )

        headers = {
            "Content-Disposition": (
                "attachment; "
                f'filename="{artifact.result.filename}"'
            ),
            "X-Report-Id": str(
                artifact.result.report_id
            ),
            "X-Case-Id": str(
                artifact.result.case_id
            ),
            "X-Summary-Id": str(
                artifact.result.summary_id
            ),
            "X-Report-Format": (
                artifact.result.format.value
            ),
            "X-Document-SHA256": (
                artifact.result.document_sha256
            ),
        }

        return Response(
            content=artifact.content,
            media_type=(
                artifact.result.media_type
            ),
            headers=headers,
        )

    except (
        InvestigationSummaryNotFoundError,
        SummaryTraceabilityCaseNotFoundError,
        SummaryTraceabilityReportNotFoundError,
        InvestigationReportFormatError,
        InvestigationReportCaseMismatchError,
        InvestigationReportIntegrityError,
        InvestigationReportError,
        SummaryTraceabilityIntegrityError,
        SummaryTraceabilityQueryError,
    ) as error:
        raise_report_http_error(error)

    raise RuntimeError(
        "Unexpected investigation report "
        "export state."
    )