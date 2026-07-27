from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.investigation_summary import (
    InvestigationSummary,
)
from app.models.summary_traceability import (
    InvestigationSummaryTraceabilityReport,
)
from app.services.summary_traceability_persistence_service import (
    persist_summary_traceability_report,
)


def commit_summary_with_traceability(
    db: Session,
    summary: InvestigationSummary,
    investigation_case: Case,
) -> InvestigationSummaryTraceabilityReport:
    try:
        db.flush()

        report = (
            persist_summary_traceability_report(
                db=db,
                summary=summary,
                investigation_case=(
                    investigation_case
                ),
            )
        )

        db.commit()
        db.refresh(summary)
        db.refresh(report)

        return report

    except Exception:
        db.rollback()
        raise