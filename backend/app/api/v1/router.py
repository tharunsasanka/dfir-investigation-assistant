from fastapi import APIRouter

from app.api.v1 import (
    administration,
    auth,
    cases,
    dashboard,
    event_correlations,
    evidence,
    forensic_timeline,
    investigation_reports,
    investigation_summaries,
    log_ingestion,
    security_findings,
    summary_traceability,
)


api_router = APIRouter()


@api_router.get(
    "/health",
    tags=["health"],
)
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
    }


api_router.include_router(
    auth.router,
)

api_router.include_router(
    administration.router,
)

api_router.include_router(
    cases.router,
)

api_router.include_router(
    dashboard.router,
)

api_router.include_router(
    evidence.router,
)

api_router.include_router(
    log_ingestion.router,
)

api_router.include_router(
    security_findings.router,
)

api_router.include_router(
    event_correlations.router,
)

api_router.include_router(
    forensic_timeline.router,
)

api_router.include_router(
    investigation_summaries.router,
)

api_router.include_router(
    investigation_reports.router,
)