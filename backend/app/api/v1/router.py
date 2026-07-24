from fastapi import APIRouter, status

from app.api.v1 import (
    auth,
    cases,
    dashboard,
    evidence,
    log_ingestion,
)


api_router = APIRouter()


@api_router.get(
    "/health",
    tags=["health"],
    status_code=status.HTTP_200_OK,
)
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
    }


api_router.include_router(auth.router)
api_router.include_router(cases.router)
api_router.include_router(dashboard.router)
api_router.include_router(evidence.router)
api_router.include_router(
    log_ingestion.router,
)