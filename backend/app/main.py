from fastapi import FastAPI
from fastapi.middleware.cors import (
    CORSMiddleware,
)
from starlette.middleware.trustedhost import (
    TrustedHostMiddleware,
)

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.middleware.security_headers import (
    SecurityHeadersMiddleware,
)


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    docs_url=(
        "/docs"
        if settings.api_docs_enabled
        else None
    ),
    redoc_url=(
        "/redoc"
        if settings.api_docs_enabled
        else None
    ),
    openapi_url=(
        "/openapi.json"
        if settings.api_docs_enabled
        else None
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=(
        settings.cors_origin_list
    ),
    allow_credentials=(
        settings.cors_allow_credentials
    ),
    allow_methods=(
        settings.cors_allowed_method_list
    ),
    allow_headers=(
        settings.cors_allowed_header_list
    ),
    expose_headers=(
        settings.cors_exposed_header_list
    ),
    max_age=600,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=(
        settings.trusted_host_list
    ),
)

if settings.security_headers_enabled:
    app.add_middleware(
        SecurityHeadersMiddleware,
        hsts_enabled=(
            settings.hsts_active
        ),
        hsts_max_age_seconds=(
            settings.hsts_max_age_seconds
        ),
    )

app.include_router(
    api_router,
    prefix=settings.api_v1_prefix,
)


@app.get(
    "/",
    include_in_schema=False,
)
def root() -> dict[str, str]:
    return {
        "message": (
            "DFIR Investigation "
            "Assistant API"
        )
    }