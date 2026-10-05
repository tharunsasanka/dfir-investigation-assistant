import logging
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse


logger = logging.getLogger(
    "app.error_handlers"
)

GENERIC_INTERNAL_ERROR_MESSAGE = (
    "An unexpected server error occurred."
)


async def unhandled_exception_handler(
    request: Request,
    exception: Exception,
) -> JSONResponse:
    error_id = uuid4().hex

    logger.error(
        (
            "Unhandled application exception "
            "error_id=%s method=%s path=%s"
        ),
        error_id,
        request.method,
        request.url.path,
        exc_info=(
            type(exception),
            exception,
            exception.__traceback__,
        ),
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": (
                GENERIC_INTERNAL_ERROR_MESSAGE
            ),
            "error_id": error_id,
        },
        headers={
            "Cache-Control":
                "no-store, max-age=0",
            "Pragma":
                "no-cache",
            "X-Content-Type-Options":
                "nosniff",
            "X-Error-ID":
                error_id,
        },
    )
