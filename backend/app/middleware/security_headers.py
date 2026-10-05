from starlette.datastructures import (
    MutableHeaders,
)
from starlette.types import (
    ASGIApp,
    Message,
    Receive,
    Scope,
    Send,
)


STRICT_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)

DOCUMENTATION_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' "
    "https://cdn.jsdelivr.net; "
    "style-src 'self' "
    "'unsafe-inline' "
    "https://cdn.jsdelivr.net; "
    "img-src 'self' data: "
    "https://fastapi.tiangolo.com; "
    "font-src 'self' data: "
    "https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        hsts_enabled: bool,
        hsts_max_age_seconds: int,
    ) -> None:
        self.app = app
        self.hsts_enabled = hsts_enabled
        self.hsts_max_age_seconds = (
            hsts_max_age_seconds
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(
                scope,
                receive,
                send,
            )
            return

        path = str(
            scope.get(
                "path",
                "",
            )
        )

        async def send_with_headers(
            message: Message,
        ) -> None:
            if (
                message["type"]
                == "http.response.start"
            ):
                headers = MutableHeaders(
                    scope=message
                )

                headers[
                    "X-Content-Type-Options"
                ] = "nosniff"

                headers[
                    "X-Frame-Options"
                ] = "DENY"

                headers[
                    "Referrer-Policy"
                ] = "no-referrer"

                headers[
                    "Permissions-Policy"
                ] = (
                    "camera=(), "
                    "microphone=(), "
                    "geolocation=(), "
                    "payment=(), "
                    "usb=()"
                )

                headers[
                    "Cross-Origin-Opener-Policy"
                ] = "same-origin"

                headers[
                    "Cross-Origin-Resource-Policy"
                ] = "same-site"

                headers[
                    "X-DNS-Prefetch-Control"
                ] = "off"

                if path in {
                    "/docs",
                    "/redoc",
                }:
                    headers[
                        "Content-Security-Policy"
                    ] = (
                        DOCUMENTATION_CONTENT_SECURITY_POLICY
                    )
                else:
                    headers[
                        "Content-Security-Policy"
                    ] = (
                        STRICT_CONTENT_SECURITY_POLICY
                    )

                if path.startswith(
                    "/api/v1/auth/"
                ):
                    headers[
                        "Cache-Control"
                    ] = (
                        "no-store, "
                        "max-age=0"
                    )

                    headers[
                        "Pragma"
                    ] = "no-cache"

                    headers[
                        "Expires"
                    ] = "0"

                if self.hsts_enabled:
                    headers[
                        "Strict-Transport-Security"
                    ] = (
                        "max-age="
                        f"{self.hsts_max_age_seconds}; "
                        "includeSubDomains"
                    )

            await send(message)

        await self.app(
            scope,
            receive,
            send_with_headers,
        )