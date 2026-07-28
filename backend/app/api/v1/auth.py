import uuid
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from sqlalchemy import select
from sqlalchemy.orm import (
    Session,
    selectinload,
)

from app.api.dependencies import (
    get_current_user,
)
from app.core.config import get_settings
from app.db.session import get_db
from app.models.role import Role
from app.models.user import User
from app.schemas.auth import (
    AccessTokenResponse,
    LoginRequest,
    LogoutRequest,
    LogoutResponse,
    RefreshTokenRequest,
    TokenResponse,
)
from app.schemas.user import UserRead
from app.services.auth_service import (
    AccountLockedError,
    InactiveAccountError,
    InvalidCredentialsError,
    authenticate_user,
)
from app.services.auth_session_service import (
    InvalidRefreshTokenError,
    RefreshTokenReuseError,
    create_auth_session,
    revoke_auth_session,
    rotate_refresh_token,
)
from app.services.login_rate_limit_service import (
    LoginRateLimitExceededError,
    clear_login_rate_limit,
    enforce_login_rate_limit,
    record_failed_login_attempt,
)


router = APIRouter(
    prefix="/auth",
    tags=[
        "Authentication",
    ],
)

settings = get_settings()

DatabaseSession = Annotated[
    Session,
    Depends(
        get_db
    ),
]

CurrentUser = Annotated[
    User,
    Depends(
        get_current_user
    ),
]


def get_user_with_roles(
    db: Session,
    user_id: uuid.UUID,
) -> User | None:
    statement = (
        select(User)
        .options(
            selectinload(
                User.roles
            ).selectinload(
                Role.permissions
            )
        )
        .where(
            User.id == user_id
        )
    )

    return db.scalar(
        statement
    )


def raise_rate_limit_error(
    error: LoginRateLimitExceededError,
) -> None:
    raise HTTPException(
        status_code=(
            status
            .HTTP_429_TOO_MANY_REQUESTS
        ),
        detail=(
            "Too many authentication "
            "attempts. Try again later."
        ),
        headers={
            "Retry-After": str(
                error.retry_after_seconds
            )
        },
    ) from error


def record_failed_request(
    db: Session,
    request: Request,
) -> None:
    try:
        record_failed_login_attempt(
            db,
            request,
        )
    except (
        LoginRateLimitExceededError
    ) as error:
        raise_rate_limit_error(
            error
        )


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(
    login_data: LoginRequest,
    request: Request,
    db: DatabaseSession,
) -> TokenResponse:
    try:
        enforce_login_rate_limit(
            db,
            request,
        )

    except (
        LoginRateLimitExceededError
    ) as error:
        raise_rate_limit_error(
            error
        )

    try:
        authenticated_user = (
            authenticate_user(
                db=db,
                email=str(
                    login_data.email
                ),
                password=(
                    login_data.password
                ),
            )
        )

    except InvalidCredentialsError as error:
        record_failed_request(
            db,
            request,
        )

        raise HTTPException(
            status_code=(
                status
                .HTTP_401_UNAUTHORIZED
            ),
            detail=(
                "The email address or "
                "password is incorrect."
            ),
            headers={
                "WWW-Authenticate":
                    "Bearer"
            },
        ) from error

    except InactiveAccountError as error:
        record_failed_request(
            db,
            request,
        )

        raise HTTPException(
            status_code=(
                status
                .HTTP_403_FORBIDDEN
            ),
            detail=(
                "This user account "
                "is inactive."
            ),
        ) from error

    except AccountLockedError as error:
        record_failed_request(
            db,
            request,
        )

        raise HTTPException(
            status_code=423,
            detail=(
                "This account is "
                "temporarily locked."
            ),
        ) from error

    clear_login_rate_limit(
        db,
        request,
    )

    user = get_user_with_roles(
        db,
        authenticated_user.id,
    )

    if user is None:
        raise HTTPException(
            status_code=(
                status
                .HTTP_401_UNAUTHORIZED
            ),
            detail=(
                "Could not load the "
                "authenticated user."
            ),
        )

    issued_tokens = (
        create_auth_session(
            db,
            user,
            request,
        )
    )

    return TokenResponse(
        access_token=(
            issued_tokens
            .access_token
        ),
        refresh_token=(
            issued_tokens
            .refresh_token
        ),
        expires_in=(
            settings
            .access_token_expire_minutes
            * 60
        ),
        user=UserRead.model_validate(
            user
        ),
    )


@router.post(
    "/refresh",
    response_model=(
        AccessTokenResponse
    ),
)
def refresh_access_token(
    refresh_data: RefreshTokenRequest,
    db: DatabaseSession,
) -> AccessTokenResponse:
    credentials_error = HTTPException(
        status_code=(
            status
            .HTTP_401_UNAUTHORIZED
        ),
        detail=(
            "The refresh token is "
            "invalid or expired."
        ),
        headers={
            "WWW-Authenticate":
                "Bearer"
        },
    )

    try:
        issued_tokens = (
            rotate_refresh_token(
                db,
                refresh_data.refresh_token,
            )
        )

    except (
        InvalidRefreshTokenError,
        RefreshTokenReuseError,
    ) as error:
        raise credentials_error from error

    return AccessTokenResponse(
        access_token=(
            issued_tokens
            .access_token
        ),
        refresh_token=(
            issued_tokens
            .refresh_token
        ),
        expires_in=(
            settings
            .access_token_expire_minutes
            * 60
        ),
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
)
def logout(
    logout_data: LogoutRequest,
    db: DatabaseSession,
) -> LogoutResponse:
    revoke_auth_session(
        db,
        logout_data.refresh_token,
    )

    return LogoutResponse(
        message=(
            "The authentication "
            "session was ended."
        )
    )


@router.get(
    "/me",
    response_model=UserRead,
)
def read_current_user(
    current_user: CurrentUser,
) -> UserRead:
    return UserRead.model_validate(
        current_user
    )