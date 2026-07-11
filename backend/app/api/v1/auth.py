import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from jwt import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.db.session import get_db
from app.models.role import Role
from app.models.user import User
from app.schemas.auth import (
    AccessTokenResponse,
    LoginRequest,
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


router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()

DatabaseSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]


def _get_user_with_roles(
    db: Session,
    user_id: uuid.UUID,
) -> User | None:
    statement = (
        select(User)
        .options(
            selectinload(User.roles).selectinload(Role.permissions)
        )
        .where(User.id == user_id)
    )

    return db.scalar(statement)


@router.post("/login", response_model=TokenResponse)
def login(
    login_data: LoginRequest,
    db: DatabaseSession,
) -> TokenResponse:
    try:
        authenticated_user = authenticate_user(
            db=db,
            email=str(login_data.email),
            password=login_data.password,
        )

    except InvalidCredentialsError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The email address or password is incorrect.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from error

    except InactiveAccountError as error:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This user account is inactive.",
        ) from error

    except AccountLockedError as error:
        raise HTTPException(
            status_code=423,
            detail="This account is temporarily locked.",
        ) from error

    user = _get_user_with_roles(db, authenticated_user.id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not load the authenticated user.",
        )

    subject = str(user.id)

    return TokenResponse(
        access_token=create_access_token(subject),
        refresh_token=create_refresh_token(subject),
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserRead.model_validate(user),
    )


@router.post("/refresh", response_model=AccessTokenResponse)
def refresh_access_token(
    refresh_data: RefreshTokenRequest,
    db: DatabaseSession,
) -> AccessTokenResponse:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="The refresh token is invalid or expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(
            refresh_data.refresh_token,
            expected_type="refresh",
        )

        subject = payload.get("sub")

        if not subject:
            raise credentials_error

        user_id = uuid.UUID(subject)

    except (
        InvalidTokenError,
        TypeError,
        ValueError,
    ) as error:
        raise credentials_error from error

    user = _get_user_with_roles(db, user_id)

    if user is None or not user.is_active:
        raise credentials_error

    return AccessTokenResponse(
        access_token=create_access_token(str(user.id)),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserRead)
def read_current_user(
    current_user: CurrentUser,
) -> UserRead:
    return UserRead.model_validate(current_user)