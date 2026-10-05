import math
import uuid
from datetime import datetime, timezone
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
    get_current_user,
    get_permission_names,
    require_permission,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.administration import (
    PasswordChangeRequest,
    PermissionListResponse,
    ProfileUpdateRequest,
    RoleListResponse,
    UserListResponse,
    UserUnlockResponse,
)
from app.schemas.permission import PermissionRead
from app.schemas.role import RoleRead
from app.schemas.user import (
    UserCreate,
    UserRead,
    UserUpdate,
)
from app.services.role_service import (
    list_permissions,
    list_roles,
)
from app.services.user_service import (
    EmailAlreadyExistsError,
    InactiveRoleAssignmentError,
    InvalidCurrentPasswordError,
    PasswordReuseError,
    RoleNotFoundError,
    UserNotFoundError,
    change_password,
    create_user,
    get_user_with_roles,
    list_users,
    unlock_user,
    update_profile,
    update_user,
)


router = APIRouter(
    tags=["Administration"],
)

DatabaseSession = Annotated[
    Session,
    Depends(get_db),
]

CurrentUser = Annotated[
    User,
    Depends(get_current_user),
]

UsersReader = Annotated[
    User,
    Depends(
        require_permission(
            "users.read"
        )
    ),
]

UsersManager = Annotated[
    User,
    Depends(
        require_permission(
            "users.manage"
        )
    ),
]

RolesReader = Annotated[
    User,
    Depends(
        require_permission(
            "roles.read"
        )
    ),
]


def _ensure_role_assignment_allowed(
    current_user: User,
    role_ids: list[uuid.UUID] | None,
    *,
    allow_empty: bool,
) -> None:
    if role_ids is None:
        return

    if allow_empty and not role_ids:
        return

    if current_user.is_superuser:
        return

    permission_names = (
        get_permission_names(
            current_user
        )
    )

    if "roles.manage" not in permission_names:
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "Role assignment requires "
                "the roles.manage permission."
            ),
        )


def _raise_user_service_error(
    error: Exception,
) -> None:
    if isinstance(
        error,
        EmailAlreadyExistsError,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        (
            RoleNotFoundError,
            InactiveRoleAssignmentError,
        ),
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        UserNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        InvalidCurrentPasswordError,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        PasswordReuseError,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    raise error


def _protect_superuser_account(
    target_user: User,
    acting_user: User,
) -> None:
    if (
        target_user.is_superuser
        and not acting_user.is_superuser
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Only a superuser can manage "
                "another superuser account."
            ),
        )


@router.get(
    "/users",
    response_model=UserListResponse,
)
def read_users(
    db: DatabaseSession,
    _: UsersReader,
    page: Annotated[
        int,
        Query(ge=1),
    ] = 1,
    page_size: Annotated[
        int,
        Query(ge=1, le=100),
    ] = 20,
    search: Annotated[
        str | None,
        Query(max_length=255),
    ] = None,
    is_active: Annotated[
        bool | None,
        Query(),
    ] = None,
) -> UserListResponse:
    users, total = list_users(
        db,
        page=page,
        page_size=page_size,
        search=search,
        is_active=is_active,
    )

    pages = (
        math.ceil(
            total / page_size
        )
        if total > 0
        else 0
    )

    return UserListResponse(
        items=[
            UserRead.model_validate(
                user
            )
            for user in users
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
def create_system_user(
    user_data: UserCreate,
    db: DatabaseSession,
    current_user: UsersManager,
) -> UserRead:
    _ensure_role_assignment_allowed(
        current_user,
        user_data.role_ids,
        allow_empty=True,
    )

    try:
        user = create_user(
            db,
            user_data,
        )

    except (
        EmailAlreadyExistsError,
        InactiveRoleAssignmentError,
        RoleNotFoundError,
    ) as error:
        _raise_user_service_error(
            error
        )

    return UserRead.model_validate(
        user
    )


@router.get(
    "/users/{user_id}",
    response_model=UserRead,
)
def read_user(
    user_id: uuid.UUID,
    db: DatabaseSession,
    _: UsersReader,
) -> UserRead:
    user = get_user_with_roles(
        db,
        user_id,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "The requested user "
                "does not exist."
            ),
        )

    return UserRead.model_validate(
        user
    )


@router.patch(
    "/users/{user_id}",
    response_model=UserRead,
)
def update_system_user(
    user_id: uuid.UUID,
    user_data: UserUpdate,
    db: DatabaseSession,
    current_user: UsersManager,
) -> UserRead:
    target_user = get_user_with_roles(
        db,
        user_id,
    )

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "The requested user "
                "does not exist."
            ),
        )

    _protect_superuser_account(
        target_user,
        current_user,
    )

    if (
        user_data.is_superuser
        is not None
        and not current_user.is_superuser
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Only a superuser can change "
                "superuser status."
            ),
        )

    if (
        target_user.id
        == current_user.id
        and user_data.is_active
        is False
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "You cannot deactivate "
                "your own account."
            ),
        )

    if (
        target_user.id
        == current_user.id
        and user_data.is_superuser
        is False
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "You cannot remove your own "
                "superuser status."
            ),
        )

    _ensure_role_assignment_allowed(
        current_user,
        user_data.role_ids,
        allow_empty=False,
    )

    try:
        updated_user = update_user(
            db,
            user_id,
            user_data,
        )

    except (
        EmailAlreadyExistsError,
        InactiveRoleAssignmentError,
        RoleNotFoundError,
        UserNotFoundError,
    ) as error:
        _raise_user_service_error(
            error
        )

    return UserRead.model_validate(
        updated_user
    )


@router.post(
    "/users/{user_id}/unlock",
    response_model=UserUnlockResponse,
)
def unlock_system_user(
    user_id: uuid.UUID,
    db: DatabaseSession,
    current_user: UsersManager,
) -> UserUnlockResponse:
    target_user = get_user_with_roles(
        db,
        user_id,
    )

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "The requested user "
                "does not exist."
            ),
        )

    _protect_superuser_account(
        target_user,
        current_user,
    )

    try:
        unlocked_user = unlock_user(
            db,
            user_id,
        )

    except UserNotFoundError as error:
        _raise_user_service_error(
            error
        )

    unlocked_at = datetime.now(
        timezone.utc
    )

    return UserUnlockResponse(
        user=UserRead.model_validate(
            unlocked_user
        ),
        unlocked_at=unlocked_at,
        message=(
            "The user account was "
            "unlocked successfully."
        ),
    )


@router.get(
    "/roles",
    response_model=RoleListResponse,
)
def read_roles(
    db: DatabaseSession,
    _: RolesReader,
    is_active: Annotated[
        bool | None,
        Query(),
    ] = None,
) -> RoleListResponse:
    roles = list_roles(
        db,
        is_active=is_active,
    )

    return RoleListResponse(
        items=[
            RoleRead.model_validate(
                role
            )
            for role in roles
        ],
        total=len(roles),
    )


@router.get(
    "/permissions",
    response_model=PermissionListResponse,
)
def read_permissions(
    db: DatabaseSession,
    _: RolesReader,
    is_active: Annotated[
        bool | None,
        Query(),
    ] = None,
) -> PermissionListResponse:
    permissions = list_permissions(
        db,
        is_active=is_active,
    )

    return PermissionListResponse(
        items=[
            PermissionRead.model_validate(
                permission
            )
            for permission
            in permissions
        ],
        total=len(
            permissions
        ),
    )


@router.patch(
    "/profile",
    response_model=UserRead,
)
def update_current_profile(
    profile_data: ProfileUpdateRequest,
    db: DatabaseSession,
    current_user: CurrentUser,
) -> UserRead:
    try:
        user = update_profile(
            db,
            current_user.id,
            profile_data,
        )

    except UserNotFoundError as error:
        _raise_user_service_error(
            error
        )

    return UserRead.model_validate(
        user
    )


@router.post(
    "/profile/password",
    response_model=dict[str, str],
)
def change_current_password(
    password_data: PasswordChangeRequest,
    db: DatabaseSession,
    current_user: CurrentUser,
) -> dict[str, str]:
    try:
        change_password(
            db,
            current_user.id,
            password_data,
        )

    except (
        UserNotFoundError,
        InvalidCurrentPasswordError,
        PasswordReuseError,
    ) as error:
        _raise_user_service_error(
            error
        )

    return {
        "message": (
            "Password changed successfully."
        ),
    }