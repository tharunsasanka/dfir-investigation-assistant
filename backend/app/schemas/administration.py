from datetime import datetime

from pydantic import (
    BaseModel,
    Field,
    field_validator,
)

from app.schemas.permission import PermissionRead
from app.schemas.role import RoleRead
from app.schemas.user import UserRead


class UserListResponse(BaseModel):
    items: list[UserRead] = Field(
        default_factory=list,
    )
    total: int = Field(
        ge=0,
    )
    page: int = Field(
        ge=1,
    )
    page_size: int = Field(
        ge=1,
        le=100,
    )
    pages: int = Field(
        ge=0,
    )


class RoleListResponse(BaseModel):
    items: list[RoleRead] = Field(
        default_factory=list,
    )
    total: int = Field(
        ge=0,
    )


class PermissionListResponse(BaseModel):
    items: list[PermissionRead] = Field(
        default_factory=list,
    )
    total: int = Field(
        ge=0,
    )


class UserUnlockResponse(BaseModel):
    user: UserRead
    unlocked_at: datetime
    message: str


class ProfileUpdateRequest(BaseModel):
    full_name: str = Field(
        min_length=2,
        max_length=150,
    )

    @field_validator(
        "full_name",
    )
    @classmethod
    def normalize_full_name(
        cls,
        value: str,
    ) -> str:
        normalized = value.strip()

        if len(normalized) < 2:
            raise ValueError(
                "Full name must contain at least two characters."
            )

        return normalized


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(
        min_length=1,
        max_length=128,
    )
    new_password: str = Field(
        min_length=12,
        max_length=128,
    )
    confirm_password: str = Field(
        min_length=12,
        max_length=128,
    )

    @field_validator(
        "new_password",
    )
    @classmethod
    def validate_new_password(
        cls,
        password: str,
    ) -> str:
        if not any(
            character.islower()
            for character in password
        ):
            raise ValueError(
                "Password must contain a lowercase letter."
            )

        if not any(
            character.isupper()
            for character in password
        ):
            raise ValueError(
                "Password must contain an uppercase letter."
            )

        if not any(
            character.isdigit()
            for character in password
        ):
            raise ValueError(
                "Password must contain a number."
            )

        if password.isalnum():
            raise ValueError(
                "Password must contain a special character."
            )

        return password

    @field_validator(
        "confirm_password",
    )
    @classmethod
    def validate_confirmation(
        cls,
        confirmation: str,
        info,
    ) -> str:
        new_password = (
            info.data.get(
                "new_password"
            )
        )

        if (
            new_password is not None
            and confirmation
            != new_password
        ):
            raise ValueError(
                "Password confirmation does not match."
            )

        return confirmation