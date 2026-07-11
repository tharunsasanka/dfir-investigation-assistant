import uuid
from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
)

from app.schemas.role import RoleRead


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=150)
    password: str = Field(min_length=12, max_length=128)
    role_ids: list[uuid.UUID] = Field(default_factory=list)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, password: str) -> str:
        if not any(character.islower() for character in password):
            raise ValueError("Password must contain a lowercase letter.")

        if not any(character.isupper() for character in password):
            raise ValueError("Password must contain an uppercase letter.")

        if not any(character.isdigit() for character in password):
            raise ValueError("Password must contain a number.")

        if password.isalnum():
            raise ValueError("Password must contain a special character.")

        return password


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = Field(
        default=None,
        min_length=2,
        max_length=150,
    )
    password: str | None = Field(
        default=None,
        min_length=12,
        max_length=128,
    )
    is_active: bool | None = None
    is_superuser: bool | None = None
    role_ids: list[uuid.UUID] | None = None

    @field_validator("password")
    @classmethod
    def validate_password_strength(
        cls,
        password: str | None,
    ) -> str | None:
        if password is None:
            return password

        if not any(character.islower() for character in password):
            raise ValueError("Password must contain a lowercase letter.")

        if not any(character.isupper() for character in password):
            raise ValueError("Password must contain an uppercase letter.")

        if not any(character.isdigit() for character in password):
            raise ValueError("Password must contain a number.")

        if password.isalnum():
            raise ValueError("Password must contain a special character.")

        return password


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str
    is_active: bool
    is_superuser: bool
    failed_login_attempts: int
    locked_until: datetime | None
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime
    roles: list[RoleRead] = Field(default_factory=list)