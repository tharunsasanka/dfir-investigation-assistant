import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.permission import PermissionRead


class RoleCreate(BaseModel):
    name: str = Field(
        min_length=3,
        max_length=100,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    description: str = Field(default="", max_length=1000)
    permission_ids: list[uuid.UUID] = Field(default_factory=list)


class RoleUpdate(BaseModel):
    name: str | None = Field(
        default=None,
        min_length=3,
        max_length=100,
        pattern=r"^[a-z][a-z0-9_-]*$",
    )
    description: str | None = Field(
        default=None,
        max_length=1000,
    )
    is_active: bool | None = None
    permission_ids: list[uuid.UUID] | None = None


class RoleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    permissions: list[PermissionRead] = Field(default_factory=list)