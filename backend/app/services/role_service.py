from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.permission import Permission
from app.models.role import Role


def list_roles(
    db: Session,
    *,
    is_active: bool | None = None,
) -> list[Role]:
    statement = (
        select(Role)
        .options(
            selectinload(
                Role.permissions
            )
        )
        .order_by(
            Role.name.asc()
        )
    )

    if is_active is not None:
        statement = statement.where(
            Role.is_active
            == is_active
        )

    return list(
        db.scalars(
            statement
        ).unique().all()
    )


def list_permissions(
    db: Session,
    *,
    is_active: bool | None = None,
) -> list[Permission]:
    statement = (
        select(Permission)
        .order_by(
            Permission.name.asc()
        )
    )

    if is_active is not None:
        statement = statement.where(
            Permission.is_active
            == is_active
        )

    return list(
        db.scalars(
            statement
        ).all()
    )