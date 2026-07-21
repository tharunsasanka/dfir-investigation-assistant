from getpass import getpass

from pydantic import ValidationError
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.role import Role
from app.schemas.user import UserCreate
from app.services.user_service import (
    EmailAlreadyExistsError,
    create_user,
)


def main() -> None:
    db = SessionLocal()

    try:
        administrator_role = db.scalar(
            select(Role).where(Role.name == "administrator")
        )

        if administrator_role is None:
            print(
                "Administrator role not found. "
                "Run the RBAC seed command first."
            )
            return

        print("\nCreate Initial DFIR Administrator")
        print("---------------------------------")

        email = input("Email: ").strip()
        full_name = input("Full name: ").strip()

        password = getpass("Password: ")
        confirm_password = getpass("Confirm password: ")

        if password != confirm_password:
            print("Passwords do not match.")
            return

        user_data = UserCreate(
            email=email,
            full_name=full_name,
            password=password,
            role_ids=[administrator_role.id],
        )

        user = create_user(
            db=db,
            user_data=user_data,
            is_superuser=True,
        )

        print("\nAdministrator created successfully.")
        print(f"Email: {user.email}")
        print(f"User ID: {user.id}")

    except ValidationError as error:
        print("\nThe administrator information is invalid:")
        print(error)

    except EmailAlreadyExistsError:
        print("\nA user with this email address already exists.")

    except Exception as error:
        db.rollback()
        print(f"\nAdministrator creation failed: {error}")

    finally:
        db.close()


if __name__ == "__main__":
    main()