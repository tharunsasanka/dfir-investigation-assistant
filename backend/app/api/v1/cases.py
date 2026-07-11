from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.case import Case
from app.schemas.case import CaseCreate, CaseRead
from app.api.dependencies import require_permission

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("", response_model=list[CaseRead])
def list_cases(db: Session = Depends(get_db)) -> list[Case]:
    return list(db.scalars(select(Case).order_by(Case.created_at.desc())).all())


@router.post(
    "",
    response_model=CaseRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("cases.create"))],
)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)) -> Case:
    case = Case(**payload.model_dump())
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


@router.get(
    "/{case_id}",
    response_model=CaseRead,
    dependencies=[Depends(require_permission("cases.read"))],
)
def get_case(case_id: str, db: Session = Depends(get_db)) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case
