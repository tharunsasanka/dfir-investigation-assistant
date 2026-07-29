import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.dependencies import require_permission
from app.db.session import get_db
from app.models.case import Case
from app.models.evidence import (
    Evidence,
    EvidenceCustodyEvent,
    EvidenceCustodyEventType,
    EvidenceType,
)
from app.models.user import User
from app.schemas.evidence import (
    EvidenceCustodyEventListResponse,
    EvidenceCustodyEventRead,
    EvidenceIntegrityResponse,
    EvidenceListResponse,
    EvidenceRead,
)
from app.services.evidence_service import (
    record_evidence_custody_event,
)
from app.services.evidence_storage import (
    EvidenceTooLargeError,
    InvalidEvidenceFilenameError,
    calculate_file_integrity,
    get_evidence_path,
    remove_evidence_file,
    save_evidence_upload,
)


router = APIRouter(
    tags=["evidence"],
)

EVIDENCE_DOWNLOAD_MEDIA_TYPE = (
    "application/octet-stream"
)


def build_evidence_download_filename(
    value: str,
    evidence_id: uuid.UUID,
) -> str:
    normalized_value = value.replace(
        "\\",
        "/",
    )

    filename = Path(
        normalized_value
    ).name

    filename = "".join(
        character
        for character in filename
        if (
            ord(character) >= 32
            and ord(character) != 127
        )
    ).strip()

    if filename in {
        "",
        ".",
        "..",
    }:
        return (
            f"evidence-{evidence_id.hex}"
        )

    return filename[:255]



EvidenceReadUser = Annotated[
    User,
    Depends(
        require_permission("cases.read")
    ),
]

EvidenceWriteUser = Annotated[
    User,
    Depends(
        require_permission("cases.update")
    ),
]


def get_active_case(
    db: Session,
    case_id: uuid.UUID,
) -> Case | None:
    statement = select(Case).where(
        Case.id == case_id,
        Case.is_deleted.is_(False),
    )

    return db.scalar(statement)


def get_active_evidence(
    db: Session,
    evidence_id: uuid.UUID,
) -> Evidence | None:
    statement = (
        select(Evidence)
        .join(
            Case,
            Case.id == Evidence.case_id,
        )
        .where(
            Evidence.id == evidence_id,
            Case.is_deleted.is_(False),
        )
    )

    return db.scalar(statement)


@router.post(
    "/cases/{case_id}/evidence",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
)
async def upload_evidence(
    case_id: uuid.UUID,
    request: Request,
    current_user: EvidenceWriteUser,
    db: Session = Depends(get_db),
    file: UploadFile = File(...),
    evidence_type: EvidenceType = Form(
        default=EvidenceType.other
    ),
    description: str = Form(
        default="",
        max_length=5000,
    ),
    source: str = Form(
        default="",
        max_length=500,
    ),
    collected_at: datetime | None = Form(
        default=None
    ),
) -> Evidence:
    investigation_case = get_active_case(
        db,
        case_id,
    )

    if investigation_case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found",
        )

    evidence_id = uuid.uuid4()

    try:
        stored_file = await save_evidence_upload(
            upload_file=file,
            case_id=case_id,
            evidence_id=evidence_id,
        )

    except InvalidEvidenceFilenameError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    except EvidenceTooLargeError as error:
        raise HTTPException(
            status_code=(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
            ),
            detail=str(error),
        ) from error

    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    except OSError as error:
        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "The evidence file could not be stored."
            ),
        ) from error

    finally:
        await file.close()

    evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        original_filename=(
            stored_file.original_filename
        ),
        stored_filename=(
            stored_file.stored_filename
        ),
        content_type=(
            file.content_type
            or "application/octet-stream"
        )[:255],
        size_bytes=stored_file.size_bytes,
        sha256=stored_file.sha256,
        evidence_type=evidence_type,
        description=description.strip(),
        source=source.strip(),
        collected_at=collected_at,
        uploaded_by_user_id=current_user.id,
    )

    try:
        db.add(evidence)
        db.flush()

        record_evidence_custody_event(
            db=db,
            evidence=evidence,
            actor=current_user,
            event_type=(
                EvidenceCustodyEventType.uploaded
            ),
            request=request,
            details={
                "original_filename": (
                    evidence.original_filename
                ),
                "size_bytes": (
                    evidence.size_bytes
                ),
                "sha256": evidence.sha256,
                "evidence_type": (
                    evidence.evidence_type.value
                ),
                "source": evidence.source,
            },
        )

        db.commit()
        db.refresh(evidence)

    except Exception:
        db.rollback()

        remove_evidence_file(
            case_id=case_id,
            stored_filename=(
                stored_file.stored_filename
            ),
        )

        raise

    return evidence


@router.get(
    "/cases/{case_id}/evidence",
    response_model=EvidenceListResponse,
)
def list_case_evidence(
    case_id: uuid.UUID,
    _current_user: EvidenceReadUser,
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    search: str | None = Query(
        default=None,
        max_length=255,
    ),
    evidence_type: EvidenceType | None = Query(
        default=None
    ),
) -> EvidenceListResponse:
    investigation_case = get_active_case(
        db,
        case_id,
    )

    if investigation_case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found",
        )

    filters = [
        Evidence.case_id == case_id,
    ]

    normalized_search = (
        search.strip()
        if search is not None
        else ""
    )

    if normalized_search:
        pattern = f"%{normalized_search}%"

        filters.append(
            or_(
                Evidence.original_filename.ilike(
                    pattern
                ),
                Evidence.description.ilike(
                    pattern
                ),
                Evidence.source.ilike(
                    pattern
                ),
                Evidence.sha256.ilike(
                    pattern
                ),
            )
        )

    if evidence_type is not None:
        filters.append(
            Evidence.evidence_type
            == evidence_type
        )

    total = int(
        db.scalar(
            select(
                func.count(Evidence.id)
            ).where(*filters)
        )
        or 0
    )

    offset = (
        page - 1
    ) * page_size

    statement = (
        select(Evidence)
        .where(*filters)
        .order_by(
            Evidence.created_at.desc(),
            Evidence.id.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )

    evidence_items = list(
        db.scalars(statement).all()
    )

    pages = (
        (
            total
            + page_size
            - 1
        )
        // page_size
        if total > 0
        else 0
    )

    return EvidenceListResponse(
        items=[
            EvidenceRead.model_validate(item)
            for item in evidence_items
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get(
    "/evidence/{evidence_id}",
    response_model=EvidenceRead,
)
def get_evidence(
    evidence_id: uuid.UUID,
    _current_user: EvidenceReadUser,
    db: Session = Depends(get_db),
) -> Evidence:
    evidence = get_active_evidence(
        db,
        evidence_id,
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )

    return evidence


@router.get(
    "/evidence/{evidence_id}/custody-events",
    response_model=(
        EvidenceCustodyEventListResponse
    ),
)
def list_evidence_custody_events(
    evidence_id: uuid.UUID,
    _current_user: EvidenceReadUser,
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
) -> EvidenceCustodyEventListResponse:
    evidence = get_active_evidence(
        db,
        evidence_id,
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )

    total = int(
        db.scalar(
            select(
                func.count(
                    EvidenceCustodyEvent.id
                )
            ).where(
                EvidenceCustodyEvent.evidence_id
                == evidence_id
            )
        )
        or 0
    )

    offset = (
        page - 1
    ) * page_size

    statement = (
        select(EvidenceCustodyEvent)
        .where(
            EvidenceCustodyEvent.evidence_id
            == evidence_id
        )
        .order_by(
            EvidenceCustodyEvent.created_at.desc(),
            EvidenceCustodyEvent.id.desc(),
        )
        .offset(offset)
        .limit(page_size)
    )

    events = list(
        db.scalars(statement).all()
    )

    pages = (
        (
            total
            + page_size
            - 1
        )
        // page_size
        if total > 0
        else 0
    )

    return EvidenceCustodyEventListResponse(
        items=[
            EvidenceCustodyEventRead.model_validate(
                event
            )
            for event in events
        ],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post(
    "/evidence/{evidence_id}/verify-integrity",
    response_model=EvidenceIntegrityResponse,
)
def verify_evidence_integrity(
    evidence_id: uuid.UUID,
    request: Request,
    current_user: EvidenceWriteUser,
    db: Session = Depends(get_db),
) -> EvidenceIntegrityResponse:
    evidence = get_active_evidence(
        db,
        evidence_id,
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )

    path = get_evidence_path(
        evidence.case_id,
        evidence.stored_filename,
    )

    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=(
                "The stored evidence file is missing."
            ),
        )

    actual_integrity = (
        calculate_file_integrity(path)
    )

    matches = (
        actual_integrity.sha256
        == evidence.sha256
        and actual_integrity.size_bytes
        == evidence.size_bytes
    )

    event_type = (
        EvidenceCustodyEventType.integrity_verified
        if matches
        else EvidenceCustodyEventType.integrity_failed
    )

    checked_at = datetime.now(timezone.utc)

    try:
        record_evidence_custody_event(
            db=db,
            evidence=evidence,
            actor=current_user,
            event_type=event_type,
            request=request,
            details={
                "matches": matches,
                "expected_sha256": (
                    evidence.sha256
                ),
                "actual_sha256": (
                    actual_integrity.sha256
                ),
                "expected_size_bytes": (
                    evidence.size_bytes
                ),
                "actual_size_bytes": (
                    actual_integrity.size_bytes
                ),
            },
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return EvidenceIntegrityResponse(
        evidence_id=evidence.id,
        matches=matches,
        expected_sha256=evidence.sha256,
        actual_sha256=(
            actual_integrity.sha256
        ),
        expected_size_bytes=(
            evidence.size_bytes
        ),
        actual_size_bytes=(
            actual_integrity.size_bytes
        ),
        checked_at=checked_at,
    )


@router.get(
    "/evidence/{evidence_id}/content",
    response_class=FileResponse,
)
def download_evidence_content(
    evidence_id: uuid.UUID,
    request: Request,
    current_user: EvidenceReadUser,
    db: Session = Depends(get_db),
) -> FileResponse:
    evidence = get_active_evidence(
        db,
        evidence_id,
    )

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )

    path: Path = get_evidence_path(
        evidence.case_id,
        evidence.stored_filename,
    )

    if not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=(
                "The stored evidence file is missing."
            ),
        )

    try:
        record_evidence_custody_event(
            db=db,
            evidence=evidence,
            actor=current_user,
            event_type=(
                EvidenceCustodyEventType.accessed
            ),
            request=request,
            details={
                "action": "download",
                "original_filename": (
                    evidence.original_filename
                ),
                "sha256": evidence.sha256,
            },
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return FileResponse(
        path=path,
        media_type=(
            EVIDENCE_DOWNLOAD_MEDIA_TYPE
        ),
        filename=(
            build_evidence_download_filename(
                evidence.original_filename,
                evidence.id,
            )
        ),
        content_disposition_type=(
            "attachment"
        ),
        headers={
            "Cache-Control":
                "no-store, private",
            "Pragma":
                "no-cache",
            "X-Content-Type-Options":
                "nosniff",
        },
    )