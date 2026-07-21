import hashlib
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import UploadFile


CHUNK_SIZE = 1024 * 1024

DEFAULT_MAX_UPLOAD_BYTES = (
    100 * 1024 * 1024
)


class InvalidEvidenceFilenameError(
    ValueError
):
    pass


class EvidenceTooLargeError(ValueError):
    pass


@dataclass(frozen=True)
class StoredEvidenceFile:
    original_filename: str
    stored_filename: str
    size_bytes: int
    sha256: str
    path: Path


@dataclass(frozen=True)
class FileIntegrity:
    size_bytes: int
    sha256: str


def get_storage_root() -> Path:
    configured_root = os.getenv(
        "EVIDENCE_STORAGE_ROOT",
        "/app/evidence_storage",
    )

    storage_root = Path(
        configured_root
    ).resolve()

    storage_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    return storage_root


def get_max_upload_bytes() -> int:
    configured_value = os.getenv(
        "EVIDENCE_MAX_UPLOAD_BYTES",
    )

    if configured_value is None:
        return DEFAULT_MAX_UPLOAD_BYTES

    try:
        value = int(configured_value)
    except ValueError:
        return DEFAULT_MAX_UPLOAD_BYTES

    if value <= 0:
        return DEFAULT_MAX_UPLOAD_BYTES

    return value


def normalize_original_filename(
    filename: str | None,
) -> str:
    if filename is None:
        raise InvalidEvidenceFilenameError(
            "The uploaded file requires a filename."
        )

    if "\x00" in filename:
        raise InvalidEvidenceFilenameError(
            "The uploaded filename is invalid."
        )

    normalized = Path(filename).name.strip()

    if not normalized:
        raise InvalidEvidenceFilenameError(
            "The uploaded file requires a filename."
        )

    if len(normalized) > 255:
        raise InvalidEvidenceFilenameError(
            "The uploaded filename is too long."
        )

    return normalized


def get_evidence_path(
    case_id: uuid.UUID,
    stored_filename: str,
) -> Path:
    if (
        Path(stored_filename).name
        != stored_filename
    ):
        raise ValueError(
            "Invalid stored evidence filename."
        )

    storage_root = get_storage_root()

    case_directory = (
        storage_root / str(case_id)
    ).resolve()

    if storage_root not in case_directory.parents:
        raise ValueError(
            "Invalid evidence storage path."
        )

    case_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    evidence_path = (
        case_directory / stored_filename
    ).resolve()

    if case_directory not in evidence_path.parents:
        raise ValueError(
            "Invalid evidence storage path."
        )

    return evidence_path


async def save_evidence_upload(
    *,
    upload_file: UploadFile,
    case_id: uuid.UUID,
    evidence_id: uuid.UUID,
) -> StoredEvidenceFile:
    original_filename = (
        normalize_original_filename(
            upload_file.filename
        )
    )

    stored_filename = evidence_id.hex

    final_path = get_evidence_path(
        case_id,
        stored_filename,
    )

    temporary_path = final_path.with_name(
        f"{stored_filename}.part"
    )

    digest = hashlib.sha256()
    size_bytes = 0
    max_upload_bytes = get_max_upload_bytes()

    try:
        with temporary_path.open("xb") as output:
            while True:
                chunk = await upload_file.read(
                    CHUNK_SIZE
                )

                if not chunk:
                    break

                size_bytes += len(chunk)

                if size_bytes > max_upload_bytes:
                    raise EvidenceTooLargeError(
                        "The evidence file exceeds "
                        "the configured upload limit."
                    )

                digest.update(chunk)
                output.write(chunk)

        if size_bytes == 0:
            raise ValueError(
                "Empty evidence files are not accepted."
            )

        temporary_path.replace(final_path)

    except Exception:
        temporary_path.unlink(
            missing_ok=True
        )

        final_path.unlink(
            missing_ok=True
        )

        raise

    return StoredEvidenceFile(
        original_filename=original_filename,
        stored_filename=stored_filename,
        size_bytes=size_bytes,
        sha256=digest.hexdigest(),
        path=final_path,
    )


def calculate_file_integrity(
    path: Path,
) -> FileIntegrity:
    digest = hashlib.sha256()
    size_bytes = 0

    with path.open("rb") as input_file:
        while True:
            chunk = input_file.read(
                CHUNK_SIZE
            )

            if not chunk:
                break

            size_bytes += len(chunk)
            digest.update(chunk)

    return FileIntegrity(
        size_bytes=size_bytes,
        sha256=digest.hexdigest(),
    )


def remove_evidence_file(
    *,
    case_id: uuid.UUID,
    stored_filename: str,
) -> None:
    evidence_path = get_evidence_path(
        case_id,
        stored_filename,
    )

    evidence_path.unlink(
        missing_ok=True
    )

    case_directory = evidence_path.parent

    try:
        case_directory.rmdir()
    except OSError:
        pass