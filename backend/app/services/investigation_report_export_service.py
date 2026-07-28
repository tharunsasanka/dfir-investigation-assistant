import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.schemas.investigation_report import (
    InvestigationReportDocument,
    InvestigationReportExportResult,
    InvestigationReportFormat,
    InvestigationReportGenerationRequest,
    InvestigationReportStatus,
)
from app.services.investigation_report_service import (
    build_investigation_report_document,
)


class InvestigationReportExportError(Exception):
    pass


class InvestigationReportFormatError(
    InvestigationReportExportError
):
    pass


@dataclass(frozen=True)
class InvestigationReportArtifact:
    content: bytes
    result: InvestigationReportExportResult


def calculate_bytes_sha256(
    content: bytes,
) -> str:
    return hashlib.sha256(
        content
    ).hexdigest()


def safe_filename_component(
    value: str,
) -> str:
    normalized = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        value.strip(),
    )

    normalized = normalized.strip(
        "-._"
    )

    if not normalized:
        return "investigation"

    return normalized[:100]


def remove_evidence_hashes(
    payload: dict,
) -> None:
    summary = payload.get("summary")

    if isinstance(summary, dict):
        evidence_references = (
            summary.get(
                "evidence_references"
            )
        )

        if isinstance(
            evidence_references,
            list,
        ):
            for reference in (
                evidence_references
            ):
                if isinstance(
                    reference,
                    dict,
                ):
                    reference.pop(
                        "sha256",
                        None,
                    )

    traceability = payload.get(
        "traceability"
    )

    if not isinstance(
        traceability,
        dict,
    ):
        return

    claims = traceability.get(
        "claims"
    )

    if not isinstance(
        claims,
        list,
    ):
        return

    for claim in claims:
        if not isinstance(
            claim,
            dict,
        ):
            continue

        citations = claim.get(
            "citations"
        )

        if not isinstance(
            citations,
            list,
        ):
            continue

        for citation in citations:
            if isinstance(
                citation,
                dict,
            ):
                citation.pop(
                    "integrity_sha256",
                    None,
                )


def build_report_export_payload(
    document: InvestigationReportDocument,
    request: InvestigationReportGenerationRequest,
) -> dict:
    payload = document.model_dump(
        mode="json"
    )

    summary = payload.get(
        "summary"
    )

    if isinstance(summary, dict):
        if not request.include_recommendations:
            summary[
                "recommended_actions"
            ] = []

        if not request.include_assumptions:
            summary[
                "assumptions"
            ] = []

        if not request.include_limitations:
            summary[
                "limitations"
            ] = []

    if not request.include_traceability:
        payload["traceability"] = None

    if (
        not request
        .include_integrity_verification
    ):
        payload["integrity"] = None

    if not request.include_evidence_hashes:
        remove_evidence_hashes(
            payload
        )

    payload["export_options"] = (
        request.model_dump(
            mode="json"
        )
    )

    return payload


def serialize_report_json(
    payload: dict,
) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        separators=(",", ": "),
    ).encode("utf-8")


def build_report_filename(
    document: InvestigationReportDocument,
) -> str:
    case_name = safe_filename_component(
        document.case.title
    )

    version_number = (
        document.summary.version_number
    )

    report_identifier = str(
        document.report_id
    )[:8]

    return (
        f"{case_name}-"
        f"summary-v{version_number}-"
        f"{report_identifier}.json"
    )


def export_investigation_report_json(
    db: Session,
    request: InvestigationReportGenerationRequest,
    generated_by_user_id:
        uuid.UUID | None,
    generated_at:
        datetime | None = None,
) -> InvestigationReportArtifact:
    if (
        request.format
        != InvestigationReportFormat.json
    ):
        raise InvestigationReportFormatError(
            "The JSON exporter only accepts "
            "the JSON report format."
        )

    document = (
        build_investigation_report_document(
            db=db,
            request=request,
            generated_by_user_id=(
                generated_by_user_id
            ),
            generated_at=generated_at,
        )
    )

    payload = build_report_export_payload(
        document=document,
        request=request,
    )

    content = serialize_report_json(
        payload
    )

    result = (
        InvestigationReportExportResult(
            report_id=document.report_id,
            case_id=document.case.case_id,
            summary_id=(
                document.summary.id
            ),
            format=(
                InvestigationReportFormat
                .json
            ),
            status=(
                InvestigationReportStatus
                .completed
            ),
            filename=build_report_filename(
                document
            ),
            media_type=(
                "application/json"
            ),
            size_bytes=len(content),
            document_sha256=(
                calculate_bytes_sha256(
                    content
                )
            ),
            generated_at=(
                document.generated_at
            ),
        )
    )

    return InvestigationReportArtifact(
        content=content,
        result=result,
    )