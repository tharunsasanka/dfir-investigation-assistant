import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models.evidence import Evidence
from app.models.log_ingestion import (
    LogIngestionJob,
    LogIngestionStatus,
    ParsedLogEvent,
)
from app.models.security_finding import (
    SecurityFinding,
)
from app.services.log_parser import (
    ParsedRecord,
    parse_log_file,
)
from app.services.security_event_detector import (
    SecurityDetection,
    detect_security_events,
)


BATCH_SIZE = 500


def create_event_model(
    *,
    job: LogIngestionJob,
    evidence: Evidence,
    parsed_record: ParsedRecord,
) -> ParsedLogEvent:
    return ParsedLogEvent(
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        ingestion_job_id=job.id,
        event_index=(
            parsed_record.event_index
        ),
        event_time=(
            parsed_record.event_time
        ),
        source_type=(
            parsed_record.source_type
        ),
        event_code=(
            parsed_record.event_code
        ),
        severity=(
            parsed_record.severity
        ),
        host=parsed_record.host,
        username=parsed_record.username,
        process_name=(
            parsed_record.process_name
        ),
        source_ip=(
            parsed_record.source_ip
        ),
        destination_ip=(
            parsed_record.destination_ip
        ),
        message=parsed_record.message,
        raw_event=parsed_record.raw_event,
        normalized_event=(
            parsed_record.normalized_event
        ),
        parse_error=(
            parsed_record.parse_error
        ),
    )


def create_security_finding_model(
    *,
    case_id: uuid.UUID,
    evidence_id: uuid.UUID,
    ingestion_job_id: uuid.UUID,
    parsed_event_id: uuid.UUID,
    detection: SecurityDetection,
) -> SecurityFinding:
    return SecurityFinding(
        case_id=case_id,
        evidence_id=evidence_id,
        ingestion_job_id=(
            ingestion_job_id
        ),
        parsed_event_id=(
            parsed_event_id
        ),
        event_index=(
            detection.event_index
        ),
        rule_id=detection.rule_id,
        title=detection.title,
        description=(
            detection.description
        ),
        severity=detection.severity,
        confidence=(
            detection.confidence
        ),
        event_time=(
            detection.event_time
        ),
        event_code=(
            detection.event_code
        ),
        source_type=(
            detection.source_type
        ),
        mitre_tactic=(
            detection.mitre_tactic
        ),
        mitre_technique_id=(
            detection.mitre_technique_id
        ),
        mitre_technique_name=(
            detection.mitre_technique_name
        ),
        indicators=(
            detection.indicators
        ),
    )


def _flush_event_batch(
    *,
    db: Session,
    event_batch: list[
        ParsedLogEvent
    ],
    parsed_event_ids: dict[
        int,
        uuid.UUID,
    ],
) -> None:
    if not event_batch:
        return

    db.add_all(event_batch)
    db.flush()

    for event_model in event_batch:
        parsed_event_ids[
            event_model.event_index
        ] = event_model.id

    event_batch.clear()


def _flush_finding_batch(
    *,
    db: Session,
    finding_batch: list[
        SecurityFinding
    ],
) -> None:
    if not finding_batch:
        return

    db.add_all(finding_batch)
    db.flush()
    finding_batch.clear()


def run_log_ingestion(
    *,
    db: Session,
    job: LogIngestionJob,
    evidence: Evidence,
    evidence_path: Path,
) -> LogIngestionJob:
    job.status = (
        LogIngestionStatus.processing
    )

    job.started_at = datetime.now(
        timezone.utc
    )

    job.completed_at = None
    job.error_message = None

    job.total_records = 0
    job.parsed_records = 0
    job.failed_records = 0
    job.processed_bytes = 0

    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        db.execute(
            delete(
                SecurityFinding
            ).where(
                SecurityFinding
                .ingestion_job_id
                == job.id
            )
        )

        db.execute(
            delete(
                ParsedLogEvent
            ).where(
                ParsedLogEvent
                .ingestion_job_id
                == job.id
            )
        )

        (
            detected_format,
            parsed_records_iterator,
        ) = parse_log_file(
            path=evidence_path,
            original_filename=(
                evidence.original_filename
            ),
            requested_format=(
                job.requested_format
            ),
        )

        job.detected_format = (
            detected_format
        )

        job.processed_bytes = (
            evidence_path.stat().st_size
        )

        event_batch: list[
            ParsedLogEvent
        ] = []

        parsed_records_buffer: list[
            ParsedRecord
        ] = []

        parsed_event_ids: dict[
            int,
            uuid.UUID,
        ] = {}

        total_records = 0
        parsed_records = 0
        failed_records = 0

        for parsed_record in (
            parsed_records_iterator
        ):
            total_records += 1

            parsed_records_buffer.append(
                parsed_record
            )

            if parsed_record.parse_error:
                failed_records += 1
            else:
                parsed_records += 1

            event_batch.append(
                create_event_model(
                    job=job,
                    evidence=evidence,
                    parsed_record=(
                        parsed_record
                    ),
                )
            )

            if (
                len(event_batch)
                >= BATCH_SIZE
            ):
                _flush_event_batch(
                    db=db,
                    event_batch=(
                        event_batch
                    ),
                    parsed_event_ids=(
                        parsed_event_ids
                    ),
                )

        _flush_event_batch(
            db=db,
            event_batch=event_batch,
            parsed_event_ids=(
                parsed_event_ids
            ),
        )

        detections = (
            detect_security_events(
                parsed_records_buffer
            )
        )

        finding_batch: list[
            SecurityFinding
        ] = []

        for detection in detections:
            parsed_event_id = (
                parsed_event_ids.get(
                    detection.event_index
                )
            )

            if parsed_event_id is None:
                raise RuntimeError(
                    "A security detection "
                    "could not be linked to "
                    "its parsed log event."
                )

            finding_batch.append(
                create_security_finding_model(
                    case_id=evidence.case_id,
                    evidence_id=evidence.id,
                    ingestion_job_id=job.id,
                    parsed_event_id=(
                        parsed_event_id
                    ),
                    detection=detection,
                )
            )

            if (
                len(finding_batch)
                >= BATCH_SIZE
            ):
                _flush_finding_batch(
                    db=db,
                    finding_batch=(
                        finding_batch
                    ),
                )

        _flush_finding_batch(
            db=db,
            finding_batch=(
                finding_batch
            ),
        )

        job.total_records = (
            total_records
        )

        job.parsed_records = (
            parsed_records
        )

        job.failed_records = (
            failed_records
        )

        if failed_records > 0:
            job.status = (
                LogIngestionStatus
                .completed_with_errors
            )
        else:
            job.status = (
                LogIngestionStatus
                .completed
            )

        job.completed_at = datetime.now(
            timezone.utc
        )

        db.add(job)
        db.commit()
        db.refresh(job)

        return job

    except Exception as error:
        db.rollback()

        failed_job = db.get(
            LogIngestionJob,
            job.id,
        )

        if failed_job is None:
            raise

        failed_job.status = (
            LogIngestionStatus.failed
        )

        failed_job.error_message = str(
            error
        )[:5000]

        failed_job.completed_at = (
            datetime.now(timezone.utc)
        )

        db.add(failed_job)
        db.commit()
        db.refresh(failed_job)

        return failed_job