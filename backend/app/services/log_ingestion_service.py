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
from app.services.log_parser import (
    ParsedRecord,
    parse_log_file,
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
        event_time=parsed_record.event_time,
        source_type=(
            parsed_record.source_type
        ),
        event_code=(
            parsed_record.event_code
        ),
        severity=parsed_record.severity,
        host=parsed_record.host,
        username=parsed_record.username,
        process_name=(
            parsed_record.process_name
        ),
        source_ip=parsed_record.source_ip,
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

    job.error_message = None

    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        db.execute(
            delete(ParsedLogEvent).where(
                ParsedLogEvent.ingestion_job_id
                == job.id
            )
        )

        detected_format, records = (
            parse_log_file(
                path=evidence_path,
                original_filename=(
                    evidence.original_filename
                ),
                requested_format=(
                    job.requested_format
                ),
            )
        )

        job.detected_format = detected_format
        job.processed_bytes = (
            evidence_path.stat().st_size
        )

        batch: list[ParsedLogEvent] = []

        total_records = 0
        parsed_records = 0
        failed_records = 0

        for record in records:
            total_records += 1

            if record.parse_error:
                failed_records += 1
            else:
                parsed_records += 1

            batch.append(
                create_event_model(
                    job=job,
                    evidence=evidence,
                    parsed_record=record,
                )
            )

            if len(batch) >= BATCH_SIZE:
                db.add_all(batch)
                db.flush()
                batch.clear()

        if batch:
            db.add_all(batch)
            db.flush()

        job.total_records = total_records
        job.parsed_records = parsed_records
        job.failed_records = failed_records

        if failed_records > 0:
            job.status = (
                LogIngestionStatus
                .completed_with_errors
            )
        else:
            job.status = (
                LogIngestionStatus.completed
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
            datetime.now(
                timezone.utc
            )
        )

        db.add(failed_job)
        db.commit()
        db.refresh(failed_job)

        return failed_job