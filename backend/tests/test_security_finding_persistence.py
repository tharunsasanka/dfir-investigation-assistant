import uuid
from datetime import (
    datetime,
    timezone,
)

from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.services.log_ingestion_service import (
    create_security_finding_model,
)
from app.services.log_parser import (
    ParsedRecord,
)
from app.services.security_event_detector import (
    detect_single_event,
)


def test_create_security_finding_model() -> None:
    event_time = datetime(
        2026,
        7,
        24,
        10,
        30,
        tzinfo=timezone.utc,
    )

    parsed_record = ParsedRecord(
        event_index=7,
        event_time=event_time,
        source_type="windows_event",
        event_code="4688",
        severity=(
            LogEventSeverity
            .informational
        ),
        host="WORKSTATION-01",
        username="eric.fischer",
        process_name=(
            "C:\\Windows\\System32"
            "\\WindowsPowerShell"
            "\\v1.0\\powershell.exe"
        ),
        source_ip="",
        destination_ip="",
        message=(
            "powershell.exe "
            "-EncodedCommand SQBFAFgA"
        ),
        raw_event={},
        normalized_event={
            "command_line": (
                "powershell.exe "
                "-EncodedCommand "
                "SQBFAFgA"
            )
        },
        parse_error=None,
    )

    detections = detect_single_event(
        parsed_record
    )

    detection = next(
        item
        for item in detections
        if item.rule_id
        == "WINDOWS-ENCODED-COMMAND"
    )

    case_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    ingestion_job_id = uuid.uuid4()
    parsed_event_id = uuid.uuid4()

    finding = (
        create_security_finding_model(
            case_id=case_id,
            evidence_id=evidence_id,
            ingestion_job_id=(
                ingestion_job_id
            ),
            parsed_event_id=(
                parsed_event_id
            ),
            detection=detection,
        )
    )

    assert finding.case_id == case_id

    assert (
        finding.evidence_id
        == evidence_id
    )

    assert (
        finding.ingestion_job_id
        == ingestion_job_id
    )

    assert (
        finding.parsed_event_id
        == parsed_event_id
    )

    assert finding.event_index == 7

    assert (
        finding.rule_id
        == "WINDOWS-ENCODED-COMMAND"
    )

    assert (
        finding.severity
        == LogEventSeverity.high
    )

    assert finding.confidence == 95

    assert (
        finding.mitre_technique_id
        == "T1059.001"
    )

    assert (
        finding.event_time
        == event_time
    )

    assert (
        "-encodedcommand"
        in finding.indicators[
            "matched_terms"
        ]
    )