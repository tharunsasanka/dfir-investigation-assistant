import json
from pathlib import Path

from app.models.log_ingestion import (
    LogEventSeverity,
    LogFormat,
)
from app.services.log_parser import (
    parse_log_file,
)


def test_parse_json_lines(
    tmp_path: Path,
) -> None:
    log_path = (
        tmp_path / "security.jsonl"
    )

    records = [
        {
            "timestamp": (
                "2026-07-19T10:00:00Z"
            ),
            "event_id": "4624",
            "severity": "info",
            "host": "WORKSTATION-01",
            "username": "analyst",
            "source_ip": "10.0.0.15",
            "message": (
                "An account was successfully "
                "logged on."
            ),
        },
        {
            "timestamp": (
                "2026-07-19T10:05:00Z"
            ),
            "event_id": "4688",
            "severity": "high",
            "host": "WORKSTATION-01",
            "process_name": (
                "powershell.exe"
            ),
            "message": (
                "A new process was created."
            ),
        },
    ]

    log_path.write_text(
        "\n".join(
            json.dumps(record)
            for record in records
        ),
        encoding="utf-8",
    )

    detected_format, parsed_iterator = (
        parse_log_file(
            path=log_path,
            original_filename=(
                "security.jsonl"
            ),
            requested_format=(
                LogFormat.auto
            ),
        )
    )

    parsed = list(
        parsed_iterator
    )

    assert (
        detected_format
        == LogFormat.json_lines
    )

    assert len(parsed) == 2

    assert parsed[0].event_code == "4624"
    assert parsed[0].host == "WORKSTATION-01"
    assert parsed[0].username == "analyst"

    assert (
        parsed[1].process_name
        == "powershell.exe"
    )

    assert (
        parsed[1].severity
        == LogEventSeverity.high
    )


def test_parse_csv(
    tmp_path: Path,
) -> None:
    log_path = (
        tmp_path / "network.csv"
    )

    log_path.write_text(
        (
            "timestamp,source_ip,"
            "destination_ip,severity,message\n"
            "2026-07-19T11:00:00Z,"
            "192.168.1.10,8.8.8.8,"
            "medium,DNS request detected\n"
        ),
        encoding="utf-8",
    )

    detected_format, parsed_iterator = (
        parse_log_file(
            path=log_path,
            original_filename="network.csv",
            requested_format=(
                LogFormat.auto
            ),
        )
    )

    parsed = list(
        parsed_iterator
    )

    assert (
        detected_format
        == LogFormat.csv
    )

    assert len(parsed) == 1

    assert (
        parsed[0].source_ip
        == "192.168.1.10"
    )

    assert (
        parsed[0].destination_ip
        == "8.8.8.8"
    )

    assert (
        parsed[0].severity
        == LogEventSeverity.medium
    )