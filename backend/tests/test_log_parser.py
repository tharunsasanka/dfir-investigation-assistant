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
        tmp_path
        / "security.jsonl"
    )

    records = [
        {
            "timestamp": (
                "2026-07-24T10:00:00Z"
            ),
            "event_id": "4624",
            "severity": "info",
            "host": (
                "WORKSTATION-01"
            ),
            "username": "analyst",
            "source_ip": (
                "10.0.0.15"
            ),
            "message": (
                "An account was successfully "
                "logged on."
            ),
        },
        {
            "timestamp": (
                "2026-07-24T10:05:00Z"
            ),
            "event_id": "4688",
            "severity": "high",
            "host": (
                "WORKSTATION-01"
            ),
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

    (
        detected_format,
        parsed_iterator,
    ) = parse_log_file(
        path=log_path,
        original_filename=(
            "security.jsonl"
        ),
        requested_format=(
            LogFormat.auto
        ),
    )

    parsed = list(
        parsed_iterator
    )

    assert (
        detected_format
        == LogFormat.json_lines
    )

    assert len(parsed) == 2

    assert (
        parsed[0].event_code
        == "4624"
    )

    assert (
        parsed[0].host
        == "WORKSTATION-01"
    )

    assert (
        parsed[0].username
        == "analyst"
    )

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
            "destination_ip,severity,"
            "message\n"
            "2026-07-24T11:00:00Z,"
            "192.168.1.10,8.8.8.8,"
            "medium,"
            "DNS request detected\n"
        ),
        encoding="utf-8",
    )

    (
        detected_format,
        parsed_iterator,
    ) = parse_log_file(
        path=log_path,
        original_filename=(
            "network.csv"
        ),
        requested_format=(
            LogFormat.auto
        ),
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


def test_parse_windows_event_json_lines(
    tmp_path: Path,
) -> None:
    log_path = (
        tmp_path
        / "windows-events.jsonl"
    )

    windows_event = {
        "Event": {
            "System": {
                "Provider": {
                    "@Name": (
                        "Microsoft-Windows-"
                        "Security-Auditing"
                    )
                },
                "EventID": "4688",
                "Level": "4",
                "TimeCreated": {
                    "@SystemTime": (
                        "2026-07-24T12:00:00Z"
                    )
                },
                "Computer": (
                    "WORKSTATION-01"
                ),
                "Channel": "Security",
                "EventRecordID": (
                    "16001"
                ),
            },
            "EventData": {
                "Data": [
                    {
                        "@Name": (
                            "SubjectUserName"
                        ),
                        "#text": (
                            "eric.fischer"
                        ),
                    },
                    {
                        "@Name": (
                            "NewProcessName"
                        ),
                        "#text": (
                            "C:\\Windows\\System32"
                            "\\WindowsPowerShell"
                            "\\v1.0\\powershell.exe"
                        ),
                    },
                ]
            },
        },
        "Message": (
            "A new process was created."
        ),
    }

    log_path.write_text(
        json.dumps(
            windows_event
        ),
        encoding="utf-8",
    )

    (
        detected_format,
        parsed_iterator,
    ) = parse_log_file(
        path=log_path,
        original_filename=(
            "windows-events.jsonl"
        ),
        requested_format=(
            LogFormat.auto
        ),
    )

    parsed = list(
        parsed_iterator
    )

    assert (
        detected_format
        == LogFormat.json_lines
    )

    assert len(parsed) == 1

    event = parsed[0]

    assert (
        event.source_type
        == "windows_event"
    )

    assert (
        event.event_code
        == "4688"
    )

    assert (
        event.host
        == "WORKSTATION-01"
    )

    assert (
        event.username
        == "eric.fischer"
    )

    assert (
        event.process_name.endswith(
            "powershell.exe"
        )
    )

    assert (
        event.severity
        == LogEventSeverity.informational
    )

    assert (
        event.normalized_event[
            "provider"
        ]
        == (
            "Microsoft-Windows-"
            "Security-Auditing"
        )
    )

    assert (
        event.normalized_event[
            "channel"
        ]
        == "Security"
    )

    assert (
        event.normalized_event[
            "record_id"
        ]
        == "16001"
    )

    assert (
        event.normalized_event[
            "input_format"
        ]
        == "json_lines"
    )


def test_parse_linux_auth_syslog(
    tmp_path: Path,
) -> None:
    log_path = (
        tmp_path / "auth.log"
    )

    log_path.write_text(
        (
            "Jul 24 08:15:00 "
            "server-01 "
            "sshd[2150]: "
            "Accepted password for analyst "
            "from 192.168.1.25 "
            "port 52844 ssh2\n"
            "Jul 24 08:20:00 "
            "server-01 "
            "sudo[2190]: "
            "analyst : "
            "TTY=pts/0 ; "
            "PWD=/home/analyst ; "
            "USER=root ; "
            "COMMAND=/usr/bin/cat "
            "/etc/shadow\n"
        ),
        encoding="utf-8",
    )

    (
        detected_format,
        parsed_iterator,
    ) = parse_log_file(
        path=log_path,
        original_filename="auth.log",
        requested_format=(
            LogFormat.auto
        ),
    )

    parsed = list(
        parsed_iterator
    )

    assert (
        detected_format
        == LogFormat.syslog
    )

    assert len(parsed) == 2

    accepted_event = parsed[0]

    assert (
        accepted_event.source_type
        == "linux_auth"
    )

    assert (
        accepted_event.event_code
        == "linux.auth.ssh.accepted"
    )

    assert (
        accepted_event.severity
        == LogEventSeverity.informational
    )

    assert (
        accepted_event.host
        == "server-01"
    )

    assert (
        accepted_event.username
        == "analyst"
    )

    assert (
        accepted_event.source_ip
        == "192.168.1.25"
    )

    assert (
        accepted_event.normalized_event[
            "authentication_method"
        ]
        == "password"
    )

    assert (
        accepted_event.normalized_event[
            "source_port"
        ]
        == "52844"
    )

    assert (
        accepted_event.normalized_event[
            "outcome"
        ]
        == "success"
    )

    sudo_event = parsed[1]

    assert (
        sudo_event.source_type
        == "linux_auth"
    )

    assert (
        sudo_event.event_code
        == "linux.auth.sudo.command"
    )

    assert (
        sudo_event.severity
        == LogEventSeverity.medium
    )

    assert (
        sudo_event.username
        == "analyst"
    )

    assert (
        sudo_event.normalized_event[
            "target_user"
        ]
        == "root"
    )

    assert (
        sudo_event.normalized_event[
            "command"
        ]
        == (
            "/usr/bin/cat "
            "/etc/shadow"
        )
    )

    assert (
        sudo_event.normalized_event[
            "action"
        ]
        == "privilege_escalation"
    )


def test_parse_failed_linux_ssh_events(
    tmp_path: Path,
) -> None:
    log_path = (
        tmp_path / "secure"
    )

    log_path.write_text(
        (
            "Jul 24 09:00:00 "
            "server-02 "
            "sshd[3001]: "
            "Failed password for root "
            "from 198.51.100.40 "
            "port 44012 ssh2\n"
            "Jul 24 09:01:00 "
            "server-02 "
            "sshd[3002]: "
            "Invalid user administrator "
            "from 203.0.113.50 "
            "port 51222\n"
        ),
        encoding="utf-8",
    )

    (
        detected_format,
        parsed_iterator,
    ) = parse_log_file(
        path=log_path,
        original_filename="secure",
        requested_format=(
            LogFormat.auto
        ),
    )

    parsed = list(
        parsed_iterator
    )

    assert (
        detected_format
        == LogFormat.syslog
    )

    assert len(parsed) == 2

    assert (
        parsed[0].event_code
        == "linux.auth.ssh.failed"
    )

    assert (
        parsed[0].severity
        == LogEventSeverity.medium
    )

    assert (
        parsed[0].username
        == "root"
    )

    assert (
        parsed[0].source_ip
        == "198.51.100.40"
    )

    assert (
        parsed[1].event_code
        == (
            "linux.auth.ssh."
            "invalid_user"
        )
    )

    assert (
        parsed[1].severity
        == LogEventSeverity.high
    )

    assert (
        parsed[1].username
        == "administrator"
    )

    assert (
        parsed[1].source_ip
        == "203.0.113.50"
    )


def test_invalid_json_line_is_recorded(
    tmp_path: Path,
) -> None:
    log_path = (
        tmp_path
        / "partially-corrupt.jsonl"
    )

    log_path.write_text(
        (
            '{"message":"Valid event"}\n'
            '{"message": invalid}\n'
        ),
        encoding="utf-8",
    )

    (
        detected_format,
        parsed_iterator,
    ) = parse_log_file(
        path=log_path,
        original_filename=(
            "partially-corrupt.jsonl"
        ),
        requested_format=(
            LogFormat.auto
        ),
    )

    parsed = list(
        parsed_iterator
    )

    assert (
        detected_format
        == LogFormat.json_lines
    )

    assert len(parsed) == 2
    assert parsed[0].parse_error is None
    assert parsed[1].parse_error is not None