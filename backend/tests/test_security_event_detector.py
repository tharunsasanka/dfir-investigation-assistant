from datetime import datetime, timedelta, timezone
from typing import Any

from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.services.log_parser import (
    ParsedRecord,
)
from app.services.security_event_detector import (
    detect_security_events,
    detect_single_event,
)


BASE_TIME = datetime(
    2026,
    7,
    24,
    8,
    0,
    0,
    tzinfo=timezone.utc,
)


def make_event(
    *,
    event_index: int,
    event_code: str,
    source_type: str = "windows_event",
    event_time: datetime | None = None,
    severity: LogEventSeverity = (
        LogEventSeverity.unknown
    ),
    host: str = "LAB-HOST-01",
    username: str = "",
    process_name: str = "",
    source_ip: str = "",
    destination_ip: str = "",
    message: str = "",
    raw_event: dict[str, Any] | None = None,
    normalized_event: dict[str, Any] | None = None,
) -> ParsedRecord:
    return ParsedRecord(
        event_index=event_index,
        event_time=event_time,
        source_type=source_type,
        event_code=event_code,
        severity=severity,
        host=host,
        username=username,
        process_name=process_name,
        source_ip=source_ip,
        destination_ip=destination_ip,
        message=message,
        raw_event=raw_event or {},
        normalized_event=(
            normalized_event or {}
        ),
        parse_error=None,
    )


def find_detection(
    detections: list[Any],
    rule_id: str,
) -> Any:
    return next(
        detection
        for detection in detections
        if detection.rule_id == rule_id
    )


def test_detect_windows_failed_logon() -> None:
    event = make_event(
        event_index=1,
        event_code="4625",
        event_time=BASE_TIME,
        username="administrator",
        source_ip="198.51.100.25",
        message=(
            "An account failed to log on."
        ),
    )

    detections = detect_single_event(
        event
    )

    finding = find_detection(
        detections,
        "WINDOWS-LOGON-FAILURE",
    )

    assert (
        finding.title
        == "Windows logon failure"
    )

    assert (
        finding.severity
        == LogEventSeverity.medium
    )

    assert finding.confidence == 95

    assert (
        finding.mitre_technique_id
        == "T1110"
    )

    assert (
        finding.indicators["username"]
        == "administrator"
    )

    assert (
        finding.indicators["source_ip"]
        == "198.51.100.25"
    )


def test_detect_encoded_powershell() -> None:
    event = make_event(
        event_index=2,
        event_code="4688",
        event_time=(
            BASE_TIME
            + timedelta(minutes=1)
        ),
        username="eric.fischer",
        process_name=(
            "C:\\Windows\\System32"
            "\\WindowsPowerShell"
            "\\v1.0\\powershell.exe"
        ),
        message=(
            "New process command line: "
            "powershell.exe "
            "-EncodedCommand "
            "SQBFAFgA"
        ),
        normalized_event={
            "command_line": (
                "powershell.exe "
                "-EncodedCommand "
                "SQBFAFgA"
            ),
        },
    )

    detections = detect_single_event(
        event
    )

    finding = find_detection(
        detections,
        "WINDOWS-ENCODED-COMMAND",
    )

    assert (
        finding.severity
        == LogEventSeverity.high
    )

    assert finding.confidence == 95

    assert (
        finding.mitre_tactic
        == "Execution"
    )

    assert (
        finding.mitre_technique_id
        == "T1059.001"
    )

    assert (
        finding.mitre_technique_name
        == "PowerShell"
    )

    assert (
        "-encodedcommand"
        in finding.indicators[
            "matched_terms"
        ]
    )


def test_detect_high_risk_sudo_command() -> None:
    event = make_event(
        event_index=3,
        event_code=(
            "linux.auth.sudo.command"
        ),
        source_type="linux_auth",
        event_time=(
            BASE_TIME
            + timedelta(minutes=2)
        ),
        host="linux-server-01",
        username="analyst",
        process_name="sudo",
        message=(
            "analyst executed a command "
            "with sudo privileges"
        ),
        normalized_event={
            "target_user": "root",
            "command": (
                "/usr/bin/cat "
                "/etc/shadow"
            ),
        },
    )

    detections = detect_single_event(
        event
    )

    finding = find_detection(
        detections,
        "LINUX-SUDO-HIGH-RISK",
    )

    assert (
        finding.severity
        == LogEventSeverity.high
    )

    assert finding.confidence == 95

    assert (
        finding.mitre_technique_id
        == "T1548.003"
    )

    assert (
        finding.indicators["username"]
        == "analyst"
    )

    assert (
        finding.indicators[
            "target_user"
        ]
        == "root"
    )

    assert (
        finding.indicators["command"]
        == "/usr/bin/cat /etc/shadow"
    )


def test_detect_linux_account_creation() -> None:
    event = make_event(
        event_index=4,
        event_code=(
            "linux.auth.user.created"
        ),
        source_type="linux_auth",
        event_time=(
            BASE_TIME
            + timedelta(minutes=3)
        ),
        host="linux-server-01",
        username="backupadmin",
        process_name="useradd",
        message=(
            "A new Linux user account "
            "was created."
        ),
        normalized_event={
            "target_user": "backupadmin",
            "metadata": {
                "uid": "1005",
                "gid": "1005",
                "shell": "/bin/bash",
            },
        },
    )

    detections = detect_single_event(
        event
    )

    finding = find_detection(
        detections,
        "LINUX-ACCOUNT-CREATED",
    )

    assert (
        finding.severity
        == LogEventSeverity.high
    )

    assert finding.confidence == 95

    assert (
        finding.mitre_tactic
        == "Persistence"
    )

    assert (
        finding.mitre_technique_id
        == "T1136.001"
    )

    assert (
        finding.indicators[
            "target_user"
        ]
        == "backupadmin"
    )


def test_detect_authentication_brute_force() -> None:
    events = [
        make_event(
            event_index=index + 1,
            event_code="4625",
            event_time=(
                BASE_TIME
                + timedelta(
                    minutes=index,
                )
            ),
            username="administrator",
            source_ip="203.0.113.50",
            message=(
                "An account failed "
                "to log on."
            ),
        )
        for index in range(5)
    ]

    detections = detect_security_events(
        events
    )

    finding = find_detection(
        detections,
        "AUTH-BRUTE-FORCE",
    )

    assert (
        finding.severity
        == LogEventSeverity.high
    )

    assert finding.confidence == 95

    assert (
        finding.indicators[
            "attempt_count"
        ]
        == 5
    )

    assert (
        finding.indicators[
            "window_minutes"
        ]
        == 10
    )

    assert (
        finding.indicators["source_ip"]
        == "203.0.113.50"
    )

    assert (
        finding.indicators["username"]
        == "administrator"
    )


def test_detect_success_after_failures() -> None:
    events = [
        make_event(
            event_index=1,
            event_code=(
                "linux.auth.ssh.failed"
            ),
            source_type="linux_auth",
            event_time=BASE_TIME,
            host="linux-server-01",
            username="root",
            source_ip="198.51.100.40",
            process_name="sshd",
            message=(
                "Failed password for root"
            ),
        ),
        make_event(
            event_index=2,
            event_code=(
                "linux.auth.ssh.failed"
            ),
            source_type="linux_auth",
            event_time=(
                BASE_TIME
                + timedelta(minutes=1)
            ),
            host="linux-server-01",
            username="root",
            source_ip="198.51.100.40",
            process_name="sshd",
            message=(
                "Failed password for root"
            ),
        ),
        make_event(
            event_index=3,
            event_code=(
                "linux.auth.ssh.failed"
            ),
            source_type="linux_auth",
            event_time=(
                BASE_TIME
                + timedelta(minutes=2)
            ),
            host="linux-server-01",
            username="root",
            source_ip="198.51.100.40",
            process_name="sshd",
            message=(
                "Failed password for root"
            ),
        ),
        make_event(
            event_index=4,
            event_code=(
                "linux.auth.ssh.accepted"
            ),
            source_type="linux_auth",
            event_time=(
                BASE_TIME
                + timedelta(minutes=3)
            ),
            host="linux-server-01",
            username="root",
            source_ip="198.51.100.40",
            process_name="sshd",
            message=(
                "Accepted password for root"
            ),
        ),
    ]

    detections = detect_security_events(
        events
    )

    finding = find_detection(
        detections,
        "AUTH-SUCCESS-AFTER-FAILURES",
    )

    assert (
        finding.severity
        == LogEventSeverity.critical
    )

    assert finding.confidence == 95

    assert (
        finding.indicators[
            "failure_count"
        ]
        == 3
    )

    assert (
        finding.indicators[
            "success_event_index"
        ]
        == 4
    )

    assert (
        finding.indicators["source_ip"]
        == "198.51.100.40"
    )


def test_benign_process_has_no_detection() -> None:
    event = make_event(
        event_index=5,
        event_code="4688",
        event_time=BASE_TIME,
        username="analyst",
        process_name=(
            "C:\\Windows\\explorer.exe"
        ),
        message=(
            "A new process was created."
        ),
    )

    detections = detect_single_event(
        event
    )

    assert detections == []