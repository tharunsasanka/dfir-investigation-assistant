from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from app.models.log_ingestion import (
    LogEventSeverity,
)
from app.services.log_parser import (
    ParsedRecord,
)


@dataclass(frozen=True)
class SecurityDetection:
    rule_id: str
    title: str
    description: str

    severity: LogEventSeverity
    confidence: int

    event_index: int
    event_code: str
    source_type: str
    event_time: datetime | None

    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str

    indicators: dict[str, Any]


FAILED_AUTH_EVENT_CODES = {
    "4625",
    "linux.auth.ssh.failed",
    "linux.auth.ssh.invalid_user",
}

SUCCESSFUL_AUTH_EVENT_CODES = {
    "4624",
    "linux.auth.ssh.accepted",
}

SUSPICIOUS_WINDOWS_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

SUSPICIOUS_COMMAND_TERMS = {
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex ",
    "invoke-webrequest",
    "iwr ",
    "curl ",
    "wget ",
    "certutil",
    "bitsadmin",
    "rundll32",
    "regsvr32",
    "mshta",
    "javascript:",
}


def _lower_text(value: Any) -> str:
    if value is None:
        return ""

    return str(value).strip().lower()


def _event_search_text(
    event: ParsedRecord,
) -> str:
    values = [
        event.message,
        event.process_name,
        event.event_code,
        event.raw_event,
        event.normalized_event,
    ]

    return " ".join(
        _lower_text(value)
        for value in values
        if value
    )


def _normalized_value(
    event: ParsedRecord,
    key: str,
) -> Any:
    return event.normalized_event.get(key)


def _create_detection(
    *,
    event: ParsedRecord,
    rule_id: str,
    title: str,
    description: str,
    severity: LogEventSeverity,
    confidence: int,
    mitre_tactic: str,
    mitre_technique_id: str,
    mitre_technique_name: str,
    indicators: dict[str, Any],
) -> SecurityDetection:
    return SecurityDetection(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        confidence=max(
            0,
            min(confidence, 100),
        ),
        event_index=event.event_index,
        event_code=event.event_code,
        source_type=event.source_type,
        event_time=event.event_time,
        mitre_tactic=mitre_tactic,
        mitre_technique_id=(
            mitre_technique_id
        ),
        mitre_technique_name=(
            mitre_technique_name
        ),
        indicators=indicators,
    )


def _detect_windows_failed_logon(
    event: ParsedRecord,
) -> SecurityDetection | None:
    if event.event_code != "4625":
        return None

    return _create_detection(
        event=event,
        rule_id="WINDOWS-LOGON-FAILURE",
        title="Windows logon failure",
        description=(
            "Windows recorded an unsuccessful "
            "account logon attempt."
        ),
        severity=LogEventSeverity.medium,
        confidence=95,
        mitre_tactic="Credential Access",
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        indicators={
            "username": event.username,
            "source_ip": event.source_ip,
            "host": event.host,
        },
    )


def _detect_linux_auth_failure(
    event: ParsedRecord,
) -> SecurityDetection | None:
    supported_codes = {
        "linux.auth.ssh.failed",
        "linux.auth.ssh.invalid_user",
    }

    if event.event_code not in supported_codes:
        return None

    invalid_user = (
        event.event_code
        == "linux.auth.ssh.invalid_user"
    )

    return _create_detection(
        event=event,
        rule_id=(
            "AUTH-INVALID-USER"
            if invalid_user
            else "AUTH-FAILURE"
        ),
        title=(
            "Authentication attempt for invalid user"
            if invalid_user
            else "Failed authentication attempt"
        ),
        description=(
            "A login attempt targeted an account "
            "that does not appear to exist."
            if invalid_user
            else (
                "A user authentication attempt "
                "was unsuccessful."
            )
        ),
        severity=(
            LogEventSeverity.high
            if invalid_user
            else LogEventSeverity.medium
        ),
        confidence=(
            95
            if invalid_user
            else 90
        ),
        mitre_tactic="Credential Access",
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        indicators={
            "username": event.username,
            "source_ip": event.source_ip,
            "host": event.host,
            "process_name": (
                event.process_name
            ),
        },
    )


def _detect_windows_process(
    event: ParsedRecord,
) -> SecurityDetection | None:
    if event.event_code != "4688":
        return None

    process_name = _lower_text(
        event.process_name
    )

    process_basename = (
        process_name
        .replace("\\", "/")
        .split("/")[-1]
    )

    event_text = _event_search_text(event)

    suspicious_process = (
        process_basename
        in SUSPICIOUS_WINDOWS_PROCESSES
    )

    matched_terms = sorted(
        term
        for term in SUSPICIOUS_COMMAND_TERMS
        if term in event_text
    )

    if (
        not suspicious_process
        and not matched_terms
    ):
        return None

    encoded_command = any(
        term in event_text
        for term in {
            "-enc",
            "-encodedcommand",
            "frombase64string",
        }
    )

    if encoded_command:
        rule_id = (
            "WINDOWS-ENCODED-COMMAND"
        )
        title = (
            "Encoded Windows command execution"
        )
        description = (
            "A Windows process creation event "
            "contains patterns associated with "
            "encoded or obfuscated execution."
        )
        severity = LogEventSeverity.high
        confidence = 95

    elif matched_terms:
        rule_id = (
            "WINDOWS-SUSPICIOUS-COMMAND"
        )
        title = (
            "Suspicious Windows command execution"
        )
        description = (
            "A Windows process creation event "
            "contains potentially dangerous "
            "command-line behavior."
        )
        severity = LogEventSeverity.high
        confidence = 90

    else:
        rule_id = (
            "WINDOWS-SUSPICIOUS-PROCESS"
        )
        title = (
            "Suspicious Windows process created"
        )
        description = (
            "A Windows process commonly used "
            "during administrative or attacker "
            "activity was created."
        )
        severity = LogEventSeverity.medium
        confidence = 75

    powershell_process = (
        "powershell" in process_basename
        or process_basename == "pwsh.exe"
    )

    return _create_detection(
        event=event,
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        mitre_tactic="Execution",
        mitre_technique_id=(
            "T1059.001"
            if powershell_process
            else "T1059"
        ),
        mitre_technique_name=(
            "PowerShell"
            if powershell_process
            else (
                "Command and Scripting Interpreter"
            )
        ),
        indicators={
            "process_name": (
                event.process_name
            ),
            "username": event.username,
            "host": event.host,
            "matched_terms": matched_terms,
        },
    )


def _detect_sudo_command(
    event: ParsedRecord,
) -> SecurityDetection | None:
    if (
        event.event_code
        != "linux.auth.sudo.command"
    ):
        return None

    command_value = _normalized_value(
        event,
        "command",
    )

    command = _lower_text(
        command_value
    )

    high_risk_terms = {
        "/etc/shadow",
        "/etc/sudoers",
        "useradd",
        "adduser",
        "passwd",
        "chmod 777",
        "chown root",
        "systemctl disable",
        "iptables -f",
    }

    matched_terms = sorted(
        term
        for term in high_risk_terms
        if term in command
    )

    high_risk = bool(matched_terms)

    return _create_detection(
        event=event,
        rule_id=(
            "LINUX-SUDO-HIGH-RISK"
            if high_risk
            else "LINUX-SUDO-COMMAND"
        ),
        title=(
            "High-risk sudo command"
            if high_risk
            else "Privileged sudo command"
        ),
        description=(
            "A sudo command accessed or modified "
            "a security-sensitive Linux resource."
            if high_risk
            else (
                "A command was executed with "
                "elevated Linux privileges."
            )
        ),
        severity=(
            LogEventSeverity.high
            if high_risk
            else LogEventSeverity.medium
        ),
        confidence=(
            95
            if high_risk
            else 85
        ),
        mitre_tactic="Privilege Escalation",
        mitre_technique_id="T1548.003",
        mitre_technique_name=(
            "Sudo and Sudo Caching"
        ),
        indicators={
            "username": event.username,
            "target_user": (
                _normalized_value(
                    event,
                    "target_user",
                )
            ),
            "command": command_value,
            "host": event.host,
            "matched_terms": matched_terms,
        },
    )


def _detect_linux_account_creation(
    event: ParsedRecord,
) -> SecurityDetection | None:
    if (
        event.event_code
        != "linux.auth.user.created"
    ):
        return None

    return _create_detection(
        event=event,
        rule_id="LINUX-ACCOUNT-CREATED",
        title="Linux user account created",
        description=(
            "A new local Linux user account "
            "was created on the system."
        ),
        severity=LogEventSeverity.high,
        confidence=95,
        mitre_tactic="Persistence",
        mitre_technique_id="T1136.001",
        mitre_technique_name="Local Account",
        indicators={
            "username": event.username,
            "target_user": (
                _normalized_value(
                    event,
                    "target_user",
                )
            ),
            "host": event.host,
            "metadata": (
                _normalized_value(
                    event,
                    "metadata",
                )
            ),
        },
    )


def detect_single_event(
    event: ParsedRecord,
) -> list[SecurityDetection]:
    detectors = (
        _detect_windows_failed_logon,
        _detect_linux_auth_failure,
        _detect_windows_process,
        _detect_sudo_command,
        _detect_linux_account_creation,
    )

    detections: list[
        SecurityDetection
    ] = []

    seen_rule_ids: set[str] = set()

    for detector in detectors:
        detection = detector(event)

        if detection is None:
            continue

        if (
            detection.rule_id
            in seen_rule_ids
        ):
            continue

        detections.append(detection)
        seen_rule_ids.add(
            detection.rule_id
        )

    return detections


def _group_failed_authentications(
    events: list[ParsedRecord],
) -> dict[
    tuple[str, str],
    list[ParsedRecord],
]:
    grouped: dict[
        tuple[str, str],
        list[ParsedRecord],
    ] = defaultdict(list)

    for event in events:
        if (
            event.event_code
            not in FAILED_AUTH_EVENT_CODES
        ):
            continue

        source_ip = (
            event.source_ip
            or "unknown-source"
        )

        username = (
            event.username
            or "unknown-user"
        )

        grouped[
            (
                source_ip,
                username,
            )
        ].append(event)

    return grouped


def _detect_brute_force(
    events: list[ParsedRecord],
) -> list[SecurityDetection]:
    findings: list[
        SecurityDetection
    ] = []

    grouped = (
        _group_failed_authentications(
            events
        )
    )

    threshold = 5
    time_window = timedelta(
        minutes=10
    )

    for (
        source_ip,
        username,
    ), grouped_events in grouped.items():
        timed_events = sorted(
            (
                event
                for event in grouped_events
                if event.event_time
                is not None
            ),
            key=lambda item: (
                item.event_time.timestamp()
                if item.event_time
                else 0
            ),
        )

        for start_index, start_event in (
            enumerate(timed_events)
        ):
            start_time = (
                start_event.event_time
            )

            if start_time is None:
                continue

            matching_events: list[
                ParsedRecord
            ] = []

            for candidate in timed_events[
                start_index:
            ]:
                if (
                    candidate.event_time
                    is None
                ):
                    continue

                difference = (
                    candidate.event_time
                    - start_time
                )

                if difference > time_window:
                    break

                matching_events.append(
                    candidate
                )

            if (
                len(matching_events)
                < threshold
            ):
                continue

            final_event = (
                matching_events[-1]
            )

            findings.append(
                _create_detection(
                    event=final_event,
                    rule_id=(
                        "AUTH-BRUTE-FORCE"
                    ),
                    title=(
                        "Possible authentication "
                        "brute-force attack"
                    ),
                    description=(
                        f"{len(matching_events)} "
                        "failed authentication "
                        "attempts occurred within "
                        "10 minutes."
                    ),
                    severity=(
                        LogEventSeverity.high
                    ),
                    confidence=95,
                    mitre_tactic=(
                        "Credential Access"
                    ),
                    mitre_technique_id=(
                        "T1110"
                    ),
                    mitre_technique_name=(
                        "Brute Force"
                    ),
                    indicators={
                        "source_ip": source_ip,
                        "username": username,
                        "attempt_count": (
                            len(
                                matching_events
                            )
                        ),
                        "window_minutes": 10,
                        "first_event_index": (
                            matching_events[
                                0
                            ].event_index
                        ),
                        "last_event_index": (
                            final_event.event_index
                        ),
                    },
                )
            )

            break

    return findings


def _detect_success_after_failures(
    events: list[ParsedRecord],
) -> list[SecurityDetection]:
    findings: list[
        SecurityDetection
    ] = []

    failures: dict[
        tuple[str, str],
        list[ParsedRecord],
    ] = defaultdict(list)

    ordered_events = sorted(
        events,
        key=lambda item: (
            item.event_time.timestamp()
            if item.event_time
            else float("inf")
        ),
    )

    for event in ordered_events:
        key = (
            event.source_ip
            or "unknown-source",
            event.username
            or "unknown-user",
        )

        if (
            event.event_code
            in FAILED_AUTH_EVENT_CODES
        ):
            failures[key].append(event)
            continue

        if (
            event.event_code
            not in SUCCESSFUL_AUTH_EVENT_CODES
        ):
            continue

        if event.event_time is None:
            continue

        recent_failures = [
            failure
            for failure in failures.get(
                key,
                [],
            )
            if (
                failure.event_time
                is not None
                and timedelta(0)
                <= (
                    event.event_time
                    - failure.event_time
                )
                <= timedelta(minutes=15)
            )
        ]

        if len(recent_failures) < 3:
            continue

        findings.append(
            _create_detection(
                event=event,
                rule_id=(
                    "AUTH-SUCCESS-AFTER-FAILURES"
                ),
                title=(
                    "Successful authentication "
                    "after repeated failures"
                ),
                description=(
                    "A successful login followed "
                    "multiple failed authentication "
                    "attempts from the same source."
                ),
                severity=(
                    LogEventSeverity.critical
                ),
                confidence=95,
                mitre_tactic=(
                    "Credential Access"
                ),
                mitre_technique_id=(
                    "T1110"
                ),
                mitre_technique_name=(
                    "Brute Force"
                ),
                indicators={
                    "source_ip": (
                        event.source_ip
                    ),
                    "username": (
                        event.username
                    ),
                    "failure_count": (
                        len(recent_failures)
                    ),
                    "success_event_index": (
                        event.event_index
                    ),
                },
            )
        )

    return findings


def detect_security_events(
    records: Iterable[ParsedRecord],
) -> list[SecurityDetection]:
    events = list(records)

    findings: list[
        SecurityDetection
    ] = []

    for event in events:
        findings.extend(
            detect_single_event(event)
        )

    findings.extend(
        _detect_brute_force(events)
    )

    findings.extend(
        _detect_success_after_failures(
            events
        )
    )

    return sorted(
        findings,
        key=lambda finding: (
            (
                finding.event_time.timestamp()
                if finding.event_time
                else float("inf")
            ),
            finding.event_index,
            finding.rule_id,
        ),
    )