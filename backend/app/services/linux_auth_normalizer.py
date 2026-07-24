import re
from typing import Any


SSH_ACCEPTED_PATTERN = re.compile(
    r"^Accepted "
    r"(?P<method>\S+) "
    r"for (?P<username>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+)",
    re.IGNORECASE,
)

SSH_FAILED_PATTERN = re.compile(
    r"^Failed "
    r"(?P<method>\S+) "
    r"for "
    r"(?:(?P<invalid_user>invalid user)\s+)?"
    r"(?P<username>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+)",
    re.IGNORECASE,
)

SSH_INVALID_USER_PATTERN = re.compile(
    r"^Invalid user "
    r"(?P<username>\S+) "
    r"from (?P<source_ip>\S+)"
    r"(?: port (?P<source_port>\d+))?",
    re.IGNORECASE,
)

SESSION_OPEN_PATTERN = re.compile(
    r"session opened for user "
    r"(?P<target_user>\S+) "
    r"by "
    r"(?P<actor>[^(\s]+)?"
    r"(?:\(uid=(?P<uid>\d+)\))?",
    re.IGNORECASE,
)

SESSION_CLOSE_PATTERN = re.compile(
    r"session closed for user "
    r"(?P<target_user>\S+)",
    re.IGNORECASE,
)

SUDO_COMMAND_PATTERN = re.compile(
    r"^(?P<username>\S+)\s*:\s*"
    r"TTY=(?P<tty>[^;]+)\s*;\s*"
    r"PWD=(?P<pwd>[^;]+)\s*;\s*"
    r"USER=(?P<target_user>[^;]+)\s*;\s*"
    r"COMMAND=(?P<command>.+)$",
    re.IGNORECASE,
)

NEW_USER_PATTERN = re.compile(
    r"new user:\s*"
    r"name=(?P<username>[^,\s]+),\s*"
    r"UID=(?P<uid>\d+),\s*"
    r"GID=(?P<gid>\d+),\s*"
    r"home=(?P<home>[^,\s]+),\s*"
    r"shell=(?P<shell>\S+)",
    re.IGNORECASE,
)

PASSWORD_CHANGED_PATTERN = re.compile(
    r"password changed for "
    r"(?P<username>\S+)",
    re.IGNORECASE,
)

DISCONNECT_PATTERN = re.compile(
    r"(?:Received disconnect from|"
    r"Disconnected from)"
    r"\s+(?P<source_ip>\S+)",
    re.IGNORECASE,
)


def _clean_process_name(
    process_name: str,
) -> str:
    process = process_name.strip()

    if "[" in process:
        process = process.split(
            "[",
            maxsplit=1,
        )[0]

    return process.lower()


def looks_like_linux_auth_record(
    process_name: str,
    message: str,
) -> bool:
    process = _clean_process_name(
        process_name
    )

    known_processes = {
        "sshd",
        "sudo",
        "su",
        "login",
        "useradd",
        "adduser",
        "passwd",
        "pam_unix",
        "systemd-logind",
    }

    if process in known_processes:
        return True

    lowered_message = message.lower()

    indicators = (
        "accepted password for",
        "accepted publickey for",
        "failed password for",
        "invalid user",
        "session opened for user",
        "session closed for user",
        "new user:",
        "password changed for",
        "command=",
    )

    return any(
        indicator in lowered_message
        for indicator in indicators
    )


def _base_result(
    *,
    timestamp: str | None,
    host: str,
    process_name: str,
    message: str,
) -> dict[str, Any]:
    return {
        "timestamp": timestamp or "",
        "event_id": "linux.auth.generic",
        "severity": "unknown",
        "host": host,
        "username": "",
        "process_name": process_name,
        "source_ip": "",
        "destination_ip": "",
        "message": message,
        "service": (
            _clean_process_name(
                process_name
            )
            or "linux-auth"
        ),
        "action": "unknown",
        "outcome": "unknown",
        "authentication_method": "",
        "source_port": "",
        "target_user": "",
        "command": "",
        "metadata": {},
    }


def normalize_linux_auth_record(
    *,
    timestamp: str | None,
    host: str,
    process_name: str,
    message: str,
) -> dict[str, Any]:
    result = _base_result(
        timestamp=timestamp,
        host=host,
        process_name=process_name,
        message=message,
    )

    process = _clean_process_name(
        process_name
    )

    accepted_match = (
        SSH_ACCEPTED_PATTERN.search(
            message
        )
    )

    if accepted_match:
        values = accepted_match.groupdict()

        result.update(
            {
                "event_id": (
                    "linux.auth.ssh.accepted"
                ),
                "severity": (
                    "informational"
                ),
                "username": (
                    values["username"]
                ),
                "source_ip": (
                    values["source_ip"]
                ),
                "action": (
                    "authentication"
                ),
                "outcome": "success",
                "authentication_method": (
                    values["method"]
                ),
                "source_port": (
                    values["source_port"]
                ),
                "target_user": (
                    values["username"]
                ),
            }
        )

        return result

    failed_match = (
        SSH_FAILED_PATTERN.search(
            message
        )
    )

    if failed_match:
        values = failed_match.groupdict()

        invalid_user = bool(
            values.get(
                "invalid_user"
            )
        )

        result.update(
            {
                "event_id": (
                    "linux.auth.ssh."
                    "invalid_user"
                    if invalid_user
                    else (
                        "linux.auth.ssh."
                        "failed"
                    )
                ),
                "severity": (
                    "high"
                    if invalid_user
                    else "medium"
                ),
                "username": (
                    values["username"]
                ),
                "source_ip": (
                    values["source_ip"]
                ),
                "action": (
                    "authentication"
                ),
                "outcome": "failure",
                "authentication_method": (
                    values["method"]
                ),
                "source_port": (
                    values["source_port"]
                ),
                "target_user": (
                    values["username"]
                ),
                "metadata": {
                    "invalid_user": (
                        invalid_user
                    ),
                },
            }
        )

        return result

    invalid_user_match = (
        SSH_INVALID_USER_PATTERN.search(
            message
        )
    )

    if invalid_user_match:
        values = (
            invalid_user_match.groupdict()
        )

        result.update(
            {
                "event_id": (
                    "linux.auth.ssh."
                    "invalid_user"
                ),
                "severity": "high",
                "username": (
                    values["username"]
                ),
                "source_ip": (
                    values["source_ip"]
                ),
                "action": (
                    "authentication"
                ),
                "outcome": "failure",
                "source_port": (
                    values.get(
                        "source_port"
                    )
                    or ""
                ),
                "target_user": (
                    values["username"]
                ),
                "metadata": {
                    "invalid_user": True,
                },
            }
        )

        return result

    sudo_match = (
        SUDO_COMMAND_PATTERN.search(
            message
        )
    )

    if sudo_match:
        values = sudo_match.groupdict()

        result.update(
            {
                "event_id": (
                    "linux.auth.sudo."
                    "command"
                ),
                "severity": "medium",
                "username": (
                    values["username"]
                ),
                "action": (
                    "privilege_escalation"
                ),
                "outcome": "success",
                "target_user": (
                    values["target_user"]
                    .strip()
                ),
                "command": (
                    values["command"]
                    .strip()
                ),
                "metadata": {
                    "tty": (
                        values["tty"]
                        .strip()
                    ),
                    "working_directory": (
                        values["pwd"]
                        .strip()
                    ),
                },
            }
        )

        return result

    session_open_match = (
        SESSION_OPEN_PATTERN.search(
            message
        )
    )

    if session_open_match:
        values = (
            session_open_match.groupdict()
        )

        actor = (
            values.get("actor")
            or ""
        )

        target_user = (
            values["target_user"]
        )

        result.update(
            {
                "event_id": (
                    "linux.auth.session."
                    "opened"
                ),
                "severity": (
                    "medium"
                    if process
                    in {
                        "sudo",
                        "su",
                    }
                    else (
                        "informational"
                    )
                ),
                "username": actor,
                "action": (
                    "session_open"
                ),
                "outcome": "success",
                "target_user": (
                    target_user
                ),
                "metadata": {
                    "uid": (
                        values.get("uid")
                        or ""
                    ),
                },
            }
        )

        return result

    session_close_match = (
        SESSION_CLOSE_PATTERN.search(
            message
        )
    )

    if session_close_match:
        target_user = (
            session_close_match
            .group("target_user")
        )

        result.update(
            {
                "event_id": (
                    "linux.auth.session."
                    "closed"
                ),
                "severity": (
                    "informational"
                ),
                "username": target_user,
                "action": (
                    "session_close"
                ),
                "outcome": "success",
                "target_user": (
                    target_user
                ),
            }
        )

        return result

    new_user_match = (
        NEW_USER_PATTERN.search(
            message
        )
    )

    if new_user_match:
        values = (
            new_user_match.groupdict()
        )

        result.update(
            {
                "event_id": (
                    "linux.auth.user."
                    "created"
                ),
                "severity": "high",
                "username": (
                    values["username"]
                ),
                "action": (
                    "account_creation"
                ),
                "outcome": "success",
                "target_user": (
                    values["username"]
                ),
                "metadata": {
                    "uid": values["uid"],
                    "gid": values["gid"],
                    "home": values["home"],
                    "shell": (
                        values["shell"]
                    ),
                },
            }
        )

        return result

    password_match = (
        PASSWORD_CHANGED_PATTERN.search(
            message
        )
    )

    if password_match:
        username = (
            password_match.group(
                "username"
            )
        )

        result.update(
            {
                "event_id": (
                    "linux.auth.password."
                    "changed"
                ),
                "severity": "medium",
                "username": username,
                "action": (
                    "password_change"
                ),
                "outcome": "success",
                "target_user": username,
            }
        )

        return result

    disconnect_match = (
        DISCONNECT_PATTERN.search(
            message
        )
    )

    if disconnect_match:
        result.update(
            {
                "event_id": (
                    "linux.auth.ssh."
                    "disconnect"
                ),
                "severity": (
                    "informational"
                ),
                "source_ip": (
                    disconnect_match.group(
                        "source_ip"
                    )
                ),
                "action": "disconnect",
                "outcome": "success",
            }
        )

        return result

    if process == "sshd":
        result["event_id"] = (
            "linux.auth.ssh.event"
        )

    elif process in {
        "sudo",
        "su",
    }:
        result["event_id"] = (
            "linux.auth."
            f"{process}.event"
        )

    return result