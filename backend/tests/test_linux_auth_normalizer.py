from app.services.linux_auth_normalizer import (
    looks_like_linux_auth_record,
    normalize_linux_auth_record,
)


def test_accepted_ssh_password() -> None:
    message = (
        "Accepted password for analyst "
        "from 192.168.1.25 "
        "port 52844 ssh2"
    )

    assert (
        looks_like_linux_auth_record(
            "sshd",
            message,
        )
        is True
    )

    normalized = (
        normalize_linux_auth_record(
            timestamp=(
                "Jul 24 08:15:00"
            ),
            host="server-01",
            process_name="sshd",
            message=message,
        )
    )

    assert (
        normalized["event_id"]
        == "linux.auth.ssh.accepted"
    )

    assert (
        normalized["severity"]
        == "informational"
    )

    assert (
        normalized["username"]
        == "analyst"
    )

    assert (
        normalized["source_ip"]
        == "192.168.1.25"
    )

    assert (
        normalized[
            "authentication_method"
        ]
        == "password"
    )

    assert (
        normalized["outcome"]
        == "success"
    )


def test_failed_ssh_password() -> None:
    message = (
        "Failed password for root "
        "from 198.51.100.40 "
        "port 44012 ssh2"
    )

    normalized = (
        normalize_linux_auth_record(
            timestamp=(
                "Jul 24 08:17:00"
            ),
            host="server-01",
            process_name="sshd",
            message=message,
        )
    )

    assert (
        normalized["event_id"]
        == "linux.auth.ssh.failed"
    )

    assert (
        normalized["severity"]
        == "medium"
    )

    assert (
        normalized["username"]
        == "root"
    )

    assert (
        normalized["source_ip"]
        == "198.51.100.40"
    )

    assert (
        normalized["outcome"]
        == "failure"
    )


def test_invalid_ssh_user() -> None:
    message = (
        "Invalid user administrator "
        "from 203.0.113.50 port 51222"
    )

    normalized = (
        normalize_linux_auth_record(
            timestamp=(
                "Jul 24 08:18:00"
            ),
            host="server-01",
            process_name="sshd",
            message=message,
        )
    )

    assert (
        normalized["event_id"]
        == (
            "linux.auth.ssh."
            "invalid_user"
        )
    )

    assert (
        normalized["severity"]
        == "high"
    )

    assert (
        normalized["username"]
        == "administrator"
    )

    assert (
        normalized["source_ip"]
        == "203.0.113.50"
    )

    assert (
        normalized["metadata"][
            "invalid_user"
        ]
        is True
    )


def test_sudo_command() -> None:
    message = (
        "analyst : "
        "TTY=pts/0 ; "
        "PWD=/home/analyst ; "
        "USER=root ; "
        "COMMAND=/usr/bin/cat "
        "/etc/shadow"
    )

    normalized = (
        normalize_linux_auth_record(
            timestamp=(
                "Jul 24 08:20:00"
            ),
            host="server-01",
            process_name="sudo",
            message=message,
        )
    )

    assert (
        normalized["event_id"]
        == (
            "linux.auth.sudo.command"
        )
    )

    assert (
        normalized["severity"]
        == "medium"
    )

    assert (
        normalized["username"]
        == "analyst"
    )

    assert (
        normalized["target_user"]
        == "root"
    )

    assert (
        normalized["command"]
        == (
            "/usr/bin/cat "
            "/etc/shadow"
        )
    )

    assert (
        normalized["action"]
        == "privilege_escalation"
    )


def test_user_creation() -> None:
    message = (
        "new user: "
        "name=backupadmin, "
        "UID=1005, "
        "GID=1005, "
        "home=/home/backupadmin, "
        "shell=/bin/bash"
    )

    normalized = (
        normalize_linux_auth_record(
            timestamp=(
                "Jul 24 08:25:00"
            ),
            host="server-01",
            process_name="useradd",
            message=message,
        )
    )

    assert (
        normalized["event_id"]
        == (
            "linux.auth.user.created"
        )
    )

    assert (
        normalized["severity"]
        == "high"
    )

    assert (
        normalized["username"]
        == "backupadmin"
    )

    assert (
        normalized["metadata"]["uid"]
        == "1005"
    )

    assert (
        normalized["metadata"]["shell"]
        == "/bin/bash"
    )


def test_session_opened() -> None:
    message = (
        "pam_unix(sudo:session): "
        "session opened for user root "
        "by analyst(uid=1000)"
    )

    normalized = (
        normalize_linux_auth_record(
            timestamp=(
                "Jul 24 08:30:00"
            ),
            host="server-01",
            process_name="sudo",
            message=message,
        )
    )

    assert (
        normalized["event_id"]
        == (
            "linux.auth.session.opened"
        )
    )

    assert (
        normalized["severity"]
        == "medium"
    )

    assert (
        normalized["username"]
        == "analyst"
    )

    assert (
        normalized["target_user"]
        == "root"
    )

    assert (
        normalized["metadata"]["uid"]
        == "1000"
    )


def test_generic_message_not_detected() -> None:
    assert (
        looks_like_linux_auth_record(
            "application",
            "Application started",
        )
        is False
    )