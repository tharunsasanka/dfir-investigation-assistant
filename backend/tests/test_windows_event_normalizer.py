from app.services.windows_event_normalizer import (
    looks_like_windows_event_record,
    normalize_windows_event_record,
)


def test_normalize_windows_event_4624() -> None:
    record = {
        "Event": {
            "System": {
                "Provider": {
                    "#attributes": {
                        "Name": (
                            "Microsoft-Windows-"
                            "Security-Auditing"
                        )
                    }
                },
                "EventID": {
                    "#text": "4624"
                },
                "Level": "0",
                "TimeCreated": {
                    "#attributes": {
                        "SystemTime": (
                            "2026-07-24T08:15:00Z"
                        )
                    }
                },
                "Computer": (
                    "WORKSTATION-01"
                ),
                "Channel": "Security",
                "EventRecordID": (
                    "15001"
                ),
            },
            "EventData": {
                "Data": [
                    {
                        "#attributes": {
                            "Name": (
                                "TargetUserName"
                            )
                        },
                        "#text": (
                            "eric.fischer"
                        ),
                    },
                    {
                        "#attributes": {
                            "Name": (
                                "IpAddress"
                            )
                        },
                        "#text": (
                            "192.168.1.25"
                        ),
                    },
                ]
            },
        },
        "Message": (
            "An account was successfully "
            "logged on."
        ),
    }

    assert (
        looks_like_windows_event_record(
            record
        )
        is True
    )

    normalized = (
        normalize_windows_event_record(
            record
        )
    )

    assert (
        normalized["event_id"]
        == "4624"
    )

    assert (
        normalized["provider"]
        == (
            "Microsoft-Windows-"
            "Security-Auditing"
        )
    )

    assert (
        normalized["timestamp"]
        == "2026-07-24T08:15:00Z"
    )

    assert (
        normalized["host"]
        == "WORKSTATION-01"
    )

    assert (
        normalized["username"]
        == "eric.fischer"
    )

    assert (
        normalized["source_ip"]
        == "192.168.1.25"
    )

    assert (
        normalized["channel"]
        == "Security"
    )

    assert (
        normalized["record_id"]
        == "15001"
    )


def test_normalize_windows_event_4625() -> None:
    record = {
        "@timestamp": (
            "2026-07-24T08:17:12Z"
        ),
        "message": (
            "An account failed to log on."
        ),
        "winlog": {
            "event_id": 4625,
            "provider_name": (
                "Microsoft-Windows-"
                "Security-Auditing"
            ),
            "level": "error",
            "computer_name": "DC-01",
            "channel": "Security",
            "record_id": 15002,
            "event_data": {
                "TargetUserName": (
                    "administrator"
                ),
                "IpAddress": (
                    "198.51.100.25"
                ),
            },
        },
    }

    assert (
        looks_like_windows_event_record(
            record
        )
        is True
    )

    normalized = (
        normalize_windows_event_record(
            record
        )
    )

    assert (
        normalized["event_id"]
        == "4625"
    )

    assert (
        normalized["severity"]
        == "high"
    )

    assert (
        normalized["host"]
        == "DC-01"
    )

    assert (
        normalized["username"]
        == "administrator"
    )

    assert (
        normalized["source_ip"]
        == "198.51.100.25"
    )

    assert (
        normalized["message"]
        == (
            "An account failed to log on."
        )
    )


def test_normalize_windows_event_4688() -> None:
    record = {
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
                        "2026-07-24T08:18:41Z"
                    )
                },
                "Computer": (
                    "WORKSTATION-01"
                ),
                "Channel": "Security",
                "EventRecordID": (
                    "15003"
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

    normalized = (
        normalize_windows_event_record(
            record
        )
    )

    assert (
        normalized["event_id"]
        == "4688"
    )

    assert (
        normalized["severity"]
        == "informational"
    )

    assert (
        normalized["username"]
        == "eric.fischer"
    )

    assert (
        normalized["process_name"]
        == (
            "C:\\Windows\\System32"
            "\\WindowsPowerShell"
            "\\v1.0\\powershell.exe"
        )
    )

    assert (
        normalized["message"]
        == (
            "A new process was created."
        )
    )


def test_non_windows_record_is_not_detected() -> None:
    record = {
        "timestamp": (
            "2026-07-24T08:20:00Z"
        ),
        "message": (
            "Generic application event"
        ),
        "severity": (
            "informational"
        ),
    }

    assert (
        looks_like_windows_event_record(
            record
        )
        is False
    )