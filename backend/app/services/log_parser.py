import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from app.models.log_ingestion import (
    LogEventSeverity,
    LogFormat,
)
from app.services.windows_event_normalizer import (
    looks_like_windows_event_record,
    normalize_windows_event_record,
)


MAX_PARSE_BYTES = 25 * 1024 * 1024
MAX_PARSED_RECORDS = 100_000
MAX_MESSAGE_LENGTH = 20_000

SYSLOG_PATTERN = re.compile(
    r"^(?:<(?P<priority>\d{1,3})>)?"
    r"(?:(?P<timestamp>"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+"
    r"\d{2}:\d{2}:\d{2}"
    r")\s+)?"
    r"(?:(?P<host>[^\s]+)\s+)?"
    r"(?:(?P<process>[\w./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+)?"
    r"(?P<message>.*)$"
)


class UnsupportedLogFormatError(
    ValueError,
):
    pass


class LogFileTooLargeError(
    ValueError,
):
    pass


class LogRecordLimitError(
    ValueError,
):
    pass


@dataclass(frozen=True)
class ParsedRecord:
    event_index: int
    event_time: datetime | None

    source_type: str
    event_code: str
    severity: LogEventSeverity

    host: str
    username: str
    process_name: str

    source_ip: str
    destination_ip: str

    message: str

    raw_event: dict[str, Any]
    normalized_event: dict[str, Any]

    parse_error: str | None = None


def safe_text(
    value: Any,
    maximum_length: int,
) -> str:
    if value is None:
        return ""

    return str(value).strip()[
        :maximum_length
    ]


def first_present(
    record: dict[str, Any],
    keys: tuple[str, ...],
) -> Any:
    lowered_record = {
        str(key).lower(): value
        for key, value in record.items()
    }

    for key in keys:
        value = lowered_record.get(
            key.lower()
        )

        if value not in (
            None,
            "",
        ):
            return value

    return None


def parse_datetime_value(
    value: Any,
) -> datetime | None:
    if value in (
        None,
        "",
    ):
        return None

    text = str(value).strip()

    if not text:
        return None

    normalized = text

    if normalized.endswith("Z"):
        normalized = (
            normalized[:-1]
            + "+00:00"
        )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    except ValueError:
        pass

    supported_formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%b %d %H:%M:%S",
    )

    for date_format in (
        supported_formats
    ):
        try:
            parsed = datetime.strptime(
                text,
                date_format,
            )

            if (
                date_format
                == "%b %d %H:%M:%S"
            ):
                parsed = parsed.replace(
                    year=datetime.now(
                        timezone.utc
                    ).year,
                )

            return parsed.replace(
                tzinfo=timezone.utc
            )

        except ValueError:
            continue

    return None


def normalize_severity(
    value: Any,
) -> LogEventSeverity:
    if value is None:
        return (
            LogEventSeverity.unknown
        )

    text = str(value).strip().lower()

    severity_mapping = {
        "emergency": (
            LogEventSeverity.critical
        ),
        "emerg": (
            LogEventSeverity.critical
        ),
        "alert": (
            LogEventSeverity.critical
        ),
        "critical": (
            LogEventSeverity.critical
        ),
        "crit": (
            LogEventSeverity.critical
        ),
        "fatal": (
            LogEventSeverity.critical
        ),
        "high": (
            LogEventSeverity.high
        ),
        "error": (
            LogEventSeverity.high
        ),
        "err": LogEventSeverity.high,
        "warning": (
            LogEventSeverity.medium
        ),
        "warn": (
            LogEventSeverity.medium
        ),
        "medium": (
            LogEventSeverity.medium
        ),
        "notice": (
            LogEventSeverity.low
        ),
        "low": LogEventSeverity.low,
        "information": (
            LogEventSeverity
            .informational
        ),
        "informational": (
            LogEventSeverity
            .informational
        ),
        "info": (
            LogEventSeverity
            .informational
        ),
        "debug": (
            LogEventSeverity
            .informational
        ),
    }

    return severity_mapping.get(
        text,
        LogEventSeverity.unknown,
    )


def _prepare_record_for_normalization(
    record: dict[str, Any],
    source_type: str,
) -> tuple[
    dict[str, Any],
    str,
    dict[str, Any],
]:
    if not (
        looks_like_windows_event_record(
            record
        )
    ):
        return (
            record,
            source_type,
            {},
        )

    windows_record = (
        normalize_windows_event_record(
            record
        )
    )

    windows_metadata = {
        "provider": windows_record.get(
            "provider",
            "",
        ),
        "channel": windows_record.get(
            "channel",
            "",
        ),
        "record_id": windows_record.get(
            "record_id",
            "",
        ),
        "event_data": windows_record.get(
            "event_data",
            {},
        ),
        "input_format": source_type,
    }

    return (
        windows_record,
        "windows_event",
        windows_metadata,
    )


def normalize_dictionary_record(
    *,
    record: dict[str, Any],
    event_index: int,
    source_type: str,
) -> ParsedRecord:
    (
        effective_record,
        effective_source_type,
        additional_metadata,
    ) = _prepare_record_for_normalization(
        record,
        source_type,
    )

    event_time_value = first_present(
        effective_record,
        (
            "timestamp",
            "time",
            "datetime",
            "date",
            "event_time",
            "@timestamp",
            "created_at",
        ),
    )

    event_code_value = first_present(
        effective_record,
        (
            "event_id",
            "eventid",
            "event_code",
            "eventcode",
            "code",
        ),
    )

    severity_value = first_present(
        effective_record,
        (
            "severity",
            "level",
            "loglevel",
            "priority",
        ),
    )

    host_value = first_present(
        effective_record,
        (
            "host",
            "hostname",
            "computer",
            "computername",
            "device",
        ),
    )

    username_value = first_present(
        effective_record,
        (
            "username",
            "user",
            "account",
            "subjectusername",
        ),
    )

    process_value = first_present(
        effective_record,
        (
            "process",
            "process_name",
            "processname",
            "image",
            "application",
        ),
    )

    source_ip_value = first_present(
        effective_record,
        (
            "source_ip",
            "src_ip",
            "srcip",
            "client_ip",
            "ipaddress",
        ),
    )

    destination_ip_value = (
        first_present(
            effective_record,
            (
                "destination_ip",
                "dest_ip",
                "dst_ip",
                "dstip",
                "server_ip",
            ),
        )
    )

    message_value = first_present(
        effective_record,
        (
            "message",
            "description",
            "event_message",
            "msg",
            "details",
        ),
    )

    message = safe_text(
        message_value,
        MAX_MESSAGE_LENGTH,
    )

    if not message:
        message = safe_text(
            json.dumps(
                effective_record,
                ensure_ascii=False,
                default=str,
            ),
            MAX_MESSAGE_LENGTH,
        )

    event_code = safe_text(
        event_code_value,
        100,
    )

    severity = normalize_severity(
        severity_value
    )

    host = safe_text(
        host_value,
        255,
    )

    username = safe_text(
        username_value,
        255,
    )

    process_name = safe_text(
        process_value,
        500,
    )

    source_ip = safe_text(
        source_ip_value,
        64,
    )

    destination_ip = safe_text(
        destination_ip_value,
        64,
    )

    normalized_event = {
        "event_time": (
            str(event_time_value)
            if event_time_value
            is not None
            else None
        ),
        "source_type": (
            effective_source_type
        ),
        "event_code": event_code,
        "severity": severity.value,
        "host": host,
        "username": username,
        "process_name": process_name,
        "source_ip": source_ip,
        "destination_ip": (
            destination_ip
        ),
        "message": message,
        **additional_metadata,
    }

    return ParsedRecord(
        event_index=event_index,
        event_time=parse_datetime_value(
            event_time_value
        ),
        source_type=(
            effective_source_type
        ),
        event_code=event_code,
        severity=severity,
        host=host,
        username=username,
        process_name=process_name,
        source_ip=source_ip,
        destination_ip=(
            destination_ip
        ),
        message=message,
        raw_event={
            str(key): value
            for key, value
            in record.items()
        },
        normalized_event=(
            normalized_event
        ),
    )


def _looks_like_json_lines(
    sample: str,
) -> bool:
    non_empty_lines = [
        line.strip()
        for line in sample.splitlines()
        if line.strip()
    ]

    if len(non_empty_lines) < 2:
        return False

    checked_lines = non_empty_lines[:3]

    for line in checked_lines:
        try:
            json.loads(line)
        except json.JSONDecodeError:
            return False

    return True


def detect_log_format(
    path: Path,
    original_filename: str,
) -> LogFormat:
    suffix = Path(
        original_filename
    ).suffix.lower()

    if suffix in (
        ".jsonl",
        ".ndjson",
    ):
        return LogFormat.json_lines

    if suffix == ".json":
        return LogFormat.json

    if suffix == ".csv":
        return LogFormat.csv

    sample = (
        path.read_bytes()[:8192]
        .decode(
            "utf-8",
            errors="replace",
        )
    )

    stripped = sample.lstrip()

    if stripped.startswith("["):
        return LogFormat.json

    if stripped.startswith("{"):
        if _looks_like_json_lines(
            sample
        ):
            return LogFormat.json_lines

        return LogFormat.json

    lines = sample.splitlines()

    first_line = (
        lines[0]
        if lines
        else ""
    )

    if "," in first_line:
        try:
            columns = next(
                csv.reader(
                    [first_line]
                )
            )

            if len(columns) > 1:
                return LogFormat.csv

        except csv.Error:
            pass

    syslog_matches = 0

    for line in lines[:10]:
        if (
            line.startswith("<")
            or re.match(
                r"^[A-Z][a-z]{2}\s+\d",
                line,
            )
        ):
            syslog_matches += 1

    if syslog_matches >= 2:
        return LogFormat.syslog

    return LogFormat.plain_text


def parse_json_file(
    path: Path,
) -> Iterator[ParsedRecord]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
    ) as input_file:
        payload = json.load(input_file)

    if isinstance(payload, list):
        records = payload

    elif isinstance(payload, dict):
        possible_records = (
            first_present(
                payload,
                (
                    "events",
                    "records",
                    "items",
                    "logs",
                ),
            )
        )

        if isinstance(
            possible_records,
            list,
        ):
            records = possible_records
        else:
            records = [payload]

    else:
        records = [
            {
                "message": str(payload),
            }
        ]

    for event_index, item in (
        enumerate(
            records,
            start=1,
        )
    ):
        if (
            event_index
            > MAX_PARSED_RECORDS
        ):
            raise LogRecordLimitError(
                "The log file exceeds the "
                "maximum supported record count."
            )

        if not isinstance(item, dict):
            item = {
                "message": str(item),
            }

        yield normalize_dictionary_record(
            record=item,
            event_index=event_index,
            source_type="json",
        )


def parse_json_lines(
    path: Path,
) -> Iterator[ParsedRecord]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
    ) as input_file:
        event_index = 0

        for line_number, line in (
            enumerate(
                input_file,
                start=1,
            )
        ):
            stripped = line.strip()

            if not stripped:
                continue

            event_index += 1

            if (
                event_index
                > MAX_PARSED_RECORDS
            ):
                raise LogRecordLimitError(
                    "The log file exceeds the "
                    "maximum supported record count."
                )

            try:
                item = json.loads(
                    stripped
                )

                if not isinstance(
                    item,
                    dict,
                ):
                    item = {
                        "message": str(item),
                    }

                yield (
                    normalize_dictionary_record(
                        record=item,
                        event_index=(
                            event_index
                        ),
                        source_type=(
                            "json_lines"
                        ),
                    )
                )

            except (
                json.JSONDecodeError
            ) as error:
                yield ParsedRecord(
                    event_index=(
                        event_index
                    ),
                    event_time=None,
                    source_type=(
                        "json_lines"
                    ),
                    event_code="",
                    severity=(
                        LogEventSeverity
                        .unknown
                    ),
                    host="",
                    username="",
                    process_name="",
                    source_ip="",
                    destination_ip="",
                    message=stripped[
                        :MAX_MESSAGE_LENGTH
                    ],
                    raw_event={
                        "line_number": (
                            line_number
                        ),
                        "line": stripped,
                    },
                    normalized_event={
                        "message": stripped[
                            :MAX_MESSAGE_LENGTH
                        ],
                    },
                    parse_error=str(
                        error
                    ),
                )


def parse_csv_file(
    path: Path,
) -> Iterator[ParsedRecord]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline="",
    ) as input_file:
        reader = csv.DictReader(
            input_file
        )

        if not reader.fieldnames:
            raise (
                UnsupportedLogFormatError(
                    "The CSV file does not "
                    "contain a valid header row."
                )
            )

        for event_index, row in (
            enumerate(
                reader,
                start=1,
            )
        ):
            if (
                event_index
                > MAX_PARSED_RECORDS
            ):
                raise LogRecordLimitError(
                    "The log file exceeds the "
                    "maximum supported record count."
                )

            normalized_row = {
                str(key): value
                for key, value
                in row.items()
                if key is not None
            }

            yield (
                normalize_dictionary_record(
                    record=normalized_row,
                    event_index=event_index,
                    source_type="csv",
                )
            )


def parse_syslog_file(
    path: Path,
) -> Iterator[ParsedRecord]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
    ) as input_file:
        event_index = 0

        for line_number, line in (
            enumerate(
                input_file,
                start=1,
            )
        ):
            stripped = line.strip()

            if not stripped:
                continue

            event_index += 1

            if (
                event_index
                > MAX_PARSED_RECORDS
            ):
                raise LogRecordLimitError(
                    "The log file exceeds the "
                    "maximum supported record count."
                )

            match = SYSLOG_PATTERN.match(
                stripped
            )

            if match is None:
                yield ParsedRecord(
                    event_index=(
                        event_index
                    ),
                    event_time=None,
                    source_type="syslog",
                    event_code="",
                    severity=(
                        LogEventSeverity
                        .unknown
                    ),
                    host="",
                    username="",
                    process_name="",
                    source_ip="",
                    destination_ip="",
                    message=stripped[
                        :MAX_MESSAGE_LENGTH
                    ],
                    raw_event={
                        "line_number": (
                            line_number
                        ),
                        "line": stripped,
                    },
                    normalized_event={
                        "message": stripped[
                            :MAX_MESSAGE_LENGTH
                        ],
                    },
                    parse_error=(
                        "The line did not match "
                        "the supported Syslog format."
                    ),
                )

                continue

            values = match.groupdict()

            priority = values.get(
                "priority"
            )

            severity = (
                LogEventSeverity.unknown
            )

            if priority is not None:
                severity_number = (
                    int(priority) % 8
                )

                severity_mapping = {
                    0: (
                        LogEventSeverity
                        .critical
                    ),
                    1: (
                        LogEventSeverity
                        .critical
                    ),
                    2: (
                        LogEventSeverity
                        .critical
                    ),
                    3: (
                        LogEventSeverity.high
                    ),
                    4: (
                        LogEventSeverity
                        .medium
                    ),
                    5: (
                        LogEventSeverity.low
                    ),
                    6: (
                        LogEventSeverity
                        .informational
                    ),
                    7: (
                        LogEventSeverity
                        .informational
                    ),
                }

                severity = (
                    severity_mapping[
                        severity_number
                    ]
                )

            timestamp = values.get(
                "timestamp"
            )

            host = safe_text(
                values.get("host"),
                255,
            )

            process_name = safe_text(
                values.get("process"),
                500,
            )

            message = safe_text(
                values.get("message"),
                MAX_MESSAGE_LENGTH,
            )

            normalized_event = {
                "event_time": timestamp,
                "source_type": "syslog",
                "event_code": "",
                "severity": (
                    severity.value
                ),
                "host": host,
                "username": "",
                "process_name": (
                    process_name
                ),
                "source_ip": "",
                "destination_ip": "",
                "message": message,
                "priority": priority,
                "pid": values.get("pid"),
            }

            yield ParsedRecord(
                event_index=event_index,
                event_time=(
                    parse_datetime_value(
                        timestamp
                    )
                ),
                source_type="syslog",
                event_code="",
                severity=severity,
                host=host,
                username="",
                process_name=(
                    process_name
                ),
                source_ip="",
                destination_ip="",
                message=message,
                raw_event={
                    "line_number": (
                        line_number
                    ),
                    "line": stripped,
                },
                normalized_event=(
                    normalized_event
                ),
            )


def parse_plain_text_file(
    path: Path,
) -> Iterator[ParsedRecord]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
    ) as input_file:
        event_index = 0

        for line_number, line in (
            enumerate(
                input_file,
                start=1,
            )
        ):
            stripped = line.strip()

            if not stripped:
                continue

            event_index += 1

            if (
                event_index
                > MAX_PARSED_RECORDS
            ):
                raise LogRecordLimitError(
                    "The log file exceeds the "
                    "maximum supported record count."
                )

            yield ParsedRecord(
                event_index=event_index,
                event_time=None,
                source_type=(
                    "plain_text"
                ),
                event_code="",
                severity=(
                    LogEventSeverity.unknown
                ),
                host="",
                username="",
                process_name="",
                source_ip="",
                destination_ip="",
                message=stripped[
                    :MAX_MESSAGE_LENGTH
                ],
                raw_event={
                    "line_number": (
                        line_number
                    ),
                    "line": stripped,
                },
                normalized_event={
                    "message": stripped[
                        :MAX_MESSAGE_LENGTH
                    ],
                },
            )


def parse_log_file(
    *,
    path: Path,
    original_filename: str,
    requested_format: LogFormat,
) -> tuple[
    LogFormat,
    Iterator[ParsedRecord],
]:
    file_size = path.stat().st_size

    if file_size > MAX_PARSE_BYTES:
        raise LogFileTooLargeError(
            "The log file exceeds the "
            "25 MB ingestion limit."
        )

    detected_format = (
        detect_log_format(
            path,
            original_filename,
        )
        if requested_format
        == LogFormat.auto
        else requested_format
    )

    parser_map = {
        LogFormat.json: (
            parse_json_file
        ),
        LogFormat.json_lines: (
            parse_json_lines
        ),
        LogFormat.csv: (
            parse_csv_file
        ),
        LogFormat.syslog: (
            parse_syslog_file
        ),
        LogFormat.plain_text: (
            parse_plain_text_file
        ),
    }

    parser = parser_map.get(
        detected_format
    )

    if parser is None:
        raise (
            UnsupportedLogFormatError(
                "The selected log format "
                "is not supported."
            )
        )

    return (
        detected_format,
        parser(path),
    )