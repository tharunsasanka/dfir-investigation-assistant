import csv
import io
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


MAX_PARSE_BYTES = 25 * 1024 * 1024
MAX_PARSED_RECORDS = 100_000

SYSLOG_PATTERN = re.compile(
    r"^(?:<(?P<priority>\d{1,3})>)?"
    r"(?:(?P<timestamp>"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r")\s+)?"
    r"(?:(?P<host>[^\s]+)\s+)?"
    r"(?:(?P<process>[\w./-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+)?"
    r"(?P<message>.*)$"
)


class UnsupportedLogFormatError(ValueError):
    pass


class LogFileTooLargeError(ValueError):
    pass


class LogRecordLimitError(ValueError):
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


def first_present(
    record: dict[str, Any],
    keys: tuple[str, ...],
) -> Any:
    lowered = {
        str(key).lower(): value
        for key, value in record.items()
    }

    for key in keys:
        value = lowered.get(key.lower())

        if value not in (
            None,
            "",
        ):
            return value

    return None


def safe_text(
    value: Any,
    maximum_length: int,
) -> str:
    if value is None:
        return ""

    text = str(value).strip()

    return text[:maximum_length]


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

    normalized = text.replace(
        "Z",
        "+00:00",
    )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except ValueError:
        pass

    supported_formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%b %d %H:%M:%S",
    )

    for date_format in supported_formats:
        try:
            parsed = datetime.strptime(
                text,
                date_format,
            )

            if date_format == "%b %d %H:%M:%S":
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
        return LogEventSeverity.unknown

    text = str(value).strip().lower()

    severity_aliases = {
        "emergency": LogEventSeverity.critical,
        "emerg": LogEventSeverity.critical,
        "alert": LogEventSeverity.critical,
        "critical": LogEventSeverity.critical,
        "crit": LogEventSeverity.critical,
        "fatal": LogEventSeverity.critical,
        "high": LogEventSeverity.high,
        "error": LogEventSeverity.high,
        "err": LogEventSeverity.high,
        "warning": LogEventSeverity.medium,
        "warn": LogEventSeverity.medium,
        "medium": LogEventSeverity.medium,
        "notice": LogEventSeverity.low,
        "low": LogEventSeverity.low,
        "information": (
            LogEventSeverity.informational
        ),
        "informational": (
            LogEventSeverity.informational
        ),
        "info": LogEventSeverity.informational,
        "debug": LogEventSeverity.informational,
        "0": LogEventSeverity.informational,
        "1": LogEventSeverity.low,
        "2": LogEventSeverity.medium,
        "3": LogEventSeverity.high,
        "4": LogEventSeverity.critical,
    }

    return severity_aliases.get(
        text,
        LogEventSeverity.unknown,
    )


def normalize_dictionary_record(
    *,
    record: dict[str, Any],
    event_index: int,
    source_type: str,
) -> ParsedRecord:
    event_time_value = first_present(
        record,
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
        record,
        (
            "event_id",
            "eventid",
            "event_code",
            "eventcode",
            "id",
            "code",
        ),
    )

    severity_value = first_present(
        record,
        (
            "severity",
            "level",
            "loglevel",
            "priority",
        ),
    )

    host_value = first_present(
        record,
        (
            "host",
            "hostname",
            "computer",
            "computername",
            "device",
        ),
    )

    username_value = first_present(
        record,
        (
            "username",
            "user",
            "account",
            "subjectusername",
        ),
    )

    process_value = first_present(
        record,
        (
            "process",
            "process_name",
            "processname",
            "image",
            "application",
        ),
    )

    source_ip_value = first_present(
        record,
        (
            "source_ip",
            "src_ip",
            "srcip",
            "ipaddress",
            "client_ip",
        ),
    )

    destination_ip_value = first_present(
        record,
        (
            "destination_ip",
            "dest_ip",
            "dst_ip",
            "dstip",
            "server_ip",
        ),
    )

    message_value = first_present(
        record,
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
        20_000,
    )

    if not message:
        message = safe_text(
            json.dumps(
                record,
                ensure_ascii=False,
                default=str,
            ),
            20_000,
        )

    normalized_event = {
        "event_time": (
            str(event_time_value)
            if event_time_value is not None
            else None
        ),
        "source_type": source_type,
        "event_code": safe_text(
            event_code_value,
            100,
        ),
        "severity": normalize_severity(
            severity_value
        ).value,
        "host": safe_text(
            host_value,
            255,
        ),
        "username": safe_text(
            username_value,
            255,
        ),
        "process_name": safe_text(
            process_value,
            500,
        ),
        "source_ip": safe_text(
            source_ip_value,
            64,
        ),
        "destination_ip": safe_text(
            destination_ip_value,
            64,
        ),
        "message": message,
    }

    return ParsedRecord(
        event_index=event_index,
        event_time=parse_datetime_value(
            event_time_value
        ),
        source_type=source_type,
        event_code=normalized_event[
            "event_code"
        ],
        severity=normalize_severity(
            severity_value
        ),
        host=normalized_event["host"],
        username=normalized_event["username"],
        process_name=normalized_event[
            "process_name"
        ],
        source_ip=normalized_event[
            "source_ip"
        ],
        destination_ip=normalized_event[
            "destination_ip"
        ],
        message=message,
        raw_event={
            str(key): value
            for key, value in record.items()
        },
        normalized_event=normalized_event,
    )


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

    sample = path.read_bytes()[:8192].decode(
        "utf-8",
        errors="replace",
    )

    stripped = sample.lstrip()

    if stripped.startswith(
        "["
    ) or stripped.startswith(
        "{"
    ):
        if "\n{" in sample:
            return LogFormat.json_lines

        return LogFormat.json

    first_line = sample.splitlines()[0] if sample else ""

    if (
        "," in first_line
        and len(
            next(
                csv.reader(
                    [first_line]
                )
            )
        )
        > 1
    ):
        return LogFormat.csv

    syslog_matches = sum(
        1
        for line in sample.splitlines()[:10]
        if SYSLOG_PATTERN.match(
            line
        )
        and (
            line.startswith("<")
            or re.match(
                r"^[A-Z][a-z]{2}\s+\d",
                line,
            )
        )
    )

    if syslog_matches >= 2:
        return LogFormat.syslog

    return LogFormat.plain_text


def parse_json_file(
    path: Path,
) -> Iterator[ParsedRecord]:
    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as input_file:
        payload = json.load(
            input_file
        )

    if isinstance(
        payload,
        list,
    ):
        records = payload

    elif isinstance(
        payload,
        dict,
    ):
        possible_records = first_present(
            payload,
            (
                "events",
                "records",
                "items",
                "logs",
            ),
        )

        if isinstance(
            possible_records,
            list,
        ):
            records = possible_records
        else:
            records = [payload]

    else:
        raise UnsupportedLogFormatError(
            "The JSON evidence must contain "
            "an object or an array of objects."
        )

    for event_index, item in enumerate(
        records,
        start=1,
    ):
        if event_index > MAX_PARSED_RECORDS:
            raise LogRecordLimitError(
                "The log file exceeds the "
                "maximum supported record count."
            )

        if not isinstance(
            item,
            dict,
        ):
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
        encoding="utf-8",
        errors="replace",
    ) as input_file:
        event_index = 0

        for line_number, line in enumerate(
            input_file,
            start=1,
        ):
            stripped = line.strip()

            if not stripped:
                continue

            event_index += 1

            if event_index > MAX_PARSED_RECORDS:
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

                yield normalize_dictionary_record(
                    record=item,
                    event_index=event_index,
                    source_type="json_lines",
                )

            except json.JSONDecodeError as error:
                yield ParsedRecord(
                    event_index=event_index,
                    event_time=None,
                    source_type="json_lines",
                    event_code="",
                    severity=(
                        LogEventSeverity.unknown
                    ),
                    host="",
                    username="",
                    process_name="",
                    source_ip="",
                    destination_ip="",
                    message=stripped[:20_000],
                    raw_event={
                        "line_number": line_number,
                        "line": stripped,
                    },
                    normalized_event={
                        "message": stripped[:20_000],
                    },
                    parse_error=str(error),
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
            raise UnsupportedLogFormatError(
                "The CSV evidence does not contain "
                "a valid header row."
            )

        for event_index, row in enumerate(
            reader,
            start=1,
        ):
            if event_index > MAX_PARSED_RECORDS:
                raise LogRecordLimitError(
                    "The log file exceeds the "
                    "maximum supported record count."
                )

            normalized_row = {
                str(key): value
                for key, value in row.items()
                if key is not None
            }

            yield normalize_dictionary_record(
                record=normalized_row,
                event_index=event_index,
                source_type="csv",
            )


def parse_syslog_file(
    path: Path,
) -> Iterator[ParsedRecord]:
    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as input_file:
        event_index = 0

        for line_number, line in enumerate(
            input_file,
            start=1,
        ):
            stripped = line.strip()

            if not stripped:
                continue

            event_index += 1

            if event_index > MAX_PARSED_RECORDS:
                raise LogRecordLimitError(
                    "The log file exceeds the "
                    "maximum supported record count."
                )

            match = SYSLOG_PATTERN.match(
                stripped
            )

            if match is None:
                yield ParsedRecord(
                    event_index=event_index,
                    event_time=None,
                    source_type="syslog",
                    event_code="",
                    severity=(
                        LogEventSeverity.unknown
                    ),
                    host="",
                    username="",
                    process_name="",
                    source_ip="",
                    destination_ip="",
                    message=stripped[:20_000],
                    raw_event={
                        "line_number": line_number,
                        "line": stripped,
                    },
                    normalized_event={
                        "message": stripped[:20_000],
                    },
                    parse_error=(
                        "The line did not match the "
                        "supported syslog format."
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
                severity_code = int(
                    priority
                ) % 8

                severity_mapping = {
                    0: LogEventSeverity.critical,
                    1: LogEventSeverity.critical,
                    2: LogEventSeverity.critical,
                    3: LogEventSeverity.high,
                    4: LogEventSeverity.medium,
                    5: LogEventSeverity.low,
                    6: (
                        LogEventSeverity.informational
                    ),
                    7: (
                        LogEventSeverity.informational
                    ),
                }

                severity = severity_mapping[
                    severity_code
                ]

            message = safe_text(
                values.get(
                    "message"
                ),
                20_000,
            )

            normalized_event = {
                "event_time": values.get(
                    "timestamp"
                ),
                "source_type": "syslog",
                "event_code": "",
                "severity": severity.value,
                "host": safe_text(
                    values.get(
                        "host"
                    ),
                    255,
                ),
                "username": "",
                "process_name": safe_text(
                    values.get(
                        "process"
                    ),
                    500,
                ),
                "source_ip": "",
                "destination_ip": "",
                "message": message,
                "pid": values.get(
                    "pid"
                ),
                "priority": priority,
            }

            yield ParsedRecord(
                event_index=event_index,
                event_time=parse_datetime_value(
                    values.get(
                        "timestamp"
                    )
                ),
                source_type="syslog",
                event_code="",
                severity=severity,
                host=normalized_event[
                    "host"
                ],
                username="",
                process_name=normalized_event[
                    "process_name"
                ],
                source_ip="",
                destination_ip="",
                message=message,
                raw_event={
                    "line_number": line_number,
                    "line": stripped,
                },
                normalized_event=normalized_event,
            )


def parse_plain_text_file(
    path: Path,
) -> Iterator[ParsedRecord]:
    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as input_file:
        event_index = 0

        for line_number, line in enumerate(
            input_file,
            start=1,
        ):
            stripped = line.strip()

            if not stripped:
                continue

            event_index += 1

            if event_index > MAX_PARSED_RECORDS:
                raise LogRecordLimitError(
                    "The log file exceeds the "
                    "maximum supported record count."
                )

            yield ParsedRecord(
                event_index=event_index,
                event_time=None,
                source_type="plain_text",
                event_code="",
                severity=LogEventSeverity.unknown,
                host="",
                username="",
                process_name="",
                source_ip="",
                destination_ip="",
                message=stripped[:20_000],
                raw_event={
                    "line_number": line_number,
                    "line": stripped,
                },
                normalized_event={
                    "message": stripped[:20_000],
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
    size_bytes = path.stat().st_size

    if size_bytes > MAX_PARSE_BYTES:
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
        LogFormat.json: parse_json_file,
        LogFormat.json_lines: (
            parse_json_lines
        ),
        LogFormat.csv: parse_csv_file,
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
        raise UnsupportedLogFormatError(
            "The selected log format "
            "is not supported."
        )

    return (
        detected_format,
        parser(path),
    )