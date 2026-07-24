import json
from typing import Any


WINDOWS_LEVEL_SEVERITY = {
    "0": "unknown",
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "informational",
    "5": "informational",
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "information": "informational",
    "informational": "informational",
    "verbose": "informational",
}


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    return {}


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (
            None,
            "",
            [],
            {},
        ):
            return value

    return None


def _to_text(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ):
        return str(value).strip()

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )
    except TypeError:
        return str(value).strip()


def _nested_value(
    record: dict[str, Any],
    *paths: tuple[str, ...],
) -> Any:
    for path in paths:
        current: Any = record

        for key in path:
            if not isinstance(current, dict):
                current = None
                break

            current = current.get(key)

        if current not in (
            None,
            "",
            [],
            {},
        ):
            return current

    return None


def _extract_text_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value

    return _first_non_empty(
        value.get("#text"),
        value.get("_text"),
        value.get("text"),
        value.get("Text"),
        value.get("value"),
        value.get("Value"),
        value.get("$"),
    )


def _extract_attribute(
    value: Any,
    attribute_name: str,
) -> Any:
    if not isinstance(value, dict):
        return None

    attributes = _as_dict(
        value.get("#attributes")
    )

    return _first_non_empty(
        value.get(attribute_name),
        value.get(
            f"@{attribute_name}"
        ),
        attributes.get(attribute_name),
    )


def _extract_event_container(
    record: dict[str, Any],
) -> dict[str, Any]:
    event = record.get("Event")

    if isinstance(event, dict):
        return event

    event = record.get("event")

    if isinstance(event, dict):
        return event

    return record


def _extract_system(
    record: dict[str, Any],
) -> dict[str, Any]:
    event = _extract_event_container(
        record
    )

    system = _first_non_empty(
        event.get("System"),
        event.get("system"),
        record.get("System"),
        record.get("system"),
    )

    return _as_dict(system)


def _flatten_named_data(
    value: Any,
) -> dict[str, Any]:
    flattened: dict[str, Any] = {}

    if isinstance(value, list):
        items = value

    elif isinstance(value, dict):
        data_items = _first_non_empty(
            value.get("Data"),
            value.get("data"),
        )

        if isinstance(data_items, list):
            items = data_items

        elif data_items is not None:
            items = [data_items]

        else:
            return {
                str(key): _extract_text_value(
                    item_value
                )
                for key, item_value
                in value.items()
            }

    else:
        return flattened

    unnamed_index = 1

    for item in items:
        if not isinstance(item, dict):
            flattened[
                f"data_{unnamed_index}"
            ] = item

            unnamed_index += 1
            continue

        name = _first_non_empty(
            item.get("Name"),
            item.get("@Name"),
            _as_dict(
                item.get("#attributes")
            ).get("Name"),
        )

        item_value = _extract_text_value(
            item
        )

        if name is None:
            name = (
                f"data_{unnamed_index}"
            )
            unnamed_index += 1

        flattened[str(name)] = (
            item_value
        )

    return flattened


def _extract_event_data(
    record: dict[str, Any],
) -> dict[str, Any]:
    event = _extract_event_container(
        record
    )

    winlog = _as_dict(
        record.get("winlog")
    )

    event_data = _first_non_empty(
        event.get("EventData"),
        event.get("event_data"),
        event.get("UserData"),
        event.get("user_data"),
        record.get("EventData"),
        record.get("event_data"),
        record.get("UserData"),
        record.get("user_data"),
        winlog.get("event_data"),
    )

    return _flatten_named_data(
        event_data
    )


def _extract_provider_name(
    system: dict[str, Any],
    record: dict[str, Any],
) -> str:
    provider = _first_non_empty(
        system.get("Provider"),
        system.get("provider"),
        _nested_value(
            record,
            (
                "winlog",
                "provider_name",
            ),
            (
                "winlog",
                "provider",
            ),
        ),
        record.get("ProviderName"),
        record.get("provider_name"),
    )

    if isinstance(provider, dict):
        provider = _first_non_empty(
            _extract_attribute(
                provider,
                "Name",
            ),
            _extract_text_value(
                provider
            ),
        )

    return _to_text(provider)


def _extract_event_id(
    system: dict[str, Any],
    record: dict[str, Any],
) -> str:
    event_id = _first_non_empty(
        system.get("EventID"),
        system.get("EventId"),
        system.get("event_id"),
        _nested_value(
            record,
            (
                "winlog",
                "event_id",
            ),
        ),
        record.get("EventID"),
        record.get("EventId"),
        record.get("event_id"),
    )

    return _to_text(
        _extract_text_value(
            event_id
        )
    )


def _extract_timestamp(
    system: dict[str, Any],
    record: dict[str, Any],
) -> str:
    time_created = _first_non_empty(
        system.get("TimeCreated"),
        system.get("time_created"),
    )

    timestamp = _first_non_empty(
        _extract_attribute(
            time_created,
            "SystemTime",
        ),
        _extract_text_value(
            time_created
        ),
        _nested_value(
            record,
            ("@timestamp",),
            ("timestamp",),
            ("Timestamp",),
            (
                "winlog",
                "time_created",
            ),
        ),
    )

    return _to_text(timestamp)


def _normalize_windows_level(
    value: Any,
) -> str:
    text = _to_text(
        _extract_text_value(value)
    ).lower()

    return WINDOWS_LEVEL_SEVERITY.get(
        text,
        "unknown",
    )


def looks_like_windows_event_record(
    record: dict[str, Any],
) -> bool:
    system = _extract_system(record)

    event_id = _extract_event_id(
        system,
        record,
    )

    provider = _extract_provider_name(
        system,
        record,
    )

    winlog = record.get("winlog")

    return bool(
        event_id
        and (
            system
            or provider
            or isinstance(
                winlog,
                dict,
            )
        )
    )


def normalize_windows_event_record(
    record: dict[str, Any],
) -> dict[str, Any]:
    system = _extract_system(record)

    event_data = _extract_event_data(
        record
    )

    provider_name = (
        _extract_provider_name(
            system,
            record,
        )
    )

    event_id = _extract_event_id(
        system,
        record,
    )

    timestamp = _extract_timestamp(
        system,
        record,
    )

    level = _first_non_empty(
        system.get("Level"),
        system.get("level"),
        _nested_value(
            record,
            (
                "winlog",
                "level",
            ),
        ),
        record.get("Level"),
        record.get("level"),
    )

    host = _first_non_empty(
        system.get("Computer"),
        system.get("computer"),
        _nested_value(
            record,
            (
                "winlog",
                "computer_name",
            ),
            (
                "host",
                "name",
            ),
        ),
        record.get("Computer"),
        record.get("computer"),
        record.get("host"),
        record.get("hostname"),
    )

    channel = _first_non_empty(
        system.get("Channel"),
        system.get("channel"),
        _nested_value(
            record,
            (
                "winlog",
                "channel",
            ),
        ),
        record.get("Channel"),
        record.get("channel"),
    )

    record_id = _first_non_empty(
        system.get("EventRecordID"),
        system.get("EventRecordId"),
        system.get("record_id"),
        _nested_value(
            record,
            (
                "winlog",
                "record_id",
            ),
        ),
    )

    username = _first_non_empty(
        event_data.get(
            "TargetUserName"
        ),
        event_data.get(
            "SubjectUserName"
        ),
        event_data.get(
            "AccountName"
        ),
        event_data.get("UserName"),
        event_data.get("username"),
        _nested_value(
            record,
            (
                "user",
                "name",
            ),
        ),
    )

    process_name = _first_non_empty(
        event_data.get(
            "NewProcessName"
        ),
        event_data.get(
            "ProcessName"
        ),
        event_data.get("Image"),
        event_data.get(
            "Application"
        ),
        _nested_value(
            record,
            (
                "process",
                "executable",
            ),
            (
                "process",
                "name",
            ),
        ),
    )

    source_ip = _first_non_empty(
        event_data.get("IpAddress"),
        event_data.get("SourceIp"),
        event_data.get("SourceIP"),
        event_data.get(
            "SourceAddress"
        ),
        event_data.get(
            "ClientAddress"
        ),
        _nested_value(
            record,
            (
                "source",
                "ip",
            ),
            (
                "client",
                "ip",
            ),
        ),
    )

    destination_ip = _first_non_empty(
        event_data.get(
            "DestinationIp"
        ),
        event_data.get(
            "DestinationIP"
        ),
        event_data.get(
            "DestinationAddress"
        ),
        event_data.get(
            "DestAddress"
        ),
        _nested_value(
            record,
            (
                "destination",
                "ip",
            ),
            (
                "server",
                "ip",
            ),
        ),
    )

    message = _first_non_empty(
        record.get("message"),
        record.get("Message"),
        _nested_value(
            record,
            (
                "Event",
                "RenderingInfo",
                "Message",
            ),
            (
                "event",
                "rendering_info",
                "message",
            ),
        ),
    )

    if message is None:
        message_parts = [
            (
                f"Windows Event {event_id}"
                if event_id
                else "Windows event"
            ),
            (
                f"from {provider_name}"
                if provider_name
                else ""
            ),
            (
                f"on {_to_text(host)}"
                if host
                else ""
            ),
        ]

        message = " ".join(
            part
            for part in message_parts
            if part
        )

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "severity": (
            _normalize_windows_level(
                level
            )
        ),
        "host": _to_text(host),
        "username": _to_text(
            username
        ),
        "process_name": _to_text(
            process_name
        ),
        "source_ip": _to_text(
            source_ip
        ),
        "destination_ip": _to_text(
            destination_ip
        ),
        "message": _to_text(message),
        "provider": provider_name,
        "channel": _to_text(
            channel
        ),
        "record_id": _to_text(
            record_id
        ),
        "event_data": event_data,
    }