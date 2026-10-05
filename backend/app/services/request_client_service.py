import hashlib
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)

from fastapi import Request

from app.core.config import get_settings


settings = get_settings()

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


def parse_ip_address(
    value: str,
) -> IPAddress | None:
    normalized = value.strip()

    if not normalized:
        return None

    try:
        return ip_address(
            normalized
        )
    except ValueError:
        return None


def get_trusted_proxy_networks(
) -> list[IPNetwork]:
    return [
        ip_network(
            value,
            strict=False,
        )
        for value
        in settings.trusted_proxy_cidr_list
    ]


def is_trusted_proxy_address(
    address: IPAddress,
) -> bool:
    return any(
        (
            address.version
            == network.version
            and address in network
        )
        for network
        in get_trusted_proxy_networks()
    )


def get_direct_peer_value(
    request: Request,
) -> str:
    if request.client is None:
        return "unknown"

    value = (
        request.client.host
        .strip()
    )

    return value or "unknown"


def resolve_request_client_ip(
    request: Request,
) -> str:
    direct_value = (
        get_direct_peer_value(
            request
        )
    )

    direct_address = (
        parse_ip_address(
            direct_value
        )
    )

    if direct_address is None:
        return direct_value[:255]

    normalized_direct = str(
        direct_address
    )

    if not is_trusted_proxy_address(
        direct_address
    ):
        return normalized_direct

    forwarded_value = (
        request.headers.get(
            "x-forwarded-for",
            "",
        )
        .strip()
    )

    if (
        not forwarded_value
        or len(forwarded_value) > 2048
    ):
        return normalized_direct

    forwarded_parts = [
        item.strip()
        for item
        in forwarded_value.split(",")
    ]

    if (
        not forwarded_parts
        or len(forwarded_parts) > 32
    ):
        return normalized_direct

    forwarded_addresses: list[
        IPAddress
    ] = []

    for value in forwarded_parts:
        address = parse_ip_address(
            value
        )

        if address is None:
            return normalized_direct

        forwarded_addresses.append(
            address
        )

    address_chain = (
        forwarded_addresses
        + [
            direct_address
        ]
    )

    for address in reversed(
        address_chain
    ):
        if not is_trusted_proxy_address(
            address
        ):
            return str(address)

    return normalized_direct


def get_request_client_ip_hash(
    request: Request,
) -> str:
    client_ip = (
        resolve_request_client_ip(
            request
        )
    )

    return hashlib.sha256(
        client_ip.encode(
            "utf-8"
        )
    ).hexdigest()
