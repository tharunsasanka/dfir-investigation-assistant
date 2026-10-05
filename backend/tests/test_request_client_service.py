import hashlib

import pytest
from fastapi import Request

from app.core.config import (
    Settings,
    get_settings,
)
from app.services.auth_session_service import (
    request_ip_hash as session_ip_hash,
)
from app.services.login_rate_limit_service import (
    get_request_key,
)
from app.services.request_client_service import (
    get_request_client_ip_hash,
    resolve_request_client_ip,
)


settings = get_settings()


def make_request(
    client_host: str,
    forwarded_for: str | None = None,
) -> Request:
    headers: list[
        tuple[bytes, bytes]
    ] = []

    if forwarded_for is not None:
        headers.append(
            (
                b"x-forwarded-for",
                forwarded_for.encode(
                    "utf-8"
                ),
            )
        )

    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "headers": headers,
            "client": (
                client_host,
                50000,
            ),
            "server": (
                "testserver",
                80,
            ),
            "root_path": "",
        }
    )


@pytest.fixture(autouse=True)
def restore_proxy_configuration():
    original_value = (
        settings.trusted_proxy_cidrs
    )

    yield

    settings.trusted_proxy_cidrs = (
        original_value
    )


def test_untrusted_peer_ignores_forwarded_header():
    settings.trusted_proxy_cidrs = ""

    request = make_request(
        "198.51.100.10",
        "203.0.113.20",
    )

    assert (
        resolve_request_client_ip(
            request
        )
        == "198.51.100.10"
    )


def test_trusted_proxy_uses_forwarded_client():
    settings.trusted_proxy_cidrs = (
        "10.0.0.0/8"
    )

    request = make_request(
        "10.0.0.5",
        "203.0.113.20",
    )

    assert (
        resolve_request_client_ip(
            request
        )
        == "203.0.113.20"
    )


def test_trusted_chain_uses_nearest_untrusted_hop():
    settings.trusted_proxy_cidrs = (
        "10.0.0.0/8"
    )

    request = make_request(
        "10.0.0.5",
        (
            "198.51.100.99, "
            "203.0.113.20, "
            "10.0.0.8"
        ),
    )

    assert (
        resolve_request_client_ip(
            request
        )
        == "203.0.113.20"
    )


def test_malformed_forwarded_header_falls_back():
    settings.trusted_proxy_cidrs = (
        "10.0.0.0/8"
    )

    request = make_request(
        "10.0.0.5",
        "not-an-ip",
    )

    assert (
        resolve_request_client_ip(
            request
        )
        == "10.0.0.5"
    )


def test_auth_and_rate_limit_hashes_match():
    settings.trusted_proxy_cidrs = (
        "10.0.0.0/8"
    )

    request = make_request(
        "10.0.0.5",
        "203.0.113.20",
    )

    expected_hash = hashlib.sha256(
        b"203.0.113.20"
    ).hexdigest()

    assert (
        get_request_client_ip_hash(
            request
        )
        == expected_hash
    )

    assert (
        session_ip_hash(
            request
        )
        == expected_hash
    )

    assert (
        get_request_key(
            request
        )
        == expected_hash
    )


def test_invalid_proxy_cidr_is_rejected():
    with pytest.raises(
        ValueError,
        match="Trusted proxy CIDRs",
    ):
        Settings(
            _env_file=None,
            trusted_proxy_cidrs=(
                "invalid-network"
            ),
        )


def test_trust_all_network_is_rejected():
    with pytest.raises(
        ValueError,
        match="entire address space",
    ):
        Settings(
            _env_file=None,
            trusted_proxy_cidrs=(
                "0.0.0.0/0"
            ),
        )


def test_ipv6_trusted_proxy_is_supported():
    settings.trusted_proxy_cidrs = (
        "2001:db8:1::/48"
    )

    request = make_request(
        "2001:db8:1::10",
        "2001:db8:2::20",
    )

    assert (
        resolve_request_client_ip(
            request
        )
        == "2001:db8:2::20"
    )
