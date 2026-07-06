from __future__ import annotations

import socket
from types import SimpleNamespace
from typing import Any

import pytest

from skyvern.exceptions import BlockedHost
from skyvern.forge.sdk.core.ssrf import (
    PublicNetworkResolver,
    create_public_network_trace_config,
    validate_public_http_url,
)


class FakeResolver:
    def __init__(self, host: str) -> None:
        self.host = host

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[dict[str, Any]]:
        return [
            {
                "hostname": host,
                "host": self.host,
                "port": port,
                "family": family,
                "proto": 0,
                "flags": 0,
            }
        ]

    async def close(self) -> None:
        return None


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:45427/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.10/internal",
        "http://[fc00::1]/internal",
    ],
)
def test_validate_public_http_url_blocks_internal_literals(url: str) -> None:
    with pytest.raises(BlockedHost):
        validate_public_http_url(url)


def test_validate_public_http_url_allows_public_literal() -> None:
    validate_public_http_url("https://8.8.8.8/dns-query")


@pytest.mark.asyncio
async def test_public_network_resolver_blocks_private_dns_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = PublicNetworkResolver()
    monkeypatch.setattr(resolver, "_resolver", FakeResolver("10.0.0.5"))

    with pytest.raises(BlockedHost, match="internal.example.test"):
        await resolver.resolve("internal.example.test", 443)


@pytest.mark.asyncio
async def test_public_network_resolver_allows_public_dns_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = PublicNetworkResolver()
    monkeypatch.setattr(resolver, "_resolver", FakeResolver("93.184.216.34"))

    resolved = await resolver.resolve("example.com", 443)

    assert resolved[0]["host"] == "93.184.216.34"


@pytest.mark.asyncio
async def test_public_network_trace_config_blocks_redirect_to_internal_target() -> None:
    trace_config = create_public_network_trace_config()
    redirect_handler = trace_config.on_request_redirect[0]
    params = SimpleNamespace(
        url="https://example.com/start",
        response=SimpleNamespace(headers={"Location": "http://127.0.0.1/admin"}),
    )

    with pytest.raises(BlockedHost, match="127.0.0.1"):
        await redirect_handler(None, None, params)
