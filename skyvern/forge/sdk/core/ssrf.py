from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult

from skyvern.exceptions import BlockedHost, InvalidUrl

_HTTP_SCHEMES = {"http", "https"}


def _normalize_host(host: str) -> str:
    # urlparse().hostname strips brackets for normal URLs, but resolver hooks and
    # tests may pass RFC 3986 IPv6 literals through in bracketed form.
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _raise_if_blocked_ip(ip_address: str, host: str) -> None:
    try:
        ip = _public_ip(ipaddress.ip_address(_normalize_host(ip_address)))
    except ValueError:
        return

    if not ip.is_global:
        raise BlockedHost(host=f"{host} resolved to {ip}")


def _raise_if_numeric_host_is_blocked(host: str) -> None:
    normalized_host = _normalize_host(host)
    try:
        resolved_addresses = socket.getaddrinfo(
            normalized_host,
            None,
            0,
            0,
            0,
            socket.AI_NUMERICHOST,
        )
    except socket.gaierror:
        return

    checked: set[str] = set()
    for resolved_address in resolved_addresses:
        sockaddr = resolved_address[4]
        if not sockaddr:
            continue
        ip_address = str(sockaddr[0])
        if ip_address in checked:
            continue
        checked.add(ip_address)
        _raise_if_blocked_ip(ip_address, host)


def validate_public_http_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _HTTP_SCHEMES or not parsed.hostname:
        raise InvalidUrl(url=url)

    _raise_if_numeric_host_is_blocked(parsed.hostname)


class PublicNetworkResolver(AbstractResolver):
    """aiohttp resolver that rejects DNS answers pointing at non-public IPs."""

    def __init__(self) -> None:
        self._resolver = aiohttp.resolver.DefaultResolver()

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[ResolveResult]:
        resolved_hosts = await self._resolver.resolve(host, port, family)
        for resolved_host in resolved_hosts:
            _raise_if_blocked_ip(str(resolved_host["host"]), host)
        return resolved_hosts

    async def close(self) -> None:
        await self._resolver.close()


def create_public_network_connector() -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(resolver=PublicNetworkResolver())


def create_public_network_trace_config() -> aiohttp.TraceConfig:
    trace_config = aiohttp.TraceConfig()

    async def on_request_start(
        _session: aiohttp.ClientSession,
        _trace_config_ctx: object,
        params: aiohttp.TraceRequestStartParams,
    ) -> None:
        validate_public_http_url(str(params.url))

    async def on_request_redirect(
        _session: aiohttp.ClientSession,
        _trace_config_ctx: object,
        params: aiohttp.TraceRequestRedirectParams,
    ) -> None:
        location = params.response.headers.get("Location")
        if not location:
            return
        validate_public_http_url(urljoin(str(params.url), location))

    trace_config.on_request_start.append(on_request_start)
    trace_config.on_request_redirect.append(on_request_redirect)
    return trace_config
