"""Subdomain discovery via crt.sh and DNS resolution."""
from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Awaitable, Callable

import httpx

from reconkit.scope import normalize


DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"
# CNAME target suffixes where NXDOMAIN usually means anyone can claim the name (per can-i-take-over-xyz).
TAKEOVER_SUFFIXES = {
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud Services",
    "cloudapp.azure.com": "Azure VM",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "azureedge.net": "Azure CDN",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
}


class DiscoveryError(Exception):
    """Raised when crt.sh cannot be queried successfully."""


async def _fetch(domain: str, client: httpx.AsyncClient, timeout: float) -> list:
    try:
        r = await client.get("https://crt.sh/", params={"q": "%." + domain, "output": "json"}, timeout=timeout)
    except httpx.HTTPError as e:
        raise DiscoveryError(f"crt.sh request failed: {type(e).__name__}: {e}") from e
    if r.status_code != 200:
        raise DiscoveryError(f"crt.sh returned HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError as e:
        raise DiscoveryError("crt.sh returned invalid JSON") from e
    if not isinstance(data, list):
        raise DiscoveryError("crt.sh returned unexpected JSON")
    return data


async def crtsh(domain: str, client: httpx.AsyncClient, *, timeout: float = 60.0,
                retry_delay: float = 5.0) -> tuple[list[str], int]:
    """Return (sorted unique normalized names incl. domain, count of dropped raw names)."""
    try:
        entries = await _fetch(domain, client, timeout)
    except DiscoveryError:
        await asyncio.sleep(retry_delay)
        entries = await _fetch(domain, client, timeout)
    names = {normalize(domain)}
    bad: set[str] = set()
    for e in entries:
        value = e.get("name_value") if isinstance(e, dict) else None
        for raw in (value.split("\n") if isinstance(value, str) else []):
            raw = raw.strip()
            try:
                names.add(normalize(raw.removeprefix("*.")))
            except ValueError:
                bad.add(raw)
    return sorted(names), len(bad)


async def resolve(host: str, sem: asyncio.Semaphore,
                  resolver: Callable[[str], Awaitable[list[str]]] | None = None) -> list[str]:
    """Resolve host to unique addresses; [] on any resolution failure."""
    async with sem:
        try:
            if resolver is not None:
                return list(dict.fromkeys(await resolver(host)))
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
            return list(dict.fromkeys(str(i[4][0]) for i in infos))
        except (socket.gaierror, OSError, UnicodeError):
            return []


async def cname_lookup(host: str, client: httpx.AsyncClient, doh_url: str, sem: asyncio.Semaphore) -> dict:
    """CNAME chain of host via DNS-over-HTTPS (JSON API). Unlike getaddrinfo this still sees a CNAME
    whose target doesn't exist: that is a dangling CNAME, and a takeover candidate on a known service."""
    async with sem:
        try:
            r = await client.get(doh_url, params={"name": host, "type": "A"}, headers={"accept": "application/dns-json"})
            r.raise_for_status()
            data = r.json()
            chain = [normalize(a["data"]) for a in data.get("Answer") or [] if a.get("type") == 5]
            dangling = bool(chain) and data.get("Status") == 3  # NXDOMAIN applies to the end of the chain
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as e:
            return {"cname": [], "dangling": False, "takeover_candidate": None, "error": f"{type(e).__name__}: {e}"}
    service = next((name for suffix, name in TAKEOVER_SUFFIXES.items()
                    if chain and (chain[-1] == suffix or chain[-1].endswith("." + suffix))), None)
    return {"cname": chain, "dangling": dangling, "takeover_candidate": service if dangling else None, "error": None}
