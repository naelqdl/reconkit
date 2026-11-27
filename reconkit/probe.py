"""HTTP(S) probe that only connects to vetted public IPs and checks every redirect hop against scope."""
from __future__ import annotations

import asyncio
import html as htmllib
import re
import ssl
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urljoin, urlsplit

import httpx

from . import __version__
from .fingerprint import match
from .scope import Scope, is_ip, is_public, normalize

MAX_REDIRECTS = 5
MAX_BODY = 256 * 1024
USER_AGENT = f"reconkit/{__version__} (authorized security testing)"
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

Resolver = Callable[[str], Awaitable[list[str]]]


class Limiter:
    """Caps requests in flight (the semaphore is shared with DNS) and paces requests to target hosts."""

    def __init__(self, concurrency: int, rate: float) -> None:
        self.sem = asyncio.Semaphore(concurrency)
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait_turn(self) -> None:
        if not self._interval:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self._interval
        if delay > 0:
            await asyncio.sleep(delay)


def make_clients(timeout: float, transport: httpx.AsyncBaseTransport | None = None) -> tuple[httpx.AsyncClient, httpx.AsyncClient]:
    """(verifying, non-verifying) clients. Keep-alive and HTTP/2 stay off: pooled connections are keyed on
    scheme+IP+port only, so reuse could carry one hostname's SNI to another host on a shared IP."""
    common = dict(
        timeout=timeout,
        limits=httpx.Limits(max_keepalive_connections=0),
        http2=False,
        follow_redirects=False,
        trust_env=False,  # a proxy from the environment would bypass IP pinning
        headers={"User-Agent": USER_AGENT},
        transport=transport,
    )
    return httpx.AsyncClient(verify=True, **common), httpx.AsyncClient(verify=False, **common)


def tls_error(exc: BaseException) -> str | None:
    """httpx wraps TLS failures in ConnectError; walk the cause chain for the ssl error."""
    seen: set[int] = set()
    e: BaseException | None = exc
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if isinstance(e, ssl.SSLCertVerificationError):
            return e.verify_message or str(e)
        if isinstance(e, ssl.SSLError):
            return e.reason or str(e)
        e = e.__cause__ or e.__context__
    return None


def _ordered(addresses: list[str]) -> list[str]:
    v4 = [a for a in addresses if ":" not in a]
    return (v4 + [a for a in addresses if ":" in a])[:2]  # first address, plus one fallback


def _error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}".strip().rstrip(":") or type(exc).__name__


async def _fetch(client: httpx.AsyncClient, url: str, ip: str, limiter: Limiter) -> tuple[httpx.Response, bytes]:
    """GET url while connecting to ip: URL host = ip, Host header and SNI = the real hostname."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    pinned = parts._replace(netloc=(f"[{ip}]" if ":" in ip else ip) + port).geturl()
    ext = {"sni_hostname": host} if parts.scheme == "https" else {}
    request = client.build_request("GET", pinned, headers={"Host": host + port}, extensions=ext)
    await limiter.wait_turn()
    async with limiter.sem:
        response = await client.send(request, stream=True)
        body = bytearray()
        try:
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) >= MAX_BODY:
                    break
        finally:
            await response.aclose()
    return response, bytes(body[:MAX_BODY])


async def _follow(client, start_url, addresses, scope, limiter, resolve, attempts):
    """Fetch start_url and follow redirects by hand. Returns (last_response, body, last_url, error)."""
    url, ips, current = start_url, addresses, urlsplit(start_url).hostname
    for hop in range(MAX_REDIRECTS + 1):
        response = body = None
        error: BaseException | None = None
        for ip in _ordered(ips):
            try:
                response, body = await _fetch(client, url, ip, limiter)
                break
            except httpx.HTTPError as e:
                error = e
                if tls_error(e):
                    break  # a TLS failure won't change on another address
        if response is None:
            attempts.append({"url": url, "status_code": None, "error": tls_error(error) and f"tls: {tls_error(error)}" or _error_text(error)})
            return None, b"", url, error
        record = {"url": url, "status_code": response.status_code, "error": None}
        attempts.append(record)
        location = response.headers.get("location")
        if not (response.is_redirect and location):
            return response, body, url, None
        if hop == MAX_REDIRECTS:
            record["error"] = "stopped: too many redirects"
            return response, body, url, None
        # resolve against the hostname URL, never response.next_request (it carries the pinned IP)
        nxt = urljoin(url, location.strip())
        parts = urlsplit(nxt)
        host = parts.hostname
        refusal = None
        if parts.scheme not in ("http", "https"):
            refusal = f"refused: non-http redirect ({parts.scheme or 'none'})"
        elif not host or is_ip(host):
            refusal = f"refused: IP-literal redirect ({host})"
        elif not scope.allows(host):
            refusal = f"refused: out of scope ({host})"
        if refusal is None and normalize(host) != current:
            new_ips = await resolve(normalize(host))
            if not new_ips:
                refusal = f"refused: unresolved redirect target ({host})"
            elif not all(is_public(a) for a in new_ips):
                refusal = f"refused: non-public address ({host})"
            else:
                ips, current = new_ips, normalize(host)
        if refusal:
            record["error"] = refusal
            return response, body, url, None
        url = nxt
    raise AssertionError("unreachable")


def _title(body: bytes, encoding: str | None) -> str | None:
    m = _TITLE.search(body)
    if not m:
        return None
    text = m.group(1).decode(encoding or "utf-8", errors="replace")
    return " ".join(htmllib.unescape(text).split()) or None


async def probe_host(host: str, addresses: list[str], scope: Scope, limiter: Limiter,
                     clients: tuple[httpx.AsyncClient, httpx.AsyncClient], resolve: Resolver) -> dict:
    """Probe a resolved, public, in-scope host. https (verified) first; on a TLS error record it and
    retry unverified; plain http only when the https connection itself fails."""
    verified, unverified = clients
    entry = {"host": host, "addresses": addresses, "status": "unreachable", "reason": None, "attempts": [],
             "final_url": None, "status_code": None, "title": None, "server": None, "tls_error": None, "tech": [],
             "tech_evidence": {}}
    attempts = entry["attempts"]
    response, body, url, error = await _follow(verified, f"https://{host}/", addresses, scope, limiter, resolve, attempts)
    if response is None and error is not None and tls_error(error):
        entry["tls_error"] = tls_error(error)
        response, body, url, error = await _follow(unverified, f"https://{host}/", addresses, scope, limiter, resolve, attempts)
    if response is None:
        response, body, url, error = await _follow(verified, f"http://{host}/", addresses, scope, limiter, resolve, attempts)
    if response is None:
        entry["reason"] = _error_text(error) if error else "no response"
        return entry
    html = body.decode(response.encoding or "utf-8", errors="replace")
    evidence = match(response.headers, response.headers.get_list("set-cookie"), html)
    entry.update(
        status="ok",
        final_url=url,
        status_code=response.status_code,
        title=_title(body, response.encoding),
        server=response.headers.get("server"),
        tech=sorted(evidence),
        tech_evidence=evidence,
    )
    return entry


async def probe_name(name: str, scope: Scope, limiter: Limiter,
                     clients: tuple[httpx.AsyncClient, httpx.AsyncClient], resolve: Resolver) -> dict:
    """Scope check, resolve, refuse non-public addresses, then probe. The single entry point per host."""
    base = {"host": name, "addresses": [], "status": "refused", "reason": None, "attempts": [],
            "final_url": None, "status_code": None, "title": None, "server": None, "tls_error": None, "tech": [], "tech_evidence": {}}
    if not scope.allows(name):
        return {**base, "reason": "out of scope"}
    addresses = await resolve(name)
    if not addresses:
        return {**base, "status": "unresolved"}
    private = [a for a in addresses if not is_public(a)]
    if private:
        return {**base, "addresses": addresses, "reason": f"non-public address ({private[0]})"}
    return await probe_host(name, addresses, scope, limiter, clients, resolve)
