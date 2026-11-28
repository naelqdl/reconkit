"""Scope parsing and enforcement. Everything reconkit touches must pass through here."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class ScopeError(Exception):
    """Raised when the scope file is missing, empty or malformed, or the target is out of scope."""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]").split("%")[0])
        return True
    except ValueError:
        return False


def normalize(host: str) -> str:
    """Lowercase, strip the trailing dot, IDNA-encode. Raises ValueError for anything that is not a hostname."""
    h = host.strip().lower().rstrip(".")
    if not h or is_ip(h):
        raise ValueError(f"not a hostname: {host!r}")
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError(f"not a hostname: {host!r}") from e
    labels = h.split(".")
    if len(h) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise ValueError(f"not a hostname: {host!r}")
    return h


def is_valid_hostname(host: str) -> bool:
    try:
        normalize(host)
        return True
    except ValueError:
        return False


def is_public(addr: str) -> bool:
    """True only for globally routable unicast addresses (no loopback, RFC 1918, link-local, CGNAT, reserved)."""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def origin_of(url: str) -> str:
    """'scheme://host:port' of an http(s) URL, lowercased, default port made explicit. Raises ValueError.
    Hosts may be IPv4 literals or single-label names (localhost): this is only used for lab origins."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError(f"not an http(s) origin: {url!r}")
    host = parts.hostname.lower().rstrip(".")
    if is_ip(host):
        if ipaddress.ip_address(host).version != 4:
            raise ValueError(f"IPv6 lab origins aren't supported: {url!r}")  # shortcut: v4 + names only; add v6 if asked
    elif not all(_LABEL.match(label) for label in host.split(".")):
        raise ValueError(f"not a hostname: {url!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)  # .port raises ValueError when out of range
    return f"{parts.scheme}://{host}:{port}"


def lab_origin(url: str) -> str:
    """origin_of for a scope 'lab' line or --lab target: no path, query or fragment allowed."""
    parts = urlsplit(url.strip())
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError(f"a lab entry is an origin only (scheme://host:port), got {url!r}")
    return origin_of(url)


@dataclass(frozen=True)
class Scope:
    exact: frozenset[str]
    wildcard: frozenset[str]  # base domains; "*.example.com" is stored as "example.com"
    lab: frozenset[str] = frozenset()  # exact origins from 'lab URL' lines, used only with --lab

    def allows(self, host: str) -> bool:
        """Whole-label match. A wildcard covers subdomains at any depth, never the apex."""
        try:
            h = normalize(host)
        except ValueError:
            return False
        return h in self.exact or any(h.endswith("." + base) for base in self.wildcard)

    def allows_lab(self, url: str) -> bool:
        try:
            return origin_of(url) in self.lab
        except ValueError:
            return False

    def entries(self) -> list[str]:
        return sorted(self.exact) + sorted("*." + b for b in self.wildcard) + sorted("lab " + o for o in self.lab)


def parse_scope(text: str, source: str = "scope") -> Scope:
    exact: set[str] = set()
    wildcard: set[str] = set()
    lab: set[str] = set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.lower().startswith("lab "):
            try:
                lab.add(lab_origin(line[4:]))
            except ValueError as e:
                raise ScopeError(f"{source}:{n}: {e}") from None
            continue
        is_wild = line.startswith("*.")
        body = line[2:] if is_wild else line
        if "*" in body or "/" in body or ":" in body or " " in body or is_ip(body):
            raise ScopeError(f"{source}:{n}: expected 'example.com' or '*.example.com', got {raw.strip()!r}")
        try:
            host = normalize(body)
        except ValueError:
            raise ScopeError(f"{source}:{n}: expected 'example.com' or '*.example.com', got {raw.strip()!r}") from None
        (wildcard if is_wild else exact).add(host)
    if not exact and not wildcard and not lab:
        raise ScopeError(f"{source}: no scope entries (file is empty or only comments)")
    return Scope(frozenset(exact), frozenset(wildcard), frozenset(lab))


def load_scope(path: str | Path) -> Scope:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise ScopeError(f"scope file not found: {p}") from None
    except OSError as e:
        raise ScopeError(f"cannot read scope file {p}: {e}") from None
    return parse_scope(text, str(p))


def require_in_scope(scope: Scope, target: str) -> str:
    """Normalize the target and refuse to start unless it is in scope."""
    try:
        t = normalize(target)
    except ValueError:
        raise ScopeError(f"target is not a valid domain: {target!r}") from None
    if not scope.allows(t):
        raise ScopeError(f"target {t} is not in scope; refusing to run")
    return t
