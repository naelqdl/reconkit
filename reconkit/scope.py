"""Scope parsing and enforcement. Everything reconkit touches must pass through here."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

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


@dataclass(frozen=True)
class Scope:
    exact: frozenset[str]
    wildcard: frozenset[str]  # base domains; "*.example.com" is stored as "example.com"

    def allows(self, host: str) -> bool:
        """Whole-label match. A wildcard covers subdomains at any depth, never the apex."""
        try:
            h = normalize(host)
        except ValueError:
            return False
        return h in self.exact or any(h.endswith("." + base) for base in self.wildcard)

    def entries(self) -> list[str]:
        return sorted(self.exact) + sorted("*." + b for b in self.wildcard)


def parse_scope(text: str, source: str = "scope") -> Scope:
    exact: set[str] = set()
    wildcard: set[str] = set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
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
    if not exact and not wildcard:
        raise ScopeError(f"{source}: no scope entries (file is empty or only comments)")
    return Scope(frozenset(exact), frozenset(wildcard))


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
