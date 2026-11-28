"""Check modules turn gated host entries into findings.

A module is a Python module in this package (or reconkit.ports) with:
    NAME: str              short id, used by --modules / --skip and in each finding's "module"
    ACTIVE: bool           True if it sends traffic to the target; runs only with --active
    PER: "host" | "target" run once per gated host entry, or once per run with entry=None
    async def run(ctx: Context, entry: dict | None) -> list[dict]   findings, built with finding()

Passive modules only read what the probe already collected (entry["headers"], ["cookies"], ["tls"], ...)
or query DNS over HTTPS (ctx.doh), which never touches the target. Active modules send requests only
through ctx.fetch, which refuses outside --active, re-checks the scope gate, pins the vetted IP, follows
no redirects and charges the per-host request budget.

    probe entries --> gated? --> module.run --> findings --> report.md "Findings" / report.json "findings"
                         +--> ctx.fetch (active only) --> _fetch pinned to vetted IP, budget-charged
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from ..probe import Limiter, _fetch, _ordered
from ..scope import Scope, is_public

SEVERITIES = ("high", "medium", "low", "info")


def finding(module: str, host: str, id: str, severity: str, title: str, evidence: str, fix: str) -> dict:
    """One finding. id is stable across runs (--compare matches on host + id); evidence says what was seen."""
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}, got {severity!r}")
    return {"module": module, "host": host, "id": id, "severity": severity, "title": title,
            "evidence": evidence, "fix": fix}


@dataclass
class Context:
    scope: Scope
    limiter: Limiter
    clients: tuple[httpx.AsyncClient, httpx.AsyncClient]  # (verifying, non-verifying), from probe.make_clients
    doh: httpx.AsyncClient | None
    doh_url: str
    target: str
    active: bool
    lab: bool = False

    def gated(self, entry: dict) -> bool:
        """The entry answered HTTP and passed the scope gate: in scope with only public addresses,
        or (with --lab) it is exactly a lab origin from the scope file."""
        if entry.get("status") != "ok" or not entry.get("addresses") or not entry.get("origin"):
            return False
        if entry.get("lab"):
            return self.lab and self.scope.allows_lab(entry["origin"])
        return self.scope.allows(entry["host"]) and all(is_public(a) for a in entry["addresses"])

    async def fetch(self, entry: dict, path: str = "/", *, method: str = "GET", headers: dict | None = None,
                    scheme: str | None = None) -> tuple[httpx.Response, bytes] | None:
        """One request to the entry's origin + path, pinned to its vetted IP, redirects not followed.
        Returns None when the host's request budget is used up or the request fails.
        Raises PermissionError outside --active or for an entry that isn't gated."""
        if not self.active:
            raise PermissionError("network check requested without --active")
        if not self.gated(entry):
            raise PermissionError(f"{entry.get('host')} did not pass the scope gate")
        if not path.startswith("/"):
            raise ValueError(f"path must start with '/', got {path!r}")
        parts = urlsplit(entry["origin"])
        if scheme and scheme != parts.scheme:
            if entry.get("lab"):
                return None  # a lab entry is one exact origin; another scheme is another origin
            base = f"{scheme}://{parts.hostname}"
        else:
            base = entry["origin"]
        if not self.limiter.charge(entry["host"]):
            return None
        verified, unverified = self.clients
        client = unverified if entry.get("tls_error") else verified
        try:
            return await _fetch(client, base + path, _ordered(entry["addresses"])[0], self.limiter, {},
                                method=method, headers=headers)
        except httpx.HTTPError:
            return None
