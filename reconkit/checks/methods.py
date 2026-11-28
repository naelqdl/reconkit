"""Risky HTTP methods: PUT/DELETE advertised by OPTIONS, and TRACE echoing the request."""
from __future__ import annotations

from . import finding

NAME = "methods"
ACTIVE = True
PER = "host"


async def run(ctx, entry) -> list[dict]:
    """Two requests (OPTIONS /, TRACE /); neither changes server state."""
    if not ctx.gated(entry):
        return []
    host, out = entry["host"], []
    got = await ctx.fetch(entry, "/", method="OPTIONS")
    if got:
        allow = got[0].headers.get("allow", "")
        risky = [m for m in (p.strip().upper() for p in allow.split(",")) if m in ("PUT", "DELETE")]
        if risky:
            out.append(finding(NAME, host, "methods-put-delete-advertised", "low",
                               "OPTIONS advertises PUT/DELETE (advertised, not proven to work)",
                               f"Allow: {allow[:200]} on {entry['origin']}/ (HTTP {got[0].status_code})",
                               "Disable PUT and DELETE on paths that do not need them, and require authentication on those that do."))
    got = await ctx.fetch(entry, "/", method="TRACE")
    # Require the echoed request line: a 200 with other content is not TRACE.
    if got and got[0].status_code == 200 and got[1].startswith(b"TRACE / HTTP"):
        out.append(finding(NAME, host, "trace-enabled", "medium",
                           "HTTP TRACE is enabled and echoes the request",
                           f"TRACE / on {entry['origin']} returned HTTP 200 with the request line echoed in the body",
                           "Disable the TRACE method (for example TraceEnable off in Apache, or deny it at the proxy)."))
    return out
