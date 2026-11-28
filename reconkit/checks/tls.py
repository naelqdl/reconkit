"""TLS check: invalid or expiring certificate, no HTTPS, plain HTTP that does not redirect to HTTPS."""
from __future__ import annotations

from datetime import date

from . import Context, finding

NAME = "tls"
ACTIVE = False
PER = "host"


def _today() -> date:
    return date.today()


async def run(ctx: Context, entry: dict) -> list[dict]:
    """Findings about the host's certificate and HTTP-to-HTTPS behaviour."""
    if not ctx.gated(entry):
        return []
    host, origin, out = entry["host"], entry["origin"], []

    def add(id: str, severity: str, title: str, evidence: str, fix: str) -> None:
        out.append(finding(NAME, host, id, severity, title, evidence, fix))

    if entry.get("tls_error"):
        add("tls-invalid-cert", "high", "TLS certificate is not valid", entry["tls_error"],
            "Install a certificate from a trusted CA that covers this hostname and is not expired.")
    try:
        days = (date.fromisoformat(entry["tls"]["expires"]) - _today()).days
    except (TypeError, KeyError, ValueError):
        days = None
    if days is not None and days <= 30:
        when = f"expired {-days} days ago" if days < 0 else f"expires in {days} days"
        add("tls-expiring", "high" if days <= 14 else "medium", "TLS certificate is expiring soon",
            f"certificate for {host} {when} ({entry['tls']['expires']})",
            "Renew the certificate now and automate renewal (for example ACME) so it cannot lapse.")

    if entry.get("lab"):
        return out
    if origin.startswith("http://"):
        add("no-https", "medium", "Site is served over plain HTTP only", f"{origin} answered without TLS",
            "Serve the site over HTTPS and redirect all HTTP traffic to it.")
    elif origin.startswith("https://") and ctx.active:
        got = await ctx.fetch(entry, "/", scheme="http")
        if got:
            resp = got[0]
            location = resp.headers.get("location", "")
            if 200 <= resp.status_code < 300 or (300 <= resp.status_code < 400 and location.startswith("http://")):
                add("http-not-redirected", "medium", "HTTP does not redirect to HTTPS",
                    f"http://{host}/ answered HTTP {resp.status_code}"
                    + (f" with a redirect to {location}" if location else "") + " instead of redirecting to https",
                    "Redirect all plain HTTP requests to the HTTPS site (301) and send HSTS on HTTPS.")
    return out
