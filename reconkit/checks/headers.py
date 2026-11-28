"""Security headers and cookie flags, read from what the probe already collected (no requests)."""
from __future__ import annotations

import re

from . import Context, finding

NAME = "headers"
ACTIVE = False
PER = "host"

HSTS_MIN = 15552000  # 180 days
_VERSIONED = re.compile(r"[/ ]\d")


def _csp(value: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy into {directive: [sources]}; the first occurrence wins, as in browsers."""
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


async def run(ctx: Context, entry: dict) -> list[dict]:
    """Missing or weak security headers, version-leaking headers and cookies without Secure/HttpOnly/SameSite."""
    if not ctx.gated(entry):
        return []
    host, h = entry["host"], entry.get("headers") or {}
    https = entry["origin"].startswith("https://")
    seen = f"{entry.get('final_url') or entry['origin']} (HTTP {entry.get('status_code')})"
    out = []

    def add(id, severity, title, evidence, fix):
        out.append(finding(NAME, host, id, severity, title, evidence, fix))

    if https:
        hsts = h.get("strict-transport-security")
        if hsts is None:
            add("hsts-missing", "medium", "HSTS header missing", f"no Strict-Transport-Security header on {seen}",
                "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS response.")
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            if m and int(m.group(1)) < HSTS_MIN:
                add("hsts-short", "low", "HSTS max-age is short", f"Strict-Transport-Security max-age={m.group(1)} on {seen}",
                    f"Raise max-age to at least {HSTS_MIN} seconds (180 days); one year is common.")

    if "text/html" in h.get("content-type", "").lower():  # these headers only matter for documents
        csp = h.get("content-security-policy")
        policy = _csp(csp) if csp else {}
        if not csp:
            add("csp-missing", "low", "Content-Security-Policy missing", f"no Content-Security-Policy header on {seen}",
                "Add a Content-Security-Policy that restricts script-src to your own origin and trusted hosts.")
        else:
            scripts = policy.get("script-src", policy.get("default-src", []))
            # a nonce, hash or 'strict-dynamic' makes browsers ignore 'unsafe-inline', so it is no finding then
            safe = any(t.startswith(("'nonce-", "'sha")) or t == "'strict-dynamic'" for t in scripts)
            if "'unsafe-inline'" in scripts and not safe:
                add("csp-unsafe-inline", "low", "CSP allows inline scripts", f"script-src/default-src contains 'unsafe-inline' on {seen}",
                    "Remove 'unsafe-inline' from script-src and use nonces or hashes for the inline scripts you need.")
        if "x-frame-options" not in h and "frame-ancestors" not in policy:
            add("clickjacking", "low", "Page can be framed by other sites", f"no X-Frame-Options header or CSP frame-ancestors on {seen}",
                "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: SAMEORIGIN).")

    nosniff = h.get("x-content-type-options")
    if nosniff is None or nosniff.strip().lower() != "nosniff":
        add("nosniff-missing", "low", "X-Content-Type-Options: nosniff missing", f"X-Content-Type-Options is {nosniff!r} on {seen}" if nosniff else f"no X-Content-Type-Options header on {seen}",
            "Send X-Content-Type-Options: nosniff.")
    if "referrer-policy" not in h:
        add("referrer-policy-missing", "info", "Referrer-Policy missing", f"no Referrer-Policy header on {seen}",
            "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).")

    server = h.get("server", "")
    if _VERSIONED.search(server):
        add("server-version", "low", "Server header discloses a version", f"Server: {server} on {seen}",
            "Remove the version from the Server header (for example nginx: server_tokens off).")
    if "x-powered-by" in h:
        add("x-powered-by", "low", "X-Powered-By header present", f"X-Powered-By: {h['x-powered-by']} on {seen}",
            "Remove the X-Powered-By header in the framework or proxy configuration.")

    for c in entry.get("cookies") or []:
        name = c["name"]
        attrs = {a.split("=")[0].strip().lower() for a in c.get("attrs", "").split(";") if a.strip()}
        if https and "secure" not in attrs:
            add(f"cookie-no-secure-{name}", "medium", f"Cookie {name} lacks Secure", f"Set-Cookie {name} has no Secure attribute on {seen}",
                f"Add the Secure attribute to the {name} cookie so it is never sent over plain HTTP.")
        if "httponly" not in attrs:
            add(f"cookie-no-httponly-{name}", "low", f"Cookie {name} lacks HttpOnly", f"Set-Cookie {name} has no HttpOnly attribute on {seen}",
                f"Add HttpOnly to the {name} cookie, unless page JavaScript must read it.")
        if "samesite" not in attrs:
            add(f"cookie-no-samesite-{name}", "low", f"Cookie {name} lacks SameSite", f"Set-Cookie {name} has no SameSite attribute on {seen}",
                f"Add SameSite=Lax (or Strict) to the {name} cookie.")
    return out
