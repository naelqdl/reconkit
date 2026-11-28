"""Active check: does the host trust a foreign or null Origin, and does it allow credentials with it."""
from __future__ import annotations

from . import Context, finding

NAME = "cors"
ACTIVE = True
PER = "host"

FOREIGN = "https://reconkit-cors-check.invalid"
FIX = ("Answer cross-origin requests from an explicit allowlist of trusted origins, never by echoing the Origin "
       "header, and send Access-Control-Allow-Credentials only for origins on that list.")


async def _probe(ctx: Context, entry: dict, origin: str):
    """(ACAO, credentials allowed, status) for a GET / carrying this Origin, or None if no response."""
    got = await ctx.fetch(entry, "/", headers={"Origin": origin})
    if got is None:
        return None
    resp = got[0]
    acao = resp.headers.get("access-control-allow-origin", "").strip()
    creds = resp.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    return acao, creds, resp.status_code


async def run(ctx: Context, entry: dict | None) -> list[dict]:
    """Send two GETs (foreign Origin, null Origin) and report trusting policies."""
    if entry is None or not ctx.active or not ctx.gated(entry):
        return []
    host, out = entry["host"], []
    where = entry["origin"] + "/"

    got = await _probe(ctx, entry, FOREIGN)
    if got:
        acao, creds, code = got
        seen = f"Access-Control-Allow-Origin: {acao}" + (", Access-Control-Allow-Credentials: true" if creds else "")
        if acao == FOREIGN and creds:
            out.append(finding(NAME, host, "cors-reflected-origin-credentials", "high",
                               "Any origin is trusted with credentials",
                               f"{where} (HTTP {code}) echoed the arbitrary Origin {FOREIGN}: {seen}", FIX))
        elif acao == FOREIGN:
            out.append(finding(NAME, host, "cors-reflected-origin", "low",
                               "Arbitrary Origin is reflected",
                               f"{where} (HTTP {code}) echoed the arbitrary Origin {FOREIGN}: {seen}", FIX))
        elif acao == "*" and creds:
            out.append(finding(NAME, host, "cors-wildcard-credentials", "low",
                               "Wildcard CORS combined with credentials",
                               f"{where} (HTTP {code}) sent {seen}; browsers block this pair, but it shows the policy is hand-rolled",
                               "Drop Access-Control-Allow-Credentials, or answer from an explicit origin allowlist instead of \"*\"."))

    got = await _probe(ctx, entry, "null")
    if got:
        acao, creds, code = got
        if acao == "null":
            seen = "Access-Control-Allow-Origin: null" + (", Access-Control-Allow-Credentials: true" if creds else "")
            out.append(finding(NAME, host, "cors-null-origin-credentials" if creds else "cors-null-origin",
                               "high" if creds else "low", "Origin null is trusted" + (" with credentials" if creds else ""),
                               f"{where} (HTTP {code}) accepted Origin: null: {seen}",
                               "Never allow the null origin (sandboxed iframes and local files can send it); use an explicit allowlist."))
    return out
