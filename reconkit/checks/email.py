"""Email authentication DNS (SPF, DMARC, MTA-STS) for the scanned domain, over DoH only."""
from __future__ import annotations

from ..discover import txt_lookup
from . import finding

NAME = "email"
ACTIVE = False
PER = "target"


def _records(txts: list[str], prefix: str) -> list[str]:
    return [t.strip() for t in txts if t.strip().lower().startswith(prefix)]


async def run(ctx, entry) -> list[dict]:
    """SPF, DMARC and MTA-STS findings for ctx.target; no request ever goes to the target."""
    if ctx.lab or ctx.doh is None:
        return []
    t = ctx.target
    names = {"SPF": t, "DMARC": "_dmarc." + t, "MTA-STS": "_mta-sts." + t}
    txts = {k: await txt_lookup(n, ctx.doh, ctx.doh_url, ctx.limiter.sem) for k, n in names.items()}
    out = []

    def add(*a):
        out.append(finding(NAME, t, *a))

    failed = [k for k, v in txts.items() if v is None]
    if failed:
        add("email-dns-lookup-failed", "info", "Email DNS records could not be checked",
            f"DNS-over-HTTPS TXT lookup failed for: {', '.join(failed)}",
            "Re-run later or check that the DoH resolver is reachable.")

    if txts["SPF"] is not None:
        spf = _records(txts["SPF"], "v=spf1")
        if not spf:
            add("spf-missing", "medium", "No SPF record", f"no v=spf1 TXT record on {t}",
                f'Publish an SPF record listing your mail senders; a domain that sends no mail should publish "v=spf1 -all".')
        elif len(spf) > 1:
            add("spf-multiple", "medium", "More than one SPF record",
                f"{len(spf)} v=spf1 TXT records on {t}; receivers treat this as a permanent error",
                "Merge them into a single SPF record.")
        else:
            last = spf[0].split()[-1].lower()
            if last in ("+all", "all"):
                add("spf-pass-all", "high", "SPF allows any sender", f"SPF on {t} ends with {last}",
                    "End the record with -all (or ~all while rolling out) after listing your real senders.")
            elif last == "?all":
                add("spf-neutral-all", "low", "SPF is neutral for unlisted senders", f"SPF on {t} ends with ?all",
                    "End the record with -all (or ~all while rolling out).")

    if txts["DMARC"] is not None:
        dmarc = _records(txts["DMARC"], "v=dmarc1")
        if not dmarc:
            add("dmarc-missing", "medium", "No DMARC record", f"no v=DMARC1 TXT record on _dmarc.{t}",
                f"Publish a TXT record on _dmarc.{t}, starting with p=none and rua= reports, then move to quarantine or reject.")
        else:
            tags = {k.strip().lower(): v.strip().lower() for k, _, v in (p.partition("=") for p in dmarc[0].split(";"))}
            if tags.get("p") == "none":
                add("dmarc-policy-none", "low", "DMARC policy is monitor-only", f"DMARC on {t} has p=none",
                    "After reviewing the aggregate reports, raise the policy to p=quarantine and then p=reject.")

    if txts["MTA-STS"] is not None and not _records(txts["MTA-STS"], "v=stsv1"):
        add("mta-sts-missing", "info", "No MTA-STS policy", f"no v=STSv1 TXT record on _mta-sts.{t}",
            "Optionally publish MTA-STS so sending servers require TLS when delivering mail to you.")
    return out
