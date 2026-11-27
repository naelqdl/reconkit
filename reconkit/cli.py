"""reconkit command line: scope-checked recon of one authorized domain into report.md + report.json."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import httpx

from . import __version__
from .discover import DEFAULT_DOH_URL, DiscoveryError, cname_lookup, crtsh, resolve
from .probe import USER_AGENT, Limiter, make_clients, probe_name
from .report import compare, write_reports
from .scope import Scope, ScopeError, load_scope, normalize, require_in_scope


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _positive(kind):
    def parse(text: str):
        value = kind(text)
        if value <= 0:
            raise argparse.ArgumentTypeError("must be greater than 0")
        return value
    return parse


def _san_names(hosts: list[dict], scope: Scope) -> set[str]:
    """In-scope names from verified certificate SANs; wildcard entries can't be probed."""
    out = set()
    for h in hosts:
        for san in (h.get("tls") or {}).get("san", []):
            try:
                name = normalize(san)
            except ValueError:
                continue
            if not san.startswith("*.") and scope.allows(name):
                out.add(name)
    return out


async def run(target: str, scope: Scope, *, concurrency: int, rate: float, timeout: float,
              doh_url: str = DEFAULT_DOH_URL, resolver=None, transport: httpx.AsyncBaseTransport | None = None, log=print) -> dict:
    started = _now()
    limiter = Limiter(concurrency, rate)
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, trust_env=False, transport=transport) as crt:
        log(f"[1/3] querying crt.sh for {target} ...")
        names, dropped = await crtsh(target, crt)
    log(f"      {len(names)} unique names ({dropped} malformed entries dropped)")

    async def res(host: str) -> list[str]:
        return await resolve(host, limiter.sem, resolver)

    log(f"[2/3] resolving and probing (concurrency {concurrency}, {rate:g} req/s) ...")
    verified, unverified = make_clients(timeout, transport)
    doh = httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, trust_env=False, timeout=timeout, transport=transport)
    async with verified, unverified, doh:
        async def cname(host: str) -> dict:
            return await cname_lookup(host, doh, doh_url, limiter.sem)

        async def probe_all(batch):
            return list(await asyncio.gather(*(probe_name(n, scope, limiter, (verified, unverified), res, cname) for n in batch)))

        hosts = await probe_all(names)
        # one extra round only: names found in the new round's certificates are listed, not followed
        san_names = sorted(_san_names(hosts, scope) - set(names))
        if san_names:
            log(f"      {len(san_names)} more in-scope names from certificates, probing ...")
            hosts += await probe_all(san_names)
    counts = Counter(h["status"] for h in hosts)
    log("      " + ", ".join(f"{counts[k]} {k}" for k in ("ok", "unreachable", "refused", "unresolved")))
    return {
        "schema_version": 1, "tool_version": __version__, "target": target, "scope": scope.entries(),
        "started_at": started, "finished_at": _now(),
        "settings": {"concurrency": concurrency, "rate": rate, "timeout": timeout, "doh_url": doh_url},
        "dropped_entries": dropped, "san_names": san_names, "hosts": hosts,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="reconkit",
        description="Passive subdomain discovery (crt.sh), DNS resolution, HTTP probe and tech fingerprints, "
                    "strictly limited to the hosts in your scope file.",
        epilog="Only run reconkit against domains you own or are explicitly authorized to test.",
    )
    p.add_argument("domain", help="target domain, e.g. example.com (must be in scope)")
    p.add_argument("--scope", required=True, help="scope file: one 'example.com' or '*.example.com' per line")
    p.add_argument("-o", "--out", default="out", help="output directory (default: out)")
    p.add_argument("--concurrency", type=_positive(int), default=10, help="max DNS/HTTP operations in flight (default 10)")
    p.add_argument("--rate", type=_positive(float), default=5.0, help="max requests per second to target hosts (default 5)")
    p.add_argument("--timeout", type=_positive(float), default=10.0, help="seconds per HTTP request (default 10)")
    p.add_argument("--doh-url", default=DEFAULT_DOH_URL,
                   help=f"DNS-over-HTTPS JSON resolver for CNAME lookups; receives every hostname (default {DEFAULT_DOH_URL})")
    p.add_argument("--compare", metavar="FILE", help="previous report.json; adds a 'What changed' section")
    p.add_argument("--version", action="version", version=f"reconkit {__version__}")
    args = p.parse_args(argv)
    if not args.doh_url.startswith("https://"):
        p.error("--doh-url must be an https:// URL")

    try:
        scope = load_scope(args.scope)
        target = require_in_scope(scope, args.domain)
    except ScopeError as e:
        print(f"reconkit: {e}", file=sys.stderr)
        return 2
    old = None
    if args.compare:  # checked before any traffic, like the scope file
        try:
            old = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"reconkit: --compare: {e}", file=sys.stderr)
            return 2
        hosts = old.get("hosts") if isinstance(old, dict) else None
        if not isinstance(hosts, list) or not all(isinstance(h, dict) and "host" in h and "status" in h for h in hosts):
            print(f"reconkit: --compare: {args.compare} is not a reconkit report.json", file=sys.stderr)
            return 2
        if old.get("target") != target:
            print(f"reconkit: --compare: report is for {old.get('target')!r}, not {target!r}", file=sys.stderr)
            return 2
    try:
        result = asyncio.run(run(target, scope, concurrency=args.concurrency, rate=args.rate, timeout=args.timeout,
                                 doh_url=args.doh_url))
    except DiscoveryError as e:
        print(f"reconkit: {e} (no report written)", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("reconkit: interrupted (no report written)", file=sys.stderr)
        return 130
    if old is not None:
        result["changes"] = compare(old, result)
    md, js = write_reports(result, Path(args.out))
    print(f"[3/3] wrote {md} and {js}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
