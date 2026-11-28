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
from urllib.parse import urlsplit

from . import ports
from .checks import SEVERITIES, Context, cors, email, headers, methods, tls, wellknown
from .discover import DEFAULT_DOH_URL, DiscoveryError, cname_lookup, crtsh, resolve, txt_lookup
from .ports import TOP_PORTS
from .probe import USER_AGENT, Limiter, make_clients, probe_lab, probe_name
from .report import compare, write_reports
from .scope import Scope, ScopeError, is_ip, lab_origin, load_scope, normalize, require_in_scope

# check modules in run order (contract in reconkit/checks/__init__.py)
MODULES = (headers, tls, email, ports, wellknown, cors, methods)  # passive first


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


async def run_checks(ctx: Context, hosts: list[dict], modules, log=print) -> tuple[list[dict], list[str]]:
    """Run each selected module (active ones only with --active) on the hosts it may touch.
    A module that raises doesn't stop the run: its error is reported, never swallowed."""
    findings, errors = [], []
    for m in modules:
        if m.ACTIVE and not ctx.active:
            continue
        targets = [None] if m.PER == "target" else [h for h in hosts if getattr(m, "OWN_GATE", False) or ctx.gated(h)]
        results = await asyncio.gather(*(m.run(ctx, h) for h in targets), return_exceptions=True)
        for h, r in zip(targets, results):
            if isinstance(r, (KeyboardInterrupt, asyncio.CancelledError)):
                raise r
            if isinstance(r, BaseException):
                errors.append(f"{m.NAME} on {h['host'] if h else ctx.target}: {type(r).__name__}: {r}")
            else:
                findings += r
    for e in errors:
        log(f"      check error: {e}")
    return findings, errors


async def _control(target: str, doh: httpx.AsyncClient, doh_url: str, sem) -> bool | None:
    """True when DNS has TXT _reconkit.<target> = 'reconkit-verify=...': proof the user controls the domain's DNS.
    None when the lookup failed."""
    txt = await txt_lookup(f"_reconkit.{target}", doh, doh_url, sem)
    return None if txt is None else any(t.strip().lower().startswith("reconkit-verify=") for t in txt)


async def run(target: str, scope: Scope, *, concurrency: int, rate: float, timeout: float,
              doh_url: str = DEFAULT_DOH_URL, active: bool = False, lab: bool = False, discovery: bool = True,
              modules=MODULES, resolver=None, transport: httpx.AsyncBaseTransport | None = None, log=print) -> dict:
    started = _now()
    limiter = Limiter(concurrency, rate)
    names, dropped, san_names = [], 0, []
    if not lab and discovery:
        async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, trust_env=False, transport=transport) as crt:
            log(f"[1/3] querying crt.sh for {target} ...")
            names, dropped = await crtsh(target, crt)
        log(f"      {len(names)} unique names ({dropped} malformed entries dropped)")
    elif not lab:
        names = sorted(scope.exact | {target})  # wildcard entries can't be listed without discovery
        log(f"[1/3] no discovery: {len(names)} hosts from the scope file")
    else:
        log(f"[1/3] lab mode: {target} only, no discovery")

    async def res(host: str) -> list[str]:
        return await resolve(host, limiter.sem, resolver)

    log(f"[2/3] resolving and probing (concurrency {concurrency}, {rate:g} req/s) ...")
    verified, unverified = make_clients(timeout, transport)
    doh = httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, trust_env=False, timeout=timeout, transport=transport)
    async with verified, unverified, doh:
        if lab:
            host = urlsplit(target).hostname
            hosts = [await probe_lab(target, [host] if is_ip(host) else await res(host), limiter, (verified, unverified))]
        else:
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
        ran = [m.NAME for m in modules if active or not m.ACTIVE]
        log(f"      checks: {', '.join(ran) or 'none'}" + ("" if active else " (passive only; --active adds network checks)"))
        ctx = Context(scope, limiter, (verified, unverified), None if lab else doh, doh_url, target, active, lab)
        findings, errors = await run_checks(ctx, hosts, modules, log)
        control = None if lab else await _control(target, doh, doh_url, limiter.sem)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["host"], f["id"]))
    sev = Counter(f["severity"] for f in findings)
    log(f"      {len(findings)} findings (" + ", ".join(f"{sev[s]} {s}" for s in SEVERITIES) + ")")
    return {
        "schema_version": 2, "tool_version": __version__, "target": target, "scope": scope.entries(),
        "started_at": started, "finished_at": _now(),
        "settings": {"concurrency": concurrency, "rate": rate, "timeout": timeout, "doh_url": doh_url, "active": active,
                     "lab": lab, "discovery": discovery and not lab},
        "dropped_entries": dropped, "san_names": san_names, "hosts": hosts,
        "modules": ran, "findings": findings, "check_errors": errors, "control_verified": control,
        **({"active_ports": list(TOP_PORTS)} if active and "ports" in ran else {}),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="reconkit",
        description="Passive subdomain discovery (crt.sh), DNS resolution, HTTP probe and tech fingerprints, "
                    "strictly limited to the hosts in your scope file.",
        epilog="Only run reconkit against domains you own or are explicitly authorized to test.",
    )
    p.add_argument("domain", help="target domain, e.g. example.com (must be in scope); with --lab, a lab origin "
                                  "such as http://127.0.0.1:3000")
    p.add_argument("--scope", required=True,
                   help="scope file: one 'example.com', '*.example.com' or 'lab http://127.0.0.1:3000' per line")
    p.add_argument("-o", "--out", default="out", help="output directory (default: out)")
    p.add_argument("--concurrency", type=_positive(int), default=10, help="max DNS/HTTP operations in flight (default 10)")
    p.add_argument("--rate", type=_positive(float), default=5.0, help="max requests per second to target hosts (default 5)")
    p.add_argument("--timeout", type=_positive(float), default=10.0, help="seconds per HTTP request (default 10)")
    p.add_argument("--doh-url", default=DEFAULT_DOH_URL,
                   help=f"DNS-over-HTTPS JSON resolver for CNAME lookups; receives every hostname (default {DEFAULT_DOH_URL})")
    p.add_argument("--compare", metavar="FILE", help="previous report.json; adds a 'What changed' section")
    p.add_argument("--active", action="store_true",
                   help="also run checks that send requests to the target: open ports, exposed files, CORS, HTTP methods "
                        "(traffic beyond plain recon; rate-limited, at most 100 check requests per host)")
    p.add_argument("--lab", action="store_true",
                   help="test one local or staging origin listed as 'lab URL' in the scope file; private addresses are "
                        "allowed for that exact origin only, and there is no discovery")
    p.add_argument("--no-discovery", action="store_true", help="skip crt.sh: test only the exact hosts in the scope file")
    names = [m.NAME for m in MODULES]
    p.add_argument("--modules", metavar="LIST", help=f"run only these checks, comma-separated ({', '.join(names)})")
    p.add_argument("--skip", metavar="LIST", help="skip these checks, comma-separated")
    p.add_argument("--version", action="version", version=f"reconkit {__version__}")
    args = p.parse_args(argv)
    if not args.doh_url.startswith("https://"):
        p.error("--doh-url must be an https:// URL")

    def pick(text: str | None) -> set[str]:
        chosen = {x.strip() for x in (text or "").split(",") if x.strip()}
        if chosen - set(names):
            p.error(f"unknown check(s): {', '.join(sorted(chosen - set(names)))}; choose from {', '.join(names)}")
        return chosen
    only, skip = pick(args.modules), pick(args.skip)
    modules = [m for m in MODULES if (not only or m.NAME in only) and m.NAME not in skip]

    try:
        scope = load_scope(args.scope)
        if args.lab:
            try:
                target = lab_origin(args.domain)
            except ValueError as e:
                raise ScopeError(f"--lab target: {e}") from None
            if target not in scope.lab:
                raise ScopeError(f"lab origin {target} is not a 'lab' line in the scope file; refusing to run")
        else:
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
                                 doh_url=args.doh_url, active=args.active, lab=args.lab,
                                 discovery=not args.no_discovery, modules=modules))
    except DiscoveryError as e:
        print(f"reconkit: {e} (no report written)", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("reconkit: interrupted (no report written)", file=sys.stderr)
        return 130
    if old is not None:
        result["changes"] = compare(old, result)
    md, js = write_reports(result, Path(args.out))
    print(f"[3/3] wrote {md}, {js} and {md.parent / 'live-hosts.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
