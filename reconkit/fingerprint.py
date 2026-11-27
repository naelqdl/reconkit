"""Built-in technology signatures and a pure matcher (no network)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import NamedTuple


class Signature(NamedTuple):
    """One rule. Every field is a tuple of lowercase needles; any hit matches."""

    name: str
    headers: tuple[tuple[str, str], ...] = ()  # (header, substring)
    header_present: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()  # exact cookie names
    html: tuple[str, ...] = ()  # substrings


SIGNATURES: tuple[Signature, ...] = (
    Signature("nginx", headers=(("server", "nginx"),)),
    Signature("Apache", headers=(("server", "apache"),)),
    Signature(
        "Cloudflare",
        headers=(("server", "cloudflare"),),
        header_present=("cf-ray",),
        cookies=("__cf_bm", "__cfruid", "cf_clearance"),
    ),
    Signature(
        "WordPress",
        headers=(("link", "api.w.org"),),
        html=("/wp-content/", "/wp-includes/"),
    ),
    Signature(
        "Next.js",
        headers=(("x-powered-by", "next.js"),),
        html=("__next_data__", "/_next/static/"),
    ),
    Signature("Express", headers=(("x-powered-by", "express"),)),
    Signature("PHP", headers=(("x-powered-by", "php"),), cookies=("PHPSESSID",)),
)

# Not table-driven: needs a regex-free but structured check (meta generator tag).
_GENERATOR_RULES = {"WordPress": "wordpress"}


def _generators(html: str) -> list[str]:
    """Return lowercase content values of <meta name="generator"> tags."""
    out: list[str] = []
    low = html.lower()
    pos = 0
    while (start := low.find("<meta", pos)) != -1:
        end = low.find(">", start)
        if end == -1:
            break
        tag = low[start:end]
        pos = end
        if "name=\"generator\"" in tag or "name='generator'" in tag:
            for q in ('content="', "content='"):
                i = tag.find(q)
                if i != -1:
                    i += len(q)
                    out.append(tag[i:].split(q[-1], 1)[0].strip())
                    break
    return out


def match(headers: Mapping[str, str], set_cookies: Sequence[str], html: str) -> dict[str, list[str]]:
    """Return {technology: [evidence, ...]} for every signature that matched the response."""
    hdr = {k.lower(): v.lower() for k, v in headers.items()}
    names = {c.split("=", 1)[0].strip() for c in set_cookies}
    low = html.lower()
    gens = _generators(html)
    found: dict[str, list[str]] = {}
    for s in SIGNATURES:
        rule = _GENERATOR_RULES.get(s.name)
        evidence = (
            [f"header {h}: {hdr[h][:100]}" for h, needle in s.headers if needle in hdr.get(h, "")]
            + [f"header {h} present" for h in s.header_present if h in hdr]
            + [f"cookie {c}" for c in s.cookies if c in names]
            + [f"html {n}" for n in s.html if n in low]
            + [f"meta generator: {g[:100]}" for g in gens if rule and g.startswith(rule)]
        )
        if evidence:
            found[s.name] = evidence
    return found
