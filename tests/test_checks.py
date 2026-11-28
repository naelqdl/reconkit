"""Check-module foundation: the gate around active checks, lab mode, the request budget and the findings pipeline.
No network: DNS, HTTP and DoH are injected."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import httpx

from reconkit import cli
from reconkit.checks import Context, finding
from reconkit.probe import Limiter, make_clients, probe_lab
from reconkit.report import _render_md, compare, write_reports
from reconkit.scope import ScopeError, lab_origin, parse_scope

SCOPE = parse_scope("example.com\n*.example.com\nlab http://127.0.0.1:3000\n")
IP = "93.184.215.14"
ENTRY = {"host": "www.example.com", "origin": "https://www.example.com", "addresses": [IP], "status": "ok",
         "headers": {}, "cookies": [], "tls_error": None, "tls": None, "final_url": "https://www.example.com/"}


def recorder(routes=None):
    seen = []

    def handler(request):
        seen.append((request.method, request.url.host, request.headers.get("host"), request.url.path))
        return (routes or {}).get(request.url.path, httpx.Response(404))
    return seen, httpx.MockTransport(handler)


async def with_ctx(transport, fn, *, active=True, lab=False, budget=100):
    verified, unverified = make_clients(5, transport)
    async with verified, unverified:
        ctx = Context(SCOPE, Limiter(10, 0, budget), (verified, unverified), None, "", "example.com", active, lab)
        return await fn(ctx)


class LabScope(unittest.TestCase):
    def test_lab_lines(self):
        self.assertEqual(lab_origin("HTTP://LocalHost:8080/"), "http://localhost:8080")
        self.assertEqual(lab_origin("https://staging.example.test"), "https://staging.example.test:443")
        self.assertTrue(SCOPE.allows_lab("http://127.0.0.1:3000/any/path"))
        self.assertFalse(SCOPE.allows_lab("http://127.0.0.1:3001"))   # another port is another origin
        self.assertFalse(SCOPE.allows_lab("https://127.0.0.1:3000"))  # another scheme too
        self.assertFalse(SCOPE.allows("127.0.0.1"))                   # a lab line never widens normal scope
        for bad in ("lab ftp://127.0.0.1", "lab http://127.0.0.1:3000/admin", "lab http://[::1]:3000",
                    "lab http://user:pw@127.0.0.1", "lab http://127.0.0.1:99999"):
            with self.assertRaises(ScopeError, msg=bad):
                parse_scope(bad)
        self.assertEqual(parse_scope("lab http://127.0.0.1:3000").entries(), ["lab http://127.0.0.1:3000"])

    def test_lab_redirect_leaving_origin_is_not_followed(self):
        seen, transport = recorder({"/": httpx.Response(302, headers={"location": "http://127.0.0.1:3001/"}),
                                    "/login": httpx.Response(200, html="<title>Lab</title>")})

        async def go():
            verified, unverified = make_clients(5, transport)
            async with verified, unverified:
                return await probe_lab("http://127.0.0.1:3000", ["127.0.0.1"], Limiter(10, 0), (verified, unverified))
        entry = asyncio.run(go())
        self.assertEqual(len(seen), 1)
        self.assertIn("refused: redirect leaves the lab origin", entry["attempts"][-1]["error"])

    def test_lab_same_origin_redirect_is_followed(self):
        seen, transport = recorder({"/": httpx.Response(302, headers={"location": "/login"}),
                                    "/login": httpx.Response(200, html="<title>Lab</title>", headers={"set-cookie": "sid=SECRET; Path=/"})})

        async def go():
            verified, unverified = make_clients(5, transport)
            async with verified, unverified:
                return await probe_lab("http://127.0.0.1:3000", ["127.0.0.1"], Limiter(10, 0), (verified, unverified))
        entry = asyncio.run(go())
        self.assertEqual(entry["status"], "ok")
        self.assertEqual(entry["title"], "Lab")
        self.assertEqual([s[3] for s in seen], ["/", "/login"])
        self.assertEqual(entry["cookies"], [{"name": "sid", "attrs": "Path=/"}])
        self.assertNotIn("SECRET", json.dumps(entry))  # cookie values never reach the report


class FetchGate(unittest.TestCase):
    def test_refused_without_active(self):
        seen, transport = recorder()
        with self.assertRaises(PermissionError):
            asyncio.run(with_ctx(transport, lambda ctx: ctx.fetch(ENTRY, "/x"), active=False))
        self.assertEqual(seen, [])

    def test_refused_for_entries_outside_the_gate(self):
        seen, transport = recorder()
        for bad in ({**ENTRY, "host": "evil.test", "origin": "https://evil.test"},
                    {**ENTRY, "addresses": [IP, "10.0.0.1"]},
                    {**ENTRY, "status": "unreachable"},
                    {**ENTRY, "host": "127.0.0.1:3000", "origin": "http://127.0.0.1:3000", "addresses": ["127.0.0.1"], "lab": True}):
            with self.assertRaises(PermissionError, msg=bad["host"]):
                asyncio.run(with_ctx(transport, lambda ctx: ctx.fetch(bad, "/x")))  # lab entry without --lab too
        self.assertEqual(seen, [])

    def test_pinned_and_budgeted(self):
        seen, transport = recorder()

        async def go(ctx):
            return [await ctx.fetch(ENTRY, "/a") for _ in range(3)]
        results = asyncio.run(with_ctx(transport, go, budget=2))
        self.assertIsNone(results[2])  # third request is over budget and never sent
        self.assertEqual(seen, [("GET", IP, "www.example.com", "/a")] * 2)


class Pipeline(unittest.TestCase):
    def test_module_error_is_reported_not_swallowed(self):
        class Boom:
            NAME, ACTIVE, PER = "boom", False, "host"

            @staticmethod
            async def run(ctx, entry):
                raise RuntimeError("bad parse")
        _, transport = recorder()
        findings, errors = asyncio.run(with_ctx(transport, lambda ctx: cli.run_checks(ctx, [ENTRY], [Boom], log=lambda *_: None)))
        self.assertEqual(findings, [])
        self.assertEqual(errors, ["boom on www.example.com: RuntimeError: bad parse"])

    def test_end_to_end_findings_report_and_compare(self):
        seen = []

        def handler(request):
            seen.append((request.url.host, request.headers.get("host"), request.url.path))
            if request.url.host == "cloudflare-dns.com":
                return httpx.Response(200, json={"Status": 0, "Answer": []})
            if request.url.path == "/.git/HEAD":
                return httpx.Response(200, text="ref: refs/heads/main\n")
            return httpx.Response(200, html="<title>Shop</title>", headers={"set-cookie": "sid=abc; Path=/"})

        async def resolver(host):
            return [IP]
        modules = [m for m in cli.MODULES if m.NAME != "ports"]  # ports would open real sockets
        result = asyncio.run(cli.run("example.com", parse_scope("example.com\nwww.example.com"), concurrency=4, rate=1000,
                                     timeout=5, active=True, discovery=False, modules=modules, resolver=resolver,
                                     transport=httpx.MockTransport(handler), log=lambda *_: None))
        target_requests = [s for s in seen if s[0] != "cloudflare-dns.com"]
        self.assertTrue(target_requests and all(s[0] == IP for s in target_requests))
        self.assertTrue({s[1] for s in target_requests} <= {"example.com", "www.example.com"})
        ids = {(f["host"], f["id"]) for f in result["findings"]}
        self.assertIn(("www.example.com", "git-exposed"), ids)
        self.assertIn(("www.example.com", "hsts-missing"), ids)
        self.assertIn(("example.com", "spf-missing"), ids)
        self.assertEqual(result["check_errors"], [])
        self.assertFalse(result["control_verified"])
        self.assertEqual(result["findings"][0]["severity"], "high")  # sorted by severity
        md = _render_md(result)
        self.assertIn("## Findings", md)
        self.assertIn("Git repository is publicly readable", md)
        self.assertNotIn("abc", json.dumps(result["hosts"]))

        fixed = {**result, "findings": [f for f in result["findings"] if f["id"] != "git-exposed"]}
        c = compare(result, fixed)
        self.assertEqual([f["id"] for f in c["fixed_findings"]], ["git-exposed", "git-exposed"])
        self.assertEqual(c["new_findings"], [])
        self.assertNotIn("new_findings", compare({"hosts": []}, result))  # v1 report: no findings to compare

        with tempfile.TemporaryDirectory() as d:
            write_reports(result, d)
            self.assertEqual((Path(d) / "live-hosts.txt").read_text(encoding="utf-8"),
                             "https://example.com\nhttps://www.example.com\n")

    def test_finding_rejects_unknown_severity(self):
        with self.assertRaises(ValueError):
            finding("x", "h", "id", "critical", "t", "e", "f")


if __name__ == "__main__":
    unittest.main()
