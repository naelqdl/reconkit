"""Scope enforcement: the security-critical logic. No network: DNS and HTTP are injected."""
import asyncio
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import httpx

from reconkit.cli import main
from reconkit.discover import cname_lookup
from reconkit.fingerprint import match
from reconkit.probe import Limiter, cert_summary, make_clients, probe_name
from reconkit.report import compare
from reconkit.scope import ScopeError, load_scope, parse_scope, require_in_scope

SCOPE = parse_scope("example.com\n*.example.com\nshop.example.org  # exact only\n")


def run_probe(name, routes, dns):
    """Probe one name against a fake network. routes: {(host_header, path): response}. Returns (entry, requests)."""
    seen = []

    def handler(request):
        seen.append((request.headers["host"], request.url.host, request.url.path))
        resp = routes.get((request.headers["host"], request.url.path))
        if resp is None:
            raise AssertionError(f"unexpected request to {request.headers['host']}{request.url.path}")
        return resp

    async def resolver(host):
        return dns.get(host, [])

    async def go():
        verified, unverified = make_clients(5, httpx.MockTransport(handler))
        async with verified, unverified:
            return await probe_name(name, SCOPE, Limiter(4, 0), (verified, unverified), resolver)

    return asyncio.run(go()), seen


class ScopeRules(unittest.TestCase):
    def test_exact_host(self):
        self.assertTrue(SCOPE.allows("shop.example.org"))
        self.assertFalse(SCOPE.allows("www.example.org"))

    def test_wildcard_any_depth(self):
        self.assertTrue(SCOPE.allows("a.example.com"))
        self.assertTrue(SCOPE.allows("a.b.c.example.com"))

    def test_wildcard_never_apex(self):
        only_wild = parse_scope("*.example.net")
        self.assertFalse(only_wild.allows("example.net"))
        self.assertTrue(only_wild.allows("x.example.net"))

    def test_deceptive_suffixes(self):
        for host in ("evil-example.com", "example.com.evil.test", "notexample.com", "example.co"):
            self.assertFalse(SCOPE.allows(host), host)

    def test_normalization(self):
        self.assertTrue(SCOPE.allows("WWW.Example.COM."))
        self.assertTrue(parse_scope("Example.COM.").allows("example.com"))

    def test_malformed_lines(self):
        for line in ("https://example.com", "10.0.0.1", "example.com/path", "*example.com", "a.*.example.com", "example.com:443"):
            with self.assertRaises(ScopeError, msg=line):
                parse_scope(line)

    def test_missing_empty_and_comment_only_files(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ScopeError):
                load_scope(Path(d) / "nope.txt")
            for content in ("", "\n\n", "# only comments\n   # here\n"):
                p = Path(d) / "scope.txt"
                p.write_text(content, encoding="utf-8")
                with self.assertRaises(ScopeError, msg=repr(content)):
                    load_scope(p)

    def test_out_of_scope_target_refused_before_any_work(self):
        with self.assertRaises(ScopeError):
            require_in_scope(SCOPE, "example.org")
        with tempfile.TemporaryDirectory() as d:
            scope_file = Path(d) / "scope.txt"
            scope_file.write_text("*.example.com\n", encoding="utf-8")
            out = Path(d) / "out"
            with contextlib.redirect_stderr(io.StringIO()) as err:
                code = main(["example.org", "--scope", str(scope_file), "-o", str(out)])
            self.assertEqual(code, 2)
            self.assertIn("not in scope", err.getvalue())
            self.assertFalse(out.exists())


class ProbeEnforcement(unittest.TestCase):
    def test_non_public_addresses_never_contacted(self):
        for addr in ("127.0.0.1", "169.254.169.254", "10.1.2.3", "::1"):
            entry, seen = run_probe("internal.example.com", {}, {"internal.example.com": ["93.184.215.14", addr]})
            self.assertEqual(entry["status"], "refused", addr)
            self.assertIn("non-public address", entry["reason"])
            self.assertEqual(seen, [], addr)

    def test_redirect_out_of_scope_is_not_followed(self):
        routes = {("www.example.com", "/"): httpx.Response(302, headers={"location": "https://evil.test/steal"})}
        entry, seen = run_probe("www.example.com", routes, {"www.example.com": ["93.184.215.14"], "evil.test": ["1.2.3.4"]})
        self.assertEqual([s[0] for s in seen], ["www.example.com"])
        self.assertEqual(seen[0][1], "93.184.215.14")  # connected to the vetted IP, not a fresh lookup
        self.assertEqual(entry["attempts"][-1]["error"], "refused: out of scope (evil.test)")

    def test_relative_redirect_resolved_against_hostname(self):
        routes = {
            ("www.example.com", "/"): httpx.Response(301, headers={"location": "/home"}),
            ("www.example.com", "/home"): httpx.Response(200, html="<title>Home</title>"),
        }
        entry, seen = run_probe("www.example.com", routes, {"www.example.com": ["93.184.215.14"]})
        self.assertEqual(entry["status"], "ok")
        self.assertEqual(entry["final_url"], "https://www.example.com/home")
        self.assertEqual(entry["title"], "Home")
        self.assertEqual([s[0] for s in seen], ["www.example.com", "www.example.com"])


    def test_active_ports_only_on_vetted_hosts(self):
        from reconkit.ports import TOP_PORTS, check_ports

        class Writer:
            def close(self): pass
            async def wait_closed(self): pass

        calls = []

        async def connect(ip, port):
            calls.append((ip, port))
            if port == 443:
                return None, Writer()
            raise ConnectionRefusedError

        hosts = [
            {"host": "www.example.com", "status": "ok", "addresses": ["2606:2800::1", "93.184.215.14"]},
            {"host": "mail.example.com", "status": "unreachable", "addresses": ["93.184.215.15"]},
            {"host": "internal.example.com", "status": "refused", "addresses": ["10.0.0.1"]},
            {"host": "gone.example.com", "status": "unresolved", "addresses": []},
            {"host": "evil.test", "status": "ok", "addresses": ["1.2.3.4"]},  # can't happen; the module re-checks
            {"host": "mixed.example.com", "status": "ok", "addresses": ["93.184.215.16", "127.0.0.1"]},
        ]

        async def go():
            await asyncio.gather(*(check_ports(h, SCOPE, Limiter(10, 0), 1.0, connect) for h in hosts))
        asyncio.run(go())
        self.assertEqual(sorted({ip for ip, _ in calls}), ["93.184.215.14", "93.184.215.15"])  # IPv4 first, vetted only
        self.assertEqual(len(calls), 2 * len(TOP_PORTS))
        self.assertEqual(hosts[0]["open_ports"], [443])
        self.assertEqual(hosts[0]["ports_ip"], "93.184.215.14")
        for h in hosts[2:]:
            self.assertNotIn("open_ports", h)
        changes = compare({"hosts": [{**hosts[0], "open_ports": [22]}]}, {"hosts": [hosts[0]]})["changed"]
        self.assertEqual(changes, [{"host": "www.example.com", "changes": {"open_ports": {"old": [22], "new": [443]}}}])


class ReportFeatures(unittest.TestCase):
    """v1.1: not scope logic, kept here to stay at one test file."""

    def test_fingerprint_evidence(self):
        html = '<meta name="generator" content="WordPress 6.4"><link href="/wp-content/x.css">'
        ev = match({"Server": "nginx/1.25", "CF-Ray": "abc"}, ["PHPSESSID=1; path=/"], html)
        self.assertEqual(ev["nginx"], ["header server: nginx/1.25"])
        self.assertEqual(ev["Cloudflare"], ["header cf-ray present"])
        self.assertEqual(ev["PHP"], ["cookie PHPSESSID"])
        self.assertEqual(ev["WordPress"], ["html /wp-content/", "meta generator: wordpress 6.4"])

    def test_compare(self):
        ok = {"status": "ok", "status_code": 200, "final_url": "https://a.example.com/", "tls_error": None, "tech": ["nginx"]}
        old = {"hosts": [{"host": "a.example.com", **ok}, {"host": "b.example.com", **ok},
                         {"host": "gone.example.com", "status": "unresolved"}]}
        new = {"hosts": [{"host": "a.example.com", **ok, "tech": ["PHP", "nginx"]},
                         {"host": "b.example.com", **ok, "status": "unreachable", "status_code": None},
                         {"host": "new.example.com", "status": "unresolved"}]}
        c = compare(old, new)
        self.assertEqual(c["new_hosts"], ["new.example.com"])
        self.assertEqual(c["not_seen"], ["gone.example.com"])
        self.assertEqual(c["changed"], [
            {"host": "a.example.com", "changes": {"tech": {"old": ["nginx"], "new": ["PHP", "nginx"]}}},
            {"host": "b.example.com", "changes": {"status": {"old": "ok", "new": "unreachable"}}},  # no status_code noise
        ])

    def test_cert_summary(self):
        cert = {"issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),), (("commonName", "R11"),)),
                "notAfter": "Feb  3 12:00:00 2027 GMT",
                "subjectAltName": (("DNS", "www.example.com"), ("DNS", "*.Example.com."), ("IP Address", "1.2.3.4"))}
        self.assertEqual(cert_summary(cert), {"issuer": "Let's Encrypt", "expires": "2027-02-03",
                                              "san": ["www.example.com", "*.example.com"]})

    def test_dangling_cname(self):
        answers = {
            "old.example.com": {"Status": 3, "Answer": [{"type": 5, "data": "app.azurewebsites.net."}]},
            "www.example.com": {"Status": 0, "Answer": [{"type": 5, "data": "cdn.example.net."}, {"type": 1, "data": "1.2.3.4"}]},
        }
        transport = httpx.MockTransport(lambda r: httpx.Response(200, json=answers[r.url.params["name"]]))

        async def go(host):
            async with httpx.AsyncClient(transport=transport) as c:
                return await cname_lookup(host, c, "https://doh.test/dns-query", asyncio.Semaphore(1))

        self.assertEqual(asyncio.run(go("old.example.com")), {"cname": ["app.azurewebsites.net"], "dangling": True,
                                                               "takeover_candidate": "Azure App Service", "error": None})
        live = asyncio.run(go("www.example.com"))
        self.assertEqual((live["cname"], live["dangling"], live["takeover_candidate"]), (["cdn.example.net"], False, None))


if __name__ == "__main__":
    unittest.main()
