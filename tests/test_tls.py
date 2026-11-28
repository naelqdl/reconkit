"""TLS check: findings from entry fields and the one optional HTTP request. No network."""
import asyncio
import unittest
from datetime import date
from unittest import mock

import httpx

from reconkit.checks import Context, tls
from reconkit.probe import Limiter, make_clients
from reconkit.scope import parse_scope

TODAY = date(2026, 1, 1)


def entry(**kw):
    e = {"host": "www.example.com", "origin": "https://www.example.com", "addresses": ["93.184.215.14"],
         "status": "ok", "headers": {}, "cookies": [], "tls_error": None, "tls": None,
         "final_url": "https://www.example.com/"}
    e.update(kw)
    return e


def cert(days):
    return {"issuer": "X", "expires": date.fromordinal(TODAY.toordinal() + days).isoformat(), "san": []}


def check(e, active=False, response=None):
    """Run the module against a fake network; returns (findings, requests seen)."""
    seen = []

    def handler(request):
        seen.append((request.url.scheme, request.headers["host"], request.url.path))
        return response or httpx.Response(200)

    async def go():
        verified, unverified = make_clients(5, httpx.MockTransport(handler))
        async with verified, unverified:
            ctx = Context(parse_scope("example.com\n*.example.com"), Limiter(10, 0), (verified, unverified),
                          None, "", "example.com", active)
            return await tls.run(ctx, e)

    with mock.patch.object(tls, "_today", return_value=TODAY):
        return asyncio.run(go()), seen


def ids(findings):
    return [(f["id"], f["severity"]) for f in findings]


class TlsTests(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(check(entry(tls=cert(90)))[0], [])

    def test_invalid_cert(self):
        f, _ = check(entry(tls_error="certificate has expired"))
        self.assertEqual(ids(f), [("tls-invalid-cert", "high")])
        self.assertEqual(f[0]["evidence"], "certificate has expired")

    def test_expiry_levels(self):
        for days, want in [(-3, "high"), (14, "high"), (15, "medium"), (30, "medium")]:
            self.assertEqual(ids(check(entry(tls=cert(days)))[0]), [("tls-expiring", want)], days)

    def test_expiry_31_days_is_clean(self):
        self.assertEqual(check(entry(tls=cert(31)))[0], [])

    def test_no_https(self):
        f, _ = check(entry(origin="http://www.example.com"))
        self.assertEqual(ids(f), [("no-https", "medium")])

    def test_lab_http_is_not_flagged(self):
        e = entry(origin="http://127.0.0.1:3000", lab=True)
        self.assertEqual(check(e)[0], [])

    def test_not_gated(self):
        self.assertEqual(check(entry(status="error", tls_error="x"))[0], [])

    def test_inactive_sends_nothing(self):
        f, seen = check(entry(), active=False)
        self.assertEqual((f, seen), ([], []))

    def test_http_200_not_redirected(self):
        f, seen = check(entry(), active=True)
        self.assertEqual(ids(f), [("http-not-redirected", "medium")])
        self.assertEqual(seen, [("http", "www.example.com", "/")])

    def test_http_redirect_to_http(self):
        r = httpx.Response(301, headers={"location": "http://www.example.com/x"})
        self.assertEqual(ids(check(entry(), True, r)[0]), [("http-not-redirected", "medium")])

    def test_http_redirect_to_https_is_clean(self):
        r = httpx.Response(301, headers={"location": "https://www.example.com/"})
        self.assertEqual(check(entry(), True, r)[0], [])

    def test_lab_active_sends_nothing(self):
        # the scope gate rejects lab entries without --lab, so nothing is sent either way
        f, seen = check(entry(origin="https://127.0.0.1:3000", lab=True), active=True)
        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()
