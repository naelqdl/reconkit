"""Methods check: no network, requests go through a MockTransport."""
import asyncio
import unittest

import httpx

from reconkit.checks import Context
from reconkit.checks.methods import run
from reconkit.probe import Limiter, make_clients
from reconkit.scope import parse_scope

ENTRY = {"host": "www.example.com", "origin": "https://www.example.com", "addresses": ["93.184.215.14"],
         "status": "ok", "headers": {}, "cookies": [], "tls_error": None, "final_url": "https://www.example.com/"}


def check(options=None, trace=None, active=True):
    """Run the module against canned OPTIONS/TRACE responses. Returns (findings, requests seen)."""
    seen = []

    def handler(request):
        seen.append((request.method, request.headers["host"], request.url.host, request.url.path))
        return (options if request.method == "OPTIONS" else trace) or httpx.Response(404)

    async def go():
        verified, unverified = make_clients(5, httpx.MockTransport(handler))
        async with verified, unverified:
            ctx = Context(parse_scope("example.com\n*.example.com"), Limiter(10, 0), (verified, unverified),
                          None, "", "example.com", active)
            try:
                return await run(ctx, ENTRY)
            except PermissionError:
                return []

    return asyncio.run(go()), seen


def ids(findings):
    return [f["id"] for f in findings]


class Methods(unittest.TestCase):
    def test_put_delete_advertised(self):
        found, _ = check(options=httpx.Response(200, headers={"Allow": "GET, HEAD, put, OPTIONS"}))
        self.assertEqual(ids(found), ["methods-put-delete-advertised"])
        self.assertEqual(found[0]["severity"], "low")
        self.assertIn("Allow: GET, HEAD, put, OPTIONS", found[0]["evidence"])

    def test_safe_allow_is_clean(self):
        found, _ = check(options=httpx.Response(200, headers={"Allow": "GET, HEAD, OPTIONS"}))
        self.assertEqual(found, [])

    def test_trace_echo(self):
        found, _ = check(trace=httpx.Response(200, content=b"TRACE / HTTP/1.1\r\nHost: www.example.com\r\n"))
        self.assertEqual(ids(found), ["trace-enabled"])
        self.assertEqual(found[0]["severity"], "medium")

    def test_trace_405_is_clean(self):
        found, _ = check(trace=httpx.Response(405))
        self.assertEqual(found, [])

    def test_trace_200_without_echo_is_clean(self):
        found, _ = check(trace=httpx.Response(200, content=b"<html><body>Welcome</body></html>"))
        self.assertEqual(found, [])

    def test_two_requests_to_vetted_ip(self):
        _, seen = check()
        self.assertEqual([s[0] for s in seen], ["OPTIONS", "TRACE"])
        for _, host, ip, path in seen:
            self.assertEqual((host, ip, path), ("www.example.com", "93.184.215.14", "/"))

    def test_passive_sends_nothing(self):
        found, seen = check(trace=httpx.Response(200, content=b"TRACE / HTTP/1.1"), active=False)
        self.assertEqual((found, seen), ([], []))


if __name__ == "__main__":
    unittest.main()
