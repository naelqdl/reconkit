"""CORS check: no network, MockTransport; every request must go to the vetted IP."""
import asyncio
import unittest

import httpx

from reconkit.checks import Context
from reconkit.checks.cors import FOREIGN, run
from reconkit.probe import Limiter, make_clients
from reconkit.scope import parse_scope

IP = "93.184.215.14"
ENTRY = {"host": "www.example.com", "origin": "https://www.example.com", "addresses": [IP], "status": "ok",
         "headers": {}, "cookies": [], "tls_error": None, "final_url": "https://www.example.com/"}


def check(respond, active=True):
    """Run the module against a fake server. respond(origin_header) -> response headers dict. Returns (ids, seen)."""
    seen = []

    def handler(request):
        seen.append((request.method, request.url.host, request.url.path, request.headers.get("origin")))
        return httpx.Response(200, headers=respond(request.headers.get("origin")))

    async def go():
        verified, unverified = make_clients(5, httpx.MockTransport(handler))
        async with verified, unverified:
            ctx = Context(parse_scope("example.com\n*.example.com"), Limiter(10, 0), (verified, unverified),
                          None, "", "example.com", active)
            return await run(ctx, ENTRY)

    findings = asyncio.run(go())
    return {f["id"]: f["severity"] for f in findings}, seen


CREDS = {"access-control-allow-credentials": "TRUE"}


class Cors(unittest.TestCase):
    def test_clean(self):
        ids, seen = check(lambda o: {})
        self.assertEqual(ids, {})
        self.assertEqual([(m, h, p, o) for m, h, p, o in seen],
                         [("GET", IP, "/", FOREIGN), ("GET", IP, "/", "null")])

    def test_wildcard_public_is_fine(self):
        self.assertEqual(check(lambda o: {"access-control-allow-origin": "*"})[0], {})

    def test_reflected_with_credentials(self):
        ids, _ = check(lambda o: {"access-control-allow-origin": o, **CREDS})
        self.assertEqual(ids["cors-reflected-origin-credentials"], "high")
        self.assertEqual(ids["cors-null-origin-credentials"], "high")

    def test_reflected_without_credentials(self):
        ids, _ = check(lambda o: {"access-control-allow-origin": o})
        self.assertEqual(ids, {"cors-reflected-origin": "low", "cors-null-origin": "low"})

    def test_wildcard_with_credentials(self):
        ids, _ = check(lambda o: {"access-control-allow-origin": "*", **CREDS})
        self.assertEqual(ids, {"cors-wildcard-credentials": "low"})

    def test_allowlist_not_matching(self):
        self.assertEqual(check(lambda o: {"access-control-allow-origin": "https://app.example.com", **CREDS})[0], {})

    def test_inactive_sends_nothing(self):
        ids, seen = check(lambda o: {}, active=False)
        self.assertEqual((ids, seen), ({}, []))


if __name__ == "__main__":
    unittest.main()
