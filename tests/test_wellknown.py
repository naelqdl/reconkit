"""Well-known paths check: no network, a MockTransport stands in for the host."""
import asyncio
import unittest

import httpx

from reconkit.checks import Context
from reconkit.checks.wellknown import run
from reconkit.probe import Limiter, make_clients
from reconkit.scope import parse_scope

IP = "93.184.215.14"
ENTRY = {"host": "www.example.com", "origin": "https://www.example.com", "addresses": [IP], "status": "ok",
         "headers": {}, "cookies": [], "tls_error": None, "final_url": "https://www.example.com/"}
SECTXT = b"Contact: mailto:security@example.com\n"
HTML = b"<html><body>" + b"welcome " * 50 + b"</body></html>"


def go(routes, default=404, active=True, entry=ENTRY):
    """Run the check against {path: body or Response}; returns (findings, requests seen)."""
    seen = []

    def handler(request):
        seen.append((request.method, request.headers["host"], request.url.host, request.url.path))
        r = routes.get(request.url.path)
        if callable(default) and r is None:
            return default(request)
        if r is None:
            return httpx.Response(default)
        return r if isinstance(r, httpx.Response) else httpx.Response(200, content=r)

    async def main():
        verified, unverified = make_clients(5, httpx.MockTransport(handler))
        async with verified, unverified:
            ctx = Context(parse_scope("example.com\n*.example.com"), Limiter(10, 0), (verified, unverified),
                          None, "", "example.com", active)
            return await run(ctx, entry)

    return asyncio.run(main()), seen


def ids(findings):
    return sorted(f["id"] for f in findings)


class WellKnown(unittest.TestCase):
    def test_clean_host(self):
        f, seen = go({"/.well-known/security.txt": SECTXT})
        self.assertEqual(f, [])
        self.assertEqual(len(seen), 10)
        for method, host, ip, _ in seen:
            self.assertEqual((method, host, ip), ("GET", "www.example.com", IP))

    def test_each_finding(self):
        routes = {
            "/.git/HEAD": b"ref: refs/heads/main\n",
            "/.env": b"# c\nDB_PASSWORD=hunter2\nAPI_KEY=abc\n",
            "/.DS_Store": b"\x00\x00\x00\x01Bud1\x00",
            "/server-status": b"<title>Apache Server Status for x</title>",
            "/phpinfo.php": b"<title>phpinfo()</title>PHP Version 8.2",
            "/backup.zip": b"PK\x03\x04rest",
            "/site.zip": b"PK\x03\x04rest",
            "/backup.tar.gz": b"\x1f\x8b\x08rest",
        }
        f, _ = go(routes)
        self.assertEqual(ids(f), sorted(["git-exposed", "env-exposed", "ds-store-exposed", "server-status-exposed",
                                         "phpinfo-exposed", "backup-exposed-backup.zip", "backup-exposed-site.zip",
                                         "backup-exposed-backup.tar.gz", "security-txt-missing"]))
        sev = {x["id"]: x["severity"] for x in f}
        self.assertEqual((sev["git-exposed"], sev["ds-store-exposed"], sev["phpinfo-exposed"], sev["security-txt-missing"]),
                         ("high", "low", "medium", "info"))

    def test_git_commit_id(self):
        f, _ = go({"/.git/HEAD": b"a" * 40 + b"\n", "/.well-known/security.txt": SECTXT})
        self.assertEqual(ids(f), ["git-exposed"])

    def test_env_evidence_has_names_not_values(self):
        f, _ = go({"/.env": b"DB_PASSWORD=hunter2\nAPI_KEY=abc\n", "/.well-known/security.txt": SECTXT})
        ev = f[0]["evidence"]
        self.assertIn("DB_PASSWORD", ev)
        self.assertNotIn("hunter2", ev)
        self.assertNotIn("abc", ev.split("names:")[1])

    def test_html_env_is_not_a_finding(self):
        f, _ = go({"/.env": b"<html>\nFOO=bar\n</html>", "/.well-known/security.txt": SECTXT})
        self.assertEqual(f, [])

    def test_soft_404_site(self):
        f, seen = go({}, default=lambda r: httpx.Response(200, content=HTML))
        self.assertEqual(ids(f), ["security-txt-missing"])
        self.assertEqual(len(seen), 10)

    def test_soft_404_does_not_hide_real_hit(self):
        f, _ = go({"/.git/HEAD": b"ref: refs/heads/main\n"}, default=lambda r: httpx.Response(200, content=HTML))
        self.assertEqual(ids(f), ["git-exposed", "security-txt-missing"])

    def test_forbidden_is_no_finding(self):
        f, _ = go({"/.git/HEAD": httpx.Response(403, content=b"ref: refs/heads/main"),
                   "/.well-known/security.txt": SECTXT})
        self.assertEqual(f, [])

    def test_security_txt_without_contact(self):
        f, _ = go({"/.well-known/security.txt": b"Expires: 2030-01-01\n"})
        self.assertEqual(ids(f), ["security-txt-missing"])

    def test_inactive_sends_nothing(self):
        seen = []
        try:
            f, seen = go({}, active=False)
        except PermissionError:
            f = []
        self.assertEqual(f, [])
        self.assertEqual(seen, [])

    def test_not_gated_returns_nothing(self):
        f, seen = go({}, entry={**ENTRY, "status": "dns-failed"})
        self.assertEqual((f, seen), ([], []))


if __name__ == "__main__":
    unittest.main()
