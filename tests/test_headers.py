"""Headers check: findings from a host entry, no network."""
import asyncio
import unittest

from reconkit.checks import headers


class FakeCtx:
    def __init__(self, ok=True):
        self.ok = ok

    def gated(self, entry):
        return self.ok


GOOD = {
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "server": "nginx",
}


def entry(hdrs=None, cookies=(), origin="https://www.example.com"):
    return {"host": "www.example.com", "origin": origin, "final_url": origin + "/", "status": "ok",
            "status_code": 200, "addresses": ["93.184.216.34"], "headers": GOOD if hdrs is None else hdrs,
            "cookies": list(cookies)}


def ids(e, ok=True):
    return {f["id"]: f["severity"] for f in asyncio.run(headers.run(FakeCtx(ok), e))}


class Headers(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(ids(entry(cookies=[{"name": "sid", "attrs": "Path=/; Secure; HttpOnly; SameSite=Lax"}])), {})

    def test_not_gated(self):
        self.assertEqual(ids(entry({}), ok=False), {})

    def test_bare_html_response(self):
        got = ids(entry({"content-type": "text/html"}))
        self.assertEqual(got, {"hsts-missing": "medium", "csp-missing": "low", "clickjacking": "low",
                               "nosniff-missing": "low", "referrer-policy-missing": "info"})

    def test_hsts_short_and_nosniff_wrong(self):
        got = ids(entry({**GOOD, "strict-transport-security": "max-age=300", "x-content-type-options": "other"}))
        self.assertEqual(got, {"hsts-short": "low", "nosniff-missing": "low"})

    def test_csp_unsafe_inline(self):
        self.assertIn("csp-unsafe-inline", ids(entry({**GOOD, "content-security-policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'"})))
        self.assertIn("csp-unsafe-inline", ids(entry({**GOOD, "content-security-policy": "script-src 'unsafe-inline'; frame-ancestors 'self'"})))
        # script-src wins over default-src, and a nonce disables 'unsafe-inline'
        self.assertNotIn("csp-unsafe-inline", ids(entry({**GOOD, "content-security-policy": "default-src 'unsafe-inline'; script-src 'self'; frame-ancestors 'self'"})))
        self.assertNotIn("csp-unsafe-inline", ids(entry({**GOOD, "content-security-policy": "script-src 'unsafe-inline' 'nonce-abc'; frame-ancestors 'self'"})))

    def test_frame_ancestors_counts(self):
        self.assertNotIn("clickjacking", ids(entry({**GOOD, "content-security-policy": "frame-ancestors 'none'"})))
        self.assertIn("clickjacking", ids(entry({**GOOD, "content-security-policy": "default-src 'self'"})))
        self.assertNotIn("clickjacking", ids(entry({**GOOD, "x-frame-options": "DENY", "content-security-policy": "default-src 'self'"})))

    def test_non_html_skips_csp_and_framing(self):
        got = ids(entry({**GOOD, "content-type": "application/json", "content-security-policy": ""}))
        self.assertEqual(got, {})
        self.assertEqual(ids(entry({"content-type": "application/json"})), {"hsts-missing": "medium", "nosniff-missing": "low", "referrer-policy-missing": "info"})

    def test_version_leaks(self):
        got = ids(entry({**GOOD, "server": "Apache/2.4.57 (Unix)", "x-powered-by": "PHP/8.2"}))
        self.assertEqual(got, {"server-version": "low", "x-powered-by": "low"})
        self.assertEqual(ids(entry({**GOOD, "server": "cloudflare"})), {})

    def test_cookies(self):
        got = ids(entry(cookies=[{"name": "sessionid", "attrs": "Path=/"}, {"name": "ok", "attrs": "path=/; SECURE; httponly; samesite=none"}]))
        self.assertEqual(got, {"cookie-no-secure-sessionid": "medium", "cookie-no-httponly-sessionid": "low", "cookie-no-samesite-sessionid": "low"})

    def test_http_origin_has_no_hsts_or_secure_finding(self):
        got = ids(entry({**GOOD, "strict-transport-security": ""}, cookies=[{"name": "sid", "attrs": "HttpOnly; SameSite=Lax"}], origin="http://127.0.0.1:3000"))
        self.assertEqual(got, {})
        self.assertEqual(ids(entry({k: v for k, v in GOOD.items() if k != "strict-transport-security"}, origin="http://127.0.0.1:3000")), {})


if __name__ == "__main__":
    unittest.main()
