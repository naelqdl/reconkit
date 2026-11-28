"""Email DNS check: DoH is faked with MockTransport, so no network."""
import asyncio
import unittest

import httpx

from reconkit.checks import Context, email
from reconkit.probe import Limiter
from reconkit.scope import parse_scope

GOOD = {
    "example.com": ['"v=spf1 include:_spf.example.net -all"'],
    "_dmarc.example.com": ['"v=DMARC1; p=reject; rua=mailto:d@example.com"'],
    "_mta-sts.example.com": ['"v=STSv1; id=1"'],
}


def run_check(records, lab=False, doh=True):
    """records: {name: [raw TXT data] | 'fail'}. Returns (findings, DNS names requested)."""
    seen = []

    def handler(request):
        name = request.url.params["name"]
        seen.append(name)
        rec = records.get(name, [])
        if rec == "fail":
            return httpx.Response(500)
        return httpx.Response(200, json={"Status": 0, "Answer": [{"name": name, "type": 16, "data": d} for d in rec]})

    async def go():
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with client:
            ctx = Context(parse_scope("example.com"), Limiter(10, 0), (None, None),
                          client if doh else None, "https://doh.test/dns-query", "example.com", False, lab)
            return await email.run(ctx, None)

    return asyncio.run(go()), seen


def ids(findings):
    return sorted(f["id"] for f in findings)


class EmailTests(unittest.TestCase):
    def test_all_good(self):
        self.assertEqual(run_check(GOOD)[0], [])

    def test_nothing_published(self):
        f, _ = run_check({})
        self.assertEqual(ids(f), ["dmarc-missing", "mta-sts-missing", "spf-missing"])
        self.assertTrue(all(x["host"] == "example.com" and x["module"] == "email" for x in f))

    def test_spf_pass_all(self):
        f, _ = run_check({**GOOD, "example.com": ['"v=spf1 +all"']})
        self.assertEqual([(x["id"], x["severity"]) for x in f], [("spf-pass-all", "high")])

    def test_spf_neutral_and_multiple(self):
        f, _ = run_check({**GOOD, "example.com": ['"v=spf1 ?all"']})
        self.assertEqual(ids(f), ["spf-neutral-all"])
        f, _ = run_check({**GOOD, "example.com": ['"v=spf1 -all"', '"v=spf1 ~all"']})
        self.assertEqual(ids(f), ["spf-multiple"])

    def test_dmarc_policy_none(self):
        f, _ = run_check({**GOOD, "_dmarc.example.com": ['"v=DMARC1; p=none; rua=mailto:d@example.com"']})
        self.assertEqual([(x["id"], x["severity"]) for x in f], [("dmarc-policy-none", "low")])

    def test_split_record(self):
        f, _ = run_check({**GOOD, "example.com": ['"v=spf1 " "-all"']})
        self.assertEqual(f, [])

    def test_lookup_failure(self):
        f, _ = run_check({**GOOD, "_dmarc.example.com": "fail"})
        self.assertEqual(ids(f), ["email-dns-lookup-failed"])
        self.assertIn("DMARC", f[0]["evidence"])
        f, _ = run_check({"example.com": "fail", "_dmarc.example.com": "fail", "_mta-sts.example.com": "fail"})
        self.assertEqual(ids(f), ["email-dns-lookup-failed"])

    def test_lab_and_no_doh(self):
        f, seen = run_check({}, lab=True)
        self.assertEqual((f, seen), ([], []))
        self.assertEqual(run_check({}, doh=False)[0], [])


if __name__ == "__main__":
    unittest.main()
