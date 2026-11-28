# reconkit

**A scope-safe recon CLI: point it at a domain you're authorized to test and get a clean report, without it ever touching a host outside your scope.**

> **Authorized use only.** Run reconkit only against domains you own or have explicit written permission to test. You are responsible for staying within your authorization and the law. reconkit enforces your scope file, but it can't know what you're actually allowed to test.

## What it does

1. **Discovers subdomains passively** from certificate transparency logs (crt.sh), with duplicates and junk entries removed.
2. **Resolves** each name to A/AAAA records and drops names that don't resolve.
3. **Probes HTTP(S)**: status code, page title, final URL after redirects, `Server` header. Rate-limited, with timeouts and a concurrency cap.
4. **Fingerprints technology** from headers, cookies and HTML markers using a small built-in signature list: nginx, Apache, Cloudflare, WordPress, Next.js, Express, PHP. The report shows the evidence for each match (which header, cookie or HTML marker).
5. **Reads TLS certificates** that pass verification: issuer, expiry date and SANs. In-scope SAN names that crt.sh didn't list are probed too (one extra round, wildcards skipped).
6. **Finds dangling CNAMEs** with DNS-over-HTTPS: a CNAME whose target doesn't exist (NXDOMAIN). When the target is a known claimable service (Azure, AWS Elastic Beanstalk), it's reported as a takeover *candidate* to verify by hand, never as a confirmed vulnerability.
7. **Compares runs** with `--compare old/report.json`: new hosts, hosts not seen this run, and changes in status, status code, final URL, TLS error or tech.
8. **Runs security checks** and reports each finding with severity, evidence and a fix, grouped in a "Findings" section (`--compare` lists new and fixed findings). Passive checks run on every scan and send nothing extra to the target:
   - `headers`: HSTS, Content-Security-Policy, clickjacking protection, nosniff, Referrer-Policy, version-leaking `Server`/`X-Powered-By`, and cookies without Secure, HttpOnly or SameSite (cookie names only; values are never stored).
   - `tls`: invalid or soon-expiring certificates, sites with no HTTPS.
   - `email`: SPF, DMARC and MTA-STS records for the domain, over DNS-over-HTTPS.
9. **Runs active checks, only with `--active`**. Every request goes to the vetted IP, follows no redirects, shares the `--rate` and `--concurrency` limits, and counts against a cap of 100 check requests per host:
   - `ports`: a TCP connect to 24 common ports; databases, RDP, SMB and similar services reachable from the internet are findings. Waits at most 3 s per port.
   - `wellknown`: exposed `/.git/HEAD`, `/.env` (variable names only), backups, `/server-status`, `phpinfo.php`, `.DS_Store`, missing `security.txt`. A hit needs the file's own signature, not just HTTP 200, and sites that answer 200 for everything are detected.
   - `cors`: an arbitrary or `null` Origin trusted, with or without credentials (2 requests).
   - `methods`: TRACE echoing requests, PUT/DELETE advertised by OPTIONS (2 requests; nothing state-changing is sent).
   - `tls` also checks that plain HTTP redirects to HTTPS (1 request).
10. **Writes** `report.md`, `report.json` (`schema_version: 2`) and `live-hosts.txt` (the origins that answered, one per line).

reconkit reports indicators of exposure and misconfiguration; it sends no attack payloads and tries no passwords. For payload-based testing of your own site, feed `live-hosts.txt` to a dedicated scanner, e.g. `nuclei -l out/live-hosts.txt` or OWASP ZAP.

Pure Python: `httpx` plus the standard library. No Go, no Docker, no external binaries. Works on Windows, macOS and Linux.

## Scope enforcement

The scope file is required, and reconkit fails closed:

- It refuses to start if the scope file is missing, empty or malformed, or if the target isn't in scope.
- Every discovered name is checked against scope. Out-of-scope names are listed as refused and never resolved or contacted.
- Names that resolve to non-public addresses (loopback, private ranges, link-local such as `169.254.169.254`) are refused and never contacted.
- Requests go to the address that was checked (pinned IP with the real hostname in `Host`/SNI), so DNS can't be swapped between the check and the request.
- Redirects are followed by hand, at most 5 hops, and each hop is checked against scope before it is requested. A redirect out of scope is recorded and not followed.

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/naelqdl/reconkit
cd reconkit
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e .
```

## Usage

Create `scope.txt` with one entry per line:

```text
# exact host
example.com
# any subdomain, at any depth (not the apex itself)
*.example.com
```

Run:

```bash
reconkit example.com --scope scope.txt -o out/
```

| Option | Default | Meaning |
|---|---|---|
| `--scope FILE` | required | Scope file, as above |
| `-o, --out DIR` | `out` | Where `report.md` and `report.json` are written |
| `--concurrency N` | 10 | Max DNS/HTTP operations in flight |
| `--rate R` | 5 | Max requests per second to target hosts |
| `--timeout S` | 10 | Seconds per HTTP request |
| `--doh-url URL` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS (JSON API) resolver used for CNAME lookups |
| `--compare FILE` | - | A previous `report.json` for the same domain; adds a "What changed" section |
| `--active` | off | Also run the active checks above |
| `--lab` | off | Test one local or staging origin (see below) |
| `--no-discovery` | off | Skip crt.sh and test only the exact hosts listed in the scope file |
| `--modules LIST` / `--skip LIST` | all | Run only, or skip, these checks (comma-separated names from the list above) |

Exit codes: `0` report written, `2` scope or `--compare` file problem (nothing was sent), `3` crt.sh unavailable after one retry (no report written).

**Testing a local or staging copy (`--lab`).** Private addresses are always refused, except for an origin you list on a `lab` line in the scope file:

```text
lab http://127.0.0.1:3000
```

```bash
reconkit http://127.0.0.1:3000 --scope scope.txt --lab --active -o out/
```

A lab line allows that exact scheme, host and port only (another port is another origin), runs without discovery, and redirects that leave the origin are refused.

**Proving domain control (optional).** Publish a TXT record `_reconkit.example.com` with the value `reconkit-verify=<anything>`. The report then says "Domain control: verified", which shows a reader that whoever ran the scan controls the domain's DNS. Runs never require it.

HTTPS is tried first with certificate checking on. If the certificate is invalid, the reason is recorded in the TLS column and the page is fetched again without verification. Plain HTTP is tried only when the HTTPS connection fails.

Privacy note: CNAME lookups send every in-scope hostname to the DoH resolver (Cloudflare by default). Point `--doh-url` at a resolver you trust, e.g. `https://dns.google/resolve`. No traffic for those lookups goes to the target.

### Desktop window

`reconkit-gui` opens a small window (tkinter, no extra dependency) to edit the scope file, set the options above, run, follow the log, and open `report.md`. It runs the same CLI underneath, so the same scope checks and exit codes apply. Stop (or Esc) ends a run without writing a report; Ctrl+S saves the scope file. The window follows the Windows light or dark app setting and the Windows text size (Accessibility > Text size). Screen readers can't read tkinter windows; use the CLI with a screen reader.

To build a standalone Windows app (`dist/reconkit.exe`, no Python needed to run it):

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name reconkit --icon reconkit/icon.ico --add-data reconkit/icon.ico:reconkit --add-data reconkit/icon.png:reconkit packaging/reconkit_gui.py
```

## Sample report

_Illustrative only: generated by running reconkit against a simulated network of reserved `example.com` names, not a real target._

# reconkit report: example.com

- Scope: `example.com`, `*.example.com`
- Settings: concurrency=10, rate=0, timeout=5
- Hosts: 4 ok, 0 unreachable, 1 refused, 1 unresolved
- Dropped crt.sh entries: 1

## Live hosts

| Host | Code | Title | Server | Tech | TLS | Final URL |
|---|---|---|---|---|---|---|
| api.example.com | 401 | - | cloudflare | Cloudflare, Express | ok | https://api.example.com/ |
| example.com | 200 | Example Domain | nginx/1.25.3 | nginx | ok | https://example.com/ |
| shop.example.com | 302 | - | - | - | ok | https://shop.example.com/ |
| www.example.com | 200 | Example Domain | nginx/1.25.3 | nginx | ok | https://www.example.com/ |

## Refused

- intranet.example.com — non-public address (10.0.4.12)
- shop.example.com → refused: out of scope (checkout.payments-partner.test)

## Unresolved

- old.example.com

_Generated by reconkit for authorized testing only._

## Tests

The security-critical scope logic, plus fingerprints, `--compare`, certificate parsing and CNAME detection, has one test file, with no network access:

```bash
python -m unittest -v tests.test_scope
```

## Roadmap

Done: v1.1 fingerprint evidence and `--compare`, v1.2 TLS certificate details, v1.3 CNAME takeover *candidates*, v2.0 `--active` port check. Next: more opt-in `--active` modules (security headers and well-known paths, then small content discovery). All of them run behind the same scope gate. Exploitation and payloads stay out of scope. See [docs/designs/reconkit.md](docs/designs/reconkit.md).

## License

MIT, see [LICENSE](LICENSE).
