# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

(Closest valid value. The product is a Windows desktop app built with tkinter, plus a cross-platform CLI. It follows desktop conventions, not native iOS or Android.)

## Users

Two audiences, weighted equally (confirmed 2026-11-27):
- Site owners checking their own sites, who want a findings report with fixes.
- Bug bounty hunters and pentesters working authorized programs and engagements, who use recon to feed manual testing.

The scope file is the guardrail both audiences share.

## Product Purpose

Point reconkit at a domain you are authorized to test and get a clean report (report.md and report.json) without it ever touching a host outside your scope. Success means a report the user can act on, and no out-of-scope traffic.

## Positioning

Scope safety is the mechanism. The tool fails closed on scope, pins requests to the IPs it vetted, follows redirects by hand only within scope, and sends active traffic only when `--active` is opted into. It is pure Python (httpx plus the standard library), with no external binaries.

## Operating Context

- Run from a terminal (`reconkit`) or from the desktop window (`reconkit-gui`, or `reconkit.exe` with no Python installed).
- Inputs: a target domain and a scope file. Outputs: report.md and report.json. `--compare` diffs a run against an earlier one.
- Exit codes carry meaning: 0 report written, 2 scope or input error with nothing sent, 3 crt.sh unavailable.

## Capabilities and Constraints

- Passive discovery (crt.sh), DNS, HTTP probe, tech fingerprints, TLS details, dangling CNAMEs.
- Check modules (headers, tls, email, wellknown, cors, methods, ports); the ones that send traffic to the target run only with `--active`.
- `--lab` mode for local origins.
- The GUI runs the CLI underneath, so it applies the same scope checks and exit codes.

## Brand Commitments

- Name: reconkit (lowercase).
- App icon: a target mark (reconkit/icon.png, icon.ico).
- The authorized-use warning is always visible, both in the CLI docs and at the foot of the GUI.

## Evidence on Hand

No testimonials, users, benchmarks or press exist. Do not invent any.

## Product Principles

1. Scope safety first. No design or feature work may weaken fail-closed scope, the visible authorized-use warning, or opt-in `--active` (confirmed).
2. Findings are indicators with evidence, never claimed vulnerabilities.
3. The GUI adds no capability the CLI lacks; it is a front end to the same checks.
4. Keep dependencies minimal.

## Accessibility & Inclusion

WCAG AA contrast and full keyboard operation in the GUI. Screen-reader users are directed to the CLI, because tkinter windows cannot be read by screen readers (confirmed 2026-11-27).
