"""Write report.json and report.md from a result dict."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

STATUSES = ("ok", "unreachable", "refused", "unresolved")
# Compared only when the host is "ok" in both runs; otherwise only the status change is reported.
COMPARED = ("status_code", "final_url", "tls_error", "tech", "open_ports")


def _cell(value: object, limit: int | None = None) -> str:
    """Render a table cell: '-' if empty, newlines flattened, pipes escaped."""
    text = " ".join(str(value).split()) if value not in (None, "", []) else ""
    if limit and len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.replace("|", "\\|") or "-"


def _refused_errors(host: dict) -> list[str]:
    return [a["error"] for a in host.get("attempts", [])
            if (a.get("error") or "").startswith("refused")]


def compare(old: dict, new: dict) -> dict:
    """What changed between two report dicts, matched on host name."""
    a = {h["host"]: h for h in old["hosts"]}
    b = {h["host"]: h for h in new["hosts"]}
    changed = []
    for host in sorted(a.keys() & b.keys()):
        x, y = a[host], b[host]
        fields = ("status",) if x["status"] != y["status"] else COMPARED if x["status"] == "ok" else ()
        # a field only one run has (open_ports without --active, or an older schema) is not a change
        diff = {f: {"old": x[f], "new": y[f]} for f in fields if f in x and f in y and x[f] != y[f]}
        if diff:
            changed.append({"host": host, "changes": diff})
    out = {"base_finished_at": old.get("finished_at"), "new_hosts": sorted(b.keys() - a.keys()),
           "not_seen": sorted(a.keys() - b.keys()), "changed": changed}
    if "findings" in old and "findings" in new:  # a v1 report has no findings: nothing to compare, not "all new"
        fa = {(f["host"], f["id"]): f for f in old["findings"]}
        fb = {(f["host"], f["id"]): f for f in new["findings"]}
        out["new_findings"] = [fb[k] for k in sorted(fb.keys() - fa.keys())]
        out["fixed_findings"] = [fa[k] for k in sorted(fa.keys() - fb.keys())]
    return out


def _show(value: object) -> str:
    return ", ".join(map(str, value)) or "none" if isinstance(value, list) else str(value) if value not in (None, "") else "-"


def _render_changes(c: dict) -> list[str]:
    lines = [f"## What changed (since {c.get('base_finished_at') or 'previous run'})", ""]
    lines += [f"- New: {h}" for h in c["new_hosts"]]
    lines += [f"- Not seen this run: {h}" for h in c["not_seen"]]
    for ch in c["changed"]:
        parts = [f"{f} {_show(v['old'])} → {_show(v['new'])}" for f, v in ch["changes"].items()]
        lines.append(f"- Changed: {ch['host']} — " + "; ".join(parts))
    lines += [f"- New finding ({f['severity']}): {f['host']} — {f['title']}" for f in c.get("new_findings", [])]
    lines += [f"- Fixed: {f['host']} — {f['title']}" for f in c.get("fixed_findings", [])]
    if len(lines) == 2:
        lines.append("- No changes.")
    return lines + [""]


def _render_md(result: dict) -> str:
    hosts = sorted(result.get("hosts", []), key=lambda h: h["host"])
    by = {s: [h for h in hosts if h["status"] == s] for s in STATUSES}
    counts = Counter(h["status"] for h in hosts)
    s = result.get("settings", {})
    lines = [
        f"# reconkit report: {result['target']}", "",
        f"- Generated: {result.get('finished_at', '-')}",
        "- Scope: " + ", ".join(f"`{e}`" for e in result.get("scope", [])),
        "- Settings: " + ", ".join(f"{k}={v}" for k, v in s.items()),
        "- Hosts: " + ", ".join(f"{counts[k]} {k}" for k in STATUSES),
        f"- Dropped crt.sh entries: {result.get('dropped_entries', 0)}",
    ]
    if result.get("san_names"):
        lines.append("- Names found only in certificates: " + ", ".join(result["san_names"]))
    doh_errors = sum(1 for h in hosts if (h.get("dns") or {}).get("error"))
    if doh_errors:
        lines.append(f"- CNAME lookups failed: {doh_errors} (see report.json)")
    control = result.get("control_verified")
    if "control_verified" in result and not (result.get("settings") or {}).get("lab"):
        lines.append(f"- Domain control: verified (DNS TXT `_reconkit.{result['target']}`)" if control else
                     f"- Domain control: {'not verified' if control is False else 'lookup failed'} "
                     f"(optional: publish TXT `_reconkit.{result['target']}` = `reconkit-verify=<anything>`)")
    if result.get("check_errors"):
        lines.append(f"- Check errors: {len(result['check_errors'])} (see report.json `check_errors`)")
    lines.append("")
    if "findings" in result:
        lines += _render_findings(result["findings"], result.get("modules") or [])
    if by["ok"]:
        lines += ["## Live hosts", "",
                  "| Host | Code | Title | Server | Tech | TLS | Final URL |",
                  "|---|---|---|---|---|---|---|"]
        for h in by["ok"]:
            row = [_cell(h["host"]), _cell(h.get("status_code")), _cell(h.get("title"), 80),
                   _cell(h.get("server")), _cell(", ".join(h.get("tech") or [])),
                   _cell(h.get("tls_error") or ("ok" if (h.get("origin") or h.get("final_url") or "").startswith("https") else "-")), _cell(h.get("final_url"))]
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        evidence = [f"- {h['host']} — {tech}: " + "; ".join(ev)
                    for h in by["ok"] for tech, ev in sorted((h.get("tech_evidence") or {}).items())]
        if evidence:
            lines += ["## Fingerprint evidence", "", *evidence, ""]
        certs = []
        for h in by["ok"]:
            if t := h.get("tls"):
                san = t["san"][:10] + ([f"+{len(t['san']) - 10} more"] if len(t["san"]) > 10 else [])
                certs.append(f"- {h['host']} — issuer {t['issuer'] or '-'}, expires {t['expires'] or '-'}, SANs: {', '.join(san) or '-'}")
        if certs:
            lines += ["## TLS certificates", "", *certs, ""]
    dangling = [h for h in hosts if (h.get("dns") or {}).get("dangling")]
    if dangling:
        lines += ["## Dangling CNAMEs", "",
                  "_The CNAME target doesn't exist (NXDOMAIN). On a known service this is a takeover candidate: verify by hand, never assume._", ""]
        for h in dangling:
            d = h["dns"]
            label = f"takeover candidate ({d['takeover_candidate']})" if d["takeover_candidate"] else "unknown service"
            lines.append(f"- {h['host']} → {' → '.join(d['cname'])} — {label}")
        lines.append("")
    scanned = [h for h in hosts if "open_ports" in h]
    if scanned:
        lines += ["## Open ports (--active)", "",
                  f"_TCP connect check on {len(result.get('active_ports') or [])} common ports per host. "
                  "Closed and filtered ports are not told apart._", ""]
        lines += [f"- {h['host']} ({h['ports_ip']}) — {', '.join(map(str, h['open_ports']))}" for h in scanned if h["open_ports"]]
        if quiet := sum(1 for h in scanned if not h["open_ports"]):
            lines.append(f"- No open ports found: {quiet} host{'s' if quiet > 1 else ''}")
        lines.append("")
    if "changes" in result:
        lines += _render_changes(result["changes"])
    if by["unreachable"]:
        lines += ["## Unreachable", ""]
        lines += [f"- {h['host']} — {h.get('reason') or '-'}" for h in by["unreachable"]]
        lines.append("")
    refused = [f"- {h['host']} — {h.get('reason') or '-'}" for h in by["refused"]]
    for h in by["refused"] + by["ok"]:
        refused += [f"- {h['host']} → {e}" for e in _refused_errors(h)]
    if refused:
        lines += ["## Refused", "", *refused, ""]
    if by["unresolved"]:
        lines += ["## Unresolved", ""] + [f"- {h['host']}" for h in by["unresolved"]] + [""]
    lines.append("_Generated by reconkit for authorized testing only._")
    return "\n".join(lines) + "\n"


SEVERITIES = ("high", "medium", "low", "info")


def _render_findings(findings: list[dict], modules: list[str]) -> list[str]:
    counts = Counter(f["severity"] for f in findings)
    lines = ["## Findings", "",
             f"_{', '.join(f'{counts[s]} {s}' for s in SEVERITIES)} from checks: {', '.join(modules) or 'none'}. "
             "Each finding is an indicator with the evidence reconkit saw; confirm it before acting._", ""]
    if not findings:
        return lines + ["No findings.", ""]
    for sev in SEVERITIES:
        group = [f for f in findings if f["severity"] == sev]
        if group:
            lines += [f"### {sev.capitalize()}", ""]
            for f in sorted(group, key=lambda f: (f["host"], f["id"])):
                lines += [f"- **{f['host']}: {f['title']}** (`{f['id']}`)", f"  - Evidence: {f['evidence']}",
                          f"  - Fix: {f['fix']}"]
            lines.append("")
    return lines


def write_reports(result: dict, out_dir: str | Path) -> tuple[Path, Path]:
    """Write report.md, report.json and live-hosts.txt (origins that answered, one per line, ready for
    'nuclei -l' or ZAP) into out_dir; return (md_path, json_path)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md_path, json_path = out / "report.md", out / "report.json"
    md_path.write_text(_render_md(result), encoding="utf-8")
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    live = sorted({h["origin"] for h in result.get("hosts", []) if h.get("status") == "ok" and h.get("origin")})
    (out / "live-hosts.txt").write_text("".join(o + "\n" for o in live), encoding="utf-8")
    return md_path, json_path
