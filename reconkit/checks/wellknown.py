"""Active check: well-known sensitive paths (.git, .env, backups, ...) answered with a matching signature."""
from __future__ import annotations

import hashlib
import re
import secrets

from . import Context, finding

NAME = "wellknown"
ACTIVE = True
PER = "host"

ENV_LINE = re.compile(rb"^[A-Z][A-Z0-9_]*=", re.M)
BACKUPS = ("/backup.zip", "/site.zip", "/backup.tar.gz")


def _git(body: bytes) -> bool:
    return body.startswith(b"ref: refs/") or re.fullmatch(rb"[0-9a-f]{40}\s*", body) is not None


def _env(body: bytes) -> bool:
    return b"<html" not in body[:1024].lower() and ENV_LINE.search(body) is not None


def _phpinfo(body: bytes) -> bool:
    return b"<title>" in body and (b"phpinfo()" in body or b"PHP Version" in body)


def _archive(body: bytes) -> bool:
    return body.startswith((b"PK\x03\x04", b"\x1f\x8b"))


# path, id, severity, title, signature, fix
CHECKS = [
    ("/.git/HEAD", "git-exposed", "high", "Git repository is publicly readable", _git,
     "Block /.git/ in the web server config and remove it from the web root; rotate any secrets that were committed."),
    ("/.env", "env-exposed", "high", "Environment file is publicly readable", _env,
     "Move .env out of the web root or deny it in the server config, then rotate every credential it held."),
    ("/.DS_Store", "ds-store-exposed", "low", "macOS .DS_Store file is publicly readable",
     lambda b: b.startswith(b"\x00\x00\x00\x01Bud1"),
     "Delete .DS_Store files from the web root and deny dotfiles in the server config."),
    ("/server-status", "server-status-exposed", "medium", "Apache server-status page is publicly readable",
     lambda b: b"Apache Server Status" in b,
     "Restrict /server-status to localhost or an admin network in the Apache config."),
    ("/phpinfo.php", "phpinfo-exposed", "medium", "phpinfo() page is publicly readable", _phpinfo,
     "Delete phpinfo.php from the server."),
] + [(p, "backup-exposed-" + p[1:], "high", "Backup archive is publicly downloadable", _archive,
      "Remove the archive from the web root and store backups outside it; rotate any secrets it contained.")
     for p in BACKUPS]


async def run(ctx: Context, entry: dict) -> list[dict]:
    """Probe a fixed list of sensitive paths; a hit needs HTTP 200 and the file's own signature."""
    if not ctx.gated(entry):
        return []
    host, base = entry["host"], entry["origin"]
    soft = None  # (length, sha256) of the host's answer for a path that cannot exist
    got = await ctx.fetch(entry, "/reconkit-404-check-" + secrets.token_hex(8))
    if got and got[0].status_code == 200:
        soft = (len(got[1]), hashlib.sha256(got[1]).hexdigest())

    def found(got) -> bool:
        if got is None or got[0].status_code != 200:
            return False
        body = got[1]
        if soft and (hashlib.sha256(body).hexdigest() == soft[1] or abs(len(body) - soft[0]) <= 0.05 * soft[0]):
            return False
        return True

    out = []
    for path, fid, sev, title, sig, fix in CHECKS:
        got = await ctx.fetch(entry, path)
        if not (found(got) and sig(got[1])):
            continue
        ev = f"{base}{path} returned HTTP 200 with a matching signature"
        if fid == "env-exposed":
            names = [m.decode() for m in re.findall(rb"^([A-Z][A-Z0-9_]*)=", got[1], re.M)[:3]]
            ev += f" (variable names: {', '.join(names)}; values not recorded)"
        out.append(finding(NAME, host, fid, sev, title, ev, fix))

    got = await ctx.fetch(entry, "/.well-known/security.txt")
    if got is not None:  # None means the request failed, which says nothing about the file
        if not found(got) or not re.search(rb"^\s*contact:", got[1], re.I | re.M):
            out.append(finding(NAME, host, "security-txt-missing", "info", "No security.txt with a Contact line",
                               f"{base}/.well-known/security.txt has no Contact: line (HTTP {got[0].status_code})",
                               "Publish /.well-known/security.txt with a Contact: line so researchers can report issues."))
    return out
