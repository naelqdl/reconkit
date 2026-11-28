"""--active: TCP connect check on a small top-ports list, only on hosts that already passed the scope gate."""
from __future__ import annotations

import asyncio
import contextlib

from .probe import Limiter, _ordered
from .scope import Scope, is_public

TOP_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
             8080, 8443, 9200, 27017)
# shortcut: fixed connect cap so filtered ports don't hold the shared semaphore for the full --timeout; make it an option if asked
CONNECT_TIMEOUT = 3.0


NAME, ACTIVE, PER = "ports", True, "host"
OWN_GATE = True  # also checks unreachable hosts (no HTTP, maybe SSH); check_ports re-checks scope and public addresses
# reachable from the internet, these usually shouldn't be; high = often unauthenticated by default
RISKY = {21: ("FTP", "medium"), 23: ("Telnet", "high"), 135: ("MS RPC", "medium"), 139: ("NetBIOS", "medium"),
         445: ("SMB", "high"), 1433: ("SQL Server", "medium"), 3306: ("MySQL", "medium"), 3389: ("RDP", "medium"),
         5432: ("PostgreSQL", "medium"), 5900: ("VNC", "medium"), 6379: ("Redis", "high"),
         9200: ("Elasticsearch", "high"), 27017: ("MongoDB", "high")}


async def run(ctx, entry: dict) -> list[dict]:
    """Module entry point; it gates itself (ok or unreachable hosts both have vetted addresses)."""
    from .checks import finding
    await check_ports(entry, ctx.scope, ctx.limiter, CONNECT_TIMEOUT, budget=True)
    return [finding(NAME, entry["host"], f"open-port-{p}", RISKY[p][1], f"{RISKY[p][0]} port {p} is reachable from the internet",
                    f"TCP connect to {entry['ports_ip']}:{p} succeeded",
                    f"Close port {p} on the public interface or allow only known source addresses (firewall or security group).")
            for p in entry.get("open_ports", []) if p in RISKY]


async def _is_open(ip: str, port: int, limiter: Limiter, timeout: float, connect, host: str | None = None) -> bool:
    if host is not None and not limiter.charge(host):
        return False  # over the per-host budget: not checked, reported as not open
    await limiter.wait_turn()
    async with limiter.sem:
        try:
            _, writer = await asyncio.wait_for(connect(ip, port), timeout)
        except (OSError, asyncio.TimeoutError):
            return False
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return True


async def check_ports(entry: dict, scope: Scope, limiter: Limiter, timeout: float,
                      connect=asyncio.open_connection, budget: bool = False) -> None:
    """Adds ports_ip and open_ports to a host entry that is in scope, resolved, and only on public addresses.
    Connects to the vetted IP from the shared resolve step, never to the name, so DNS can't be swapped."""
    addresses = entry.get("addresses") or []
    if (entry.get("status") not in ("ok", "unreachable") or not scope.allows(entry["host"])
            or not addresses or not all(is_public(a) for a in addresses)):
        return
    ip = _ordered(addresses)[0]
    found = await asyncio.gather(*(_is_open(ip, p, limiter, min(timeout, CONNECT_TIMEOUT), connect,
                                            entry["host"] if budget else None) for p in TOP_PORTS))
    entry["ports_ip"] = ip
    entry["open_ports"] = [p for p, is_open in zip(TOP_PORTS, found) if is_open]
