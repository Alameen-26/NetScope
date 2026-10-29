"""Traceroute-style hop check: which routers does traffic pass through?

How traceroute works: every IP packet carries a "time to live" (TTL) counter
that each router lowers by one. When it hits zero, that router throws the
packet away and sends back a "time exceeded" message - revealing its address.
Sending packets with TTL 1, 2, 3, ... maps the path one hop at a time.

Reading those "time exceeded" replies directly needs a raw socket, which needs
administrator/root rights. So, like ``ping.py``, we run the operating system's
own tool (``tracert`` on Windows, ``traceroute`` or ``tracepath`` elsewhere),
which already has the right permissions, and parse what it prints. If none of
those tools exists, we say so clearly instead of failing with a traceback.

Added in v0.1.0
"""
from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from . import hosts
from .syscmd import run_tool

DEFAULT_MAX_HOPS = 20
DEFAULT_TIMEOUT = 2.0

# A hop line starts with the hop number; tracepath writes it as "1:" or "1?:".
_HOP_RE = re.compile(r"^\s*(\d+)\??:?\s+(.*)$")
# Reply times such as "12.3 ms", "0.050ms", Windows' "<1 ms" or Russian "5 мс".
_MS_RE = re.compile(r"(<?)\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс)(?!\w)", re.IGNORECASE)
SUB_MS_VALUE = 0.5   # "<1 ms" is stored as the middle of 0-1 ms (same as ping.py)
# IPv4 address, or an IPv6 address (hex groups with colons).
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})")


class TraceUnavailable(RuntimeError):
    """Raised when no traceroute program is available."""


@dataclass
class Hop:
    number: int
    address: Optional[str]                 # None when the router didn't answer ("* * *")
    times_ms: list[float] = field(default_factory=list)
    # Some hops answer from more than one router (load balancing). macOS and
    # Linux traceroute print the extra ones on the same or the next line.
    other_addresses: list[str] = field(default_factory=list)

    @property
    def avg_ms(self) -> Optional[float]:
        return round(sum(self.times_ms) / len(self.times_ms), 2) if self.times_ms else None

    def to_dict(self) -> dict[str, Any]:
        return {"hop": self.number, "address": self.address, "avg_ms": self.avg_ms,
                "times_ms": self.times_ms, "other_addresses": self.other_addresses}


@dataclass
class TraceResult:
    host: str
    tool: str
    hops: list[Hop] = field(default_factory=list)
    error: Optional[str] = None
    address: Optional[str] = None   # the IP the host name resolved to

    @property
    def no_replies(self) -> bool:
        """True when hops were listed but not one router answered (all "*")."""
        return bool(self.hops) and all(h.address is None for h in self.hops)

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "address": self.address, "tool": self.tool,
                "error": self.error, "hops": [h.to_dict() for h in self.hops]}


def find_tool(system: Optional[str] = None, which: Callable[[str], Optional[str]] = shutil.which) -> Optional[str]:
    """Return the name of the first traceroute program that's installed, or None."""
    system = system or platform.system()
    candidates = ["tracert"] if system == "Windows" else ["traceroute", "tracepath"]
    # (traceroute6 on macOS is picked in build_trace_command for IPv6 targets.)
    for name in candidates:
        if which(name):
            return name
    return None


def build_trace_command(tool: str, host: str, max_hops: int, timeout: float,
                        system: Optional[str] = None) -> list[str]:
    """Command line for each tool. ``-n``/``-d`` skip reverse DNS so the trace is faster."""
    system = system or platform.system()
    if tool == "traceroute" and system == "Darwin" and ":" in host:
        tool = "traceroute6"  # macOS has a separate program for IPv6
    if tool == "tracert":
        return ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), host]
    if tool == "tracepath":
        return ["tracepath", "-n", "-m", str(max_hops), host]
    # traceroute: one probe per hop (-q 1) keeps it quick.
    return [tool, "-n", "-q", "1", "-m", str(max_hops), "-w", str(max(1, round(timeout))), host]


def _times(text: str) -> list[float]:
    """All reply times in ``text``, in ms ("<1 ms" -> SUB_MS_VALUE)."""
    values = []
    for less_than, number in _MS_RE.findall(text):
        value = float(number.replace(",", "."))
        values.append(SUB_MS_VALUE if less_than and value <= 1 else value)
    return values


def _addresses(text: str) -> list[str]:
    """All IP addresses in ``text`` (with the times already removed)."""
    found = []
    for candidate in _IP_RE.findall(text):
        try:
            found.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue  # looked a bit like an address but isn't one
    return found


def parse_trace_output(text: str) -> list[Hop]:
    """Turn the text from traceroute/tracert/tracepath into a list of hops."""
    hops: dict[int, Hop] = {}
    last: Optional[Hop] = None
    for line in text.splitlines():
        match = _HOP_RE.match(line)
        if not match:
            # macOS/Linux continuation line: an extra router for the hop above,
            # e.g. "    10.0.0.2  11.2 ms" right under " 5  10.0.0.1  10.1 ms".
            if last is not None and line[:1].isspace() and _MS_RE.search(line):
                extra = _addresses(_MS_RE.sub(" ", line))
                if extra:
                    last.times_ms.extend(_times(line))
                    _add_addresses(last, extra)
                    continue
            last = None  # header lines such as "traceroute to example.com ..."
            continue
        number, rest = int(match.group(1)), match.group(2)
        if "LOCALHOST" in rest or "pmtu" in rest.lower() and not _MS_RE.search(rest):
            continue  # tracepath's "[LOCALHOST] pmtu 65535" line isn't a real hop
        # Remove the times first so "0.050" isn't mistaken for part of an address.
        found = _addresses(_MS_RE.sub(" ", rest))
        # tracepath can print the same hop twice; keep the first line that has an address.
        if number in hops and hops[number].address:
            continue
        hop = Hop(number, None, _times(rest))
        _add_addresses(hop, found)
        hops[number] = last = hop
    return [hops[n] for n in sorted(hops)]


def _add_addresses(hop: Hop, found: list[str]) -> None:
    for address in found:
        if hop.address is None:
            hop.address = address
        elif address != hop.address and address not in hop.other_addresses:
            hop.other_addresses.append(address)


def trace(
    host: str,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_TIMEOUT,
    tool: Optional[str] = None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    resolver: Callable[[str], tuple[str, int]] = hosts.resolve,
) -> TraceResult:
    """Trace the route to ``host``.

    Raises TraceUnavailable if no tool is installed, hosts.InvalidHost for a
    bad name and hosts.UnknownHost if it can't be resolved. Only the resolved
    IP address is passed to the tool.
    """
    if not 1 <= max_hops <= 64:
        raise ValueError("max hops must be between 1 and 64")
    host = hosts.validate_host(host)
    tool = tool or find_tool()
    if tool is None:
        raise TraceUnavailable(
            "no traceroute program found. Install 'traceroute' (Linux/macOS) - "
            "a built-in trace would need administrator rights for raw sockets."
        )
    ip, _family = resolver(host)
    cmd = build_trace_command(tool, ip, max_hops, timeout)
    try:
        stdout, stderr, returncode = run_tool(cmd, max_hops * (timeout * 3 + 1) + 10, runner)
    except FileNotFoundError as exc:
        raise TraceUnavailable(f"'{cmd[0]}' could not be started") from exc
    except subprocess.TimeoutExpired:
        return TraceResult(host, tool, error="trace took too long and was stopped", address=ip)
    hops = parse_trace_output(stdout)
    error = None
    if not hops:
        output = (stderr + stdout).strip()
        error = output.splitlines()[-1] if output else f"{tool} exited with code {returncode}"
    return TraceResult(host, tool, hops, error, address=ip)
