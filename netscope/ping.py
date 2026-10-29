"""Reachability check: is a host up, and how long does it take to answer?

Two ways to measure it:

1. **System ping (ICMP).** Real ICMP needs a "raw socket", which normally
   requires administrator/root rights. The operating system's own ``ping``
   program already has that permission, so we run it and read its output.
2. **TCP connect (fallback).** If ``ping`` is missing or blocked, we time how
   long it takes to open a TCP connection to a port (80 by default). Even a
   "connection refused" answer proves the host is up and gives a round-trip
   time, because the host had to send a reply packet.

``method="auto"`` tries system ping first and falls back to TCP.

Added in v0.1.0
"""
from __future__ import annotations

import platform
import re
import socket
import statistics
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from . import hosts
from .syscmd import run_tool

DEFAULT_COUNT = 4
DEFAULT_TIMEOUT = 2.0   # seconds to wait for each reply
DEFAULT_TCP_PORT = 80

# ping prints its replies in the user's language: "time=12 ms" (English),
# "temps=12 ms" (French), "Zeit=12ms" (German), "время=12мс" (Russian)... So we
# don't look for the word "time". Instead we take the number just before "ms"
# (or the Cyrillic "мс") on lines that look like a reply:
#
# - the line contains "TTL=" (IPv4 replies, every language), or
# - it contains "hlim=" (macOS IPv6 "hop limit"), or
# - it contains exactly ONE time value. Windows IPv6 replies have no TTL at all
#   ("Reply from ::1: time<1ms"), while summary lines have three
#   ("Minimum = 0ms, Maximum = 1ms, Average = 0ms"), so they're still skipped.
_REPLY_MARKER = re.compile(r"\b(?:ttl|hlim)\s*=", re.IGNORECASE)
_TIME_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс)(?!\w)", re.IGNORECASE)
# Linux marks duplicate replies "(DUP!)"; they must not hide real packet loss.
_DUPLICATE = re.compile(r"\(DUP!\)")
# Windows rounds fast replies to "<1ms". We store the middle of that range
# (0.5 ms) so averages aren't pushed up to a full millisecond.
SUB_MS_VALUE = 0.5


class PingUnavailable(RuntimeError):
    """Raised when the system ``ping`` program can't be used on this machine."""


@dataclass
class PingResult:
    """Everything one ping run found out about a host."""

    host: str
    method: str                       # "icmp" (system ping) or "tcp"
    sent: int
    times_ms: list[float] = field(default_factory=list)  # one entry per reply
    port: Optional[int] = None        # only set for TCP pings
    error: Optional[str] = None
    address: Optional[str] = None     # the IP the host name resolved to
    duplicates: int = 0               # duplicate replies seen (not counted as received)

    @property
    def received(self) -> int:
        return len(self.times_ms)

    @property
    def reachable(self) -> bool:
        return self.received > 0

    @property
    def partial_loss(self) -> bool:
        """Some, but not all, replies came back - worth flagging as a finding."""
        return 0 < self.received < self.sent

    @property
    def loss_percent(self) -> float:
        if self.sent == 0:
            return 100.0
        return round(100.0 * (self.sent - self.received) / self.sent, 1)

    def _stat(self, fn: Callable[[list[float]], float]) -> Optional[float]:
        # None (not 0) when there were no replies, so "no data" never looks like "instant".
        return round(fn(self.times_ms), 2) if self.times_ms else None

    @property
    def min_ms(self) -> Optional[float]:
        return self._stat(min)

    @property
    def avg_ms(self) -> Optional[float]:
        return self._stat(statistics.fmean)

    @property
    def max_ms(self) -> Optional[float]:
        return self._stat(max)

    @property
    def jitter_ms(self) -> Optional[float]:
        """Average change between consecutive replies - how "steady" the connection is."""
        if len(self.times_ms) < 2:
            return 0.0 if self.times_ms else None
        diffs = [abs(b - a) for a, b in zip(self.times_ms, self.times_ms[1:])]
        return round(statistics.fmean(diffs), 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "address": self.address,
            "method": self.method,
            "port": self.port,
            "sent": self.sent,
            "received": self.received,
            "loss_percent": self.loss_percent,
            "reachable": self.reachable,
            "min_ms": self.min_ms,
            "avg_ms": self.avg_ms,
            "max_ms": self.max_ms,
            "jitter_ms": self.jitter_ms,
            "times_ms": [round(t, 2) for t in self.times_ms],
            "duplicates": self.duplicates,
            "error": self.error,
        }


def build_ping_command(host: str, count: int, timeout: float, system: Optional[str] = None,
                       ipv6: bool = False) -> list[str]:
    """Build the right ``ping`` command line for this operating system.

    Each OS spells the options differently:
    - Windows: ``-n`` count, ``-w`` timeout in milliseconds
    - macOS:   ``-c`` count, ``-W`` timeout in milliseconds; IPv6 needs the
      separate ``ping6`` program, which has no per-reply timeout option
    - Linux:   ``-c`` count, ``-W`` timeout in whole seconds (handles IPv6 itself)

    ``host`` should already be validated (see hosts.validate_host).
    """
    system = system or platform.system()
    if system == "Windows":
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    if system == "Darwin":
        if ipv6:
            return ["ping6", "-c", str(count), host]
        return ["ping", "-c", str(count), "-W", str(int(timeout * 1000)), host]
    return ["ping", "-c", str(count), "-W", str(max(1, round(timeout))), host]


def _to_ms(match: re.Match[str]) -> float:
    """Number from a time match; "<1ms" becomes SUB_MS_VALUE."""
    value = float(match.group(1).replace(",", "."))  # "12,3" in some languages
    if match.group(0).startswith("<") and value <= 1:
        return SUB_MS_VALUE
    return value


def parse_ping_replies(text: str) -> tuple[list[float], int]:
    """Return (reply times in ms, number of duplicate replies) from ping's output."""
    times: list[float] = []
    duplicates = 0
    for line in text.splitlines():
        matches = list(_TIME_RE.finditer(line))
        if not matches:
            continue
        if not _REPLY_MARKER.search(line) and len(matches) != 1:
            continue  # a summary line such as "Minimum = 1ms, Maximum = 5ms, Average = 2ms"
        if _DUPLICATE.search(line):
            duplicates += 1
            continue
        times.append(_to_ms(matches[0]))
    return times, duplicates


def parse_ping_output(text: str) -> list[float]:
    """Pull every reply time (in ms) out of ``ping``'s text output, in any language."""
    return parse_ping_replies(text)[0]


def system_ping(
    host: str,
    count: int = DEFAULT_COUNT,
    timeout: float = DEFAULT_TIMEOUT,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> PingResult:
    """Run the operating system's ``ping`` and turn its output into a PingResult.

    ``runner`` is ``subprocess.run`` normally; tests pass a fake one so they
    never touch the real network.
    """
    host = hosts.validate_host(host)  # never let a "host" be read as a ping option
    cmd = build_ping_command(host, count, timeout, ipv6=":" in host)
    try:
        # Give ping a little longer than count x timeout before giving up on it.
        stdout, stderr, returncode = run_tool(cmd, count * (timeout + 1) + 5, runner)
    except FileNotFoundError as exc:
        raise PingUnavailable("the 'ping' program is not installed") from exc
    except PermissionError as exc:
        raise PingUnavailable("not allowed to run 'ping' on this system") from exc
    except subprocess.TimeoutExpired:
        return PingResult(host, "icmp", count, error="ping took too long and was stopped")

    output = stdout + stderr
    times, duplicates = parse_ping_replies(output)
    times = times[:count]
    error = None
    if not times:
        # ping exits non-zero for both "no replies" and "unknown host"; show its own words.
        last_line = output.strip().splitlines()[-1] if output.strip() else ""
        error = last_line or f"no replies (ping exit code {returncode})"
    return PingResult(host, "icmp", count, times, error=error, duplicates=duplicates)


def tcp_ping(
    host: str,
    port: int = DEFAULT_TCP_PORT,
    count: int = DEFAULT_COUNT,
    timeout: float = DEFAULT_TIMEOUT,
    interval: float = 0.2,
    connect: Callable[..., socket.socket] = socket.create_connection,
    sleep: Callable[[float], None] = time.sleep,
) -> PingResult:
    """Measure reachability by timing TCP connections instead of ICMP.

    No special permissions are needed, so this works everywhere.
    """
    result = PingResult(host, "tcp", count, port=port)
    for attempt in range(count):
        start = time.perf_counter()
        try:
            sock = connect((host, port), timeout=timeout)
            sock.close()
            result.times_ms.append((time.perf_counter() - start) * 1000)
        except ConnectionRefusedError:
            # The host actively said "nothing listening here" - so it IS up.
            result.times_ms.append((time.perf_counter() - start) * 1000)
        except socket.gaierror as exc:
            # The name couldn't be resolved: no point trying again.
            result.error = f"could not resolve host: {exc.strerror or exc}"
            break
        except OSError as exc:  # includes timeouts and "network unreachable"
            result.error = str(exc) or exc.__class__.__name__
        if attempt < count - 1:
            sleep(interval)  # small pause so we don't flood the host
    if result.reachable:
        result.error = None  # a few lost packets are reported as loss, not as an error
    return result


def ping(
    host: str,
    count: int = DEFAULT_COUNT,
    timeout: float = DEFAULT_TIMEOUT,
    method: str = "auto",
    port: int = DEFAULT_TCP_PORT,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    connect: Callable[..., socket.socket] = socket.create_connection,
    resolver: Callable[[str], tuple[str, int]] = hosts.resolve,
) -> PingResult:
    """Check a host using ``method`` = "auto", "icmp" or "tcp".

    The name is checked and resolved once here, and only the IP address is
    passed on. Raises hosts.InvalidHost for a bad name and hosts.UnknownHost
    when it can't be resolved.
    """
    if count < 1:
        raise ValueError("count must be at least 1")
    if method not in ("auto", "icmp", "tcp"):
        raise ValueError(f"unknown method: {method}")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    host = hosts.validate_host(host)
    ip, _family = resolver(host)
    result: Optional[PingResult] = None
    if method in ("auto", "icmp"):
        try:
            result = system_ping(ip, count, timeout, runner=runner)
        except PingUnavailable:
            if method == "icmp":
                raise
            # auto: quietly fall back to the TCP method.
    if result is None:
        result = tcp_ping(ip, port, count, timeout, connect=connect)
    result.host, result.address = host, ip  # show the name the user typed
    return result
