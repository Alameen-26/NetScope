"""TCP port scanner: which "doors" on a host are open?

How it works, in plain words:

- A TCP connection starts with a three-way handshake. If a program is
  listening on the port, the handshake completes -> the port is **open**.
- If nothing is listening, the host replies with a reset -> **closed**.
- If nothing comes back before the timeout (often a firewall silently
  dropping packets) -> **filtered**.

Checking ports one by one would be slow (each closed/filtered port can cost a
full timeout), so we use a pool of threads that each try one port at a time.
Network waits release Python's GIL, so threads work well here.

Added in v0.1.0
"""
from __future__ import annotations

import errno
import platform
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, Optional

from . import hosts

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"



def default_timeout(system: Optional[str] = None) -> float:
    """Seconds to wait for each port.

    0.5 s is plenty on a LAN or localhost - except on Windows, which quietly
    retries a refused connection (it resends the connection request after a
    reset) and only reports "refused" after about 2 seconds. With a shorter
    timeout, closed ports would wrongly show as "filtered", so Windows gets
    3 seconds by default.
    """
    return 3.0 if (system or platform.system()) == "Windows" else 0.5


DEFAULT_TIMEOUT = default_timeout()
DEFAULT_WORKERS = 100   # how many ports are tried at the same time
MAX_PORTS = 65535

# Ports people most often need to check on their own machines and home networks.
COMMON_PORTS: list[int] = [
    20, 21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 443, 445, 465, 587,
    631, 993, 995, 1433, 1521, 1883, 3000, 3306, 3389, 5000, 5432, 5900,
    6379, 8000, 8080, 8443, 8888, 9200, 27017,
]

# Fallback names for ports the OS "services" database might not know about.
_EXTRA_SERVICES: dict[int, str] = {
    1433: "mssql", 1521: "oracle", 1883: "mqtt", 3000: "dev-server", 3306: "mysql",
    3389: "rdp", 5000: "dev-server", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    latency_ms: Optional[float] = None  # only known when the port answered

    def to_dict(self) -> dict[str, Any]:
        return {"port": self.port, "state": self.state, "service": self.service,
                "latency_ms": self.latency_ms}


@dataclass
class ScanResult:
    host: str
    ip: str
    ports_scanned: int
    duration_s: float
    results: list[PortResult] = field(default_factory=list)
    workers_used: Optional[int] = None   # lower than asked if we ran out of file handles

    @property
    def open_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state == OPEN]

    def counts(self) -> dict[str, int]:
        return {s: sum(1 for r in self.results if r.state == s) for s in (OPEN, CLOSED, FILTERED)}

    def to_dict(self, include_closed: bool = False) -> dict[str, Any]:
        shown = self.results if include_closed else self.open_ports
        return {
            "host": self.host,
            "ip": self.ip,
            "ports_scanned": self.ports_scanned,
            "duration_s": self.duration_s,
            "workers_used": self.workers_used,
            "counts": self.counts(),
            "ports": [r.to_dict() for r in shown],
        }


def parse_ports(spec: str) -> list[int]:
    """Turn text like ``"22,80,8000-8010"`` or ``"common"`` into a sorted port list.

    Raises ValueError with a clear message for anything that isn't a valid port.
    """
    spec = spec.strip().lower()
    if not spec:
        raise ValueError("no ports given")
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "common":
            ports.update(COMMON_PORTS)
        elif part == "all":
            ports.update(range(1, MAX_PORTS + 1))
        elif "-" in part:
            lo_text, hi_text = part.split("-", 1)
            lo, hi = _to_port(lo_text), _to_port(hi_text)
            if lo > hi:
                raise ValueError(f"port range '{part}' goes backwards")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(_to_port(part))
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def _to_port(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise ValueError(f"'{text}' is not a port number") from None
    if not 1 <= port <= MAX_PORTS:
        raise ValueError(f"port {port} is out of range (1-{MAX_PORTS})")
    return port


# socket.getservbyport() is NOT thread-safe on some systems (it uses a shared
# C buffer), so during a threaded scan two threads could swap answers - we saw
# port 6379 labelled "mysql". A lock makes lookups one-at-a-time, and the cache
# means each port is only looked up once anyway.
_SERVICE_LOCK = threading.Lock()


@lru_cache(maxsize=4096)
def service_name(port: int) -> str:
    """Best-guess name of the service that normally uses a TCP port."""
    with _SERVICE_LOCK:
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return _EXTRA_SERVICES.get(port, "unknown")


class TooManyOpenFiles(OSError):
    """The computer ran out of file handles (each port being checked uses one)."""


# errno values meaning "no more file handles": EMFILE (this program) and ENFILE
# (the whole system). On Windows, sockets report WSAEMFILE (10024) instead.
_OUT_OF_HANDLES = {errno.EMFILE, errno.ENFILE, 10024}


def resolve_target(host: str) -> tuple[str, int]:
    """Look up a host name once, returning (ip, address_family).

    Doing this up front means we don't repeat the DNS lookup for every port.
    Raises hosts.UnknownHost if the name can't be resolved.
    """
    return hosts.resolve(host, socket.getaddrinfo)


def check_port(
    ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    family: int = socket.AF_INET,
    socket_factory: Callable[..., socket.socket] = socket.socket,
) -> PortResult:
    """Try a single TCP connection and report open / closed / filtered.

    Raises TooManyOpenFiles if no socket could be created, so the scanner can
    slow down instead of wrongly reporting the port as "filtered".
    """
    sock: Optional[socket.socket] = None
    try:
        sock = socket_factory(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        # connect_ex returns an error number instead of raising, which keeps this simple.
        code = sock.connect_ex((ip, port))
        elapsed = round((time.perf_counter() - start) * 1000, 2)
    except OSError as exc:  # socket.timeout is a kind of OSError too
        if exc.errno in _OUT_OF_HANDLES:
            raise TooManyOpenFiles(exc.errno, "too many open files") from exc
        return PortResult(port, FILTERED, service_name(port))
    finally:
        if sock is not None:
            sock.close()
    if code == 0:
        return PortResult(port, OPEN, service_name(port), elapsed)
    if code in _REFUSED_CODES:
        return PortResult(port, CLOSED, service_name(port), elapsed)
    # Timeouts and "host unreachable" style errors: we got no clear answer.
    return PortResult(port, FILTERED, service_name(port))


# "Connection refused" has a different error number on Windows (10061) than on
# Linux (111) and macOS (61).
_REFUSED_CODES = {111, 61, 10061}


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = DEFAULT_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
    checker: Callable[[str, int, float, int], PortResult] = check_port,
    resolver: Callable[[str], tuple[str, int]] = resolve_target,
) -> ScanResult:
    """Scan ``ports`` on ``host`` in parallel and return the results sorted by port."""
    if not ports:
        raise ValueError("no ports to scan")
    ip, family = resolver(host)
    workers = max(1, min(workers, len(ports)))  # no point starting more threads than ports
    start = time.perf_counter()
    done: dict[int, PortResult] = {}
    remaining = list(ports)
    slowed_to: Optional[int] = None   # only set if we had to drop workers
    # If the computer runs out of file handles (each check holds a socket
    # open), retry just the failed ports with half as many workers, down to 1.
    while remaining:
        failed = _scan_round(ip, family, remaining, timeout, workers, checker, done)
        if not failed:
            break
        if workers == 1:
            raise TooManyOpenFiles(errno.EMFILE, "ran out of open files even with 1 worker; "
                                   "close other programs or raise the open-file limit")
        workers = max(1, workers // 2)
        slowed_to = workers
        remaining = failed
    duration = round(time.perf_counter() - start, 3)
    results = [done[p] for p in ports]  # same order as `ports`
    return ScanResult(host, ip, len(ports), duration, results, workers_used=slowed_to)


def _scan_round(ip: str, family: int, ports: list[int], timeout: float, workers: int,
                checker: Callable[[str, int, float, int], PortResult],
                done: dict[int, PortResult]) -> list[int]:
    """Check ``ports`` with a thread pool; return the ports that hit TooManyOpenFiles."""
    def attempt(port: int) -> Optional[PortResult]:
        try:
            return checker(ip, port, timeout, family)
        except TooManyOpenFiles:
            return None

    failed = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for port, result in zip(ports, pool.map(attempt, ports)):
            if result is None:
                failed.append(port)
            else:
                done[port] = result
    return failed
