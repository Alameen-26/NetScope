"""DNS lookups using only Python's standard library.

- **Forward lookup** (name -> addresses): ``socket.getaddrinfo`` asks the
  operating system's resolver, the same one your browser uses. We split the
  answers into IPv4 (A records) and IPv6 (AAAA records).
- **Reverse lookup** (address -> name): ``socket.gethostbyaddr`` asks for the
  PTR record, the "name tag" an address owner can attach to an IP.

Because we go through the OS resolver, results also include entries from the
local ``hosts`` file - handy, and worth mentioning in an interview.

Added in v0.1.0
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class LookupResult:
    name: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    elapsed_ms: Optional[float] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.ipv4 or self.ipv6)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ipv4": self.ipv4, "ipv6": self.ipv6,
                "elapsed_ms": self.elapsed_ms, "error": self.error}


@dataclass
class ReverseResult:
    ip: str
    hostname: Optional[str] = None
    aliases: list[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.hostname is not None

    def to_dict(self) -> dict[str, Any]:
        return {"ip": self.ip, "hostname": self.hostname, "aliases": self.aliases,
                "error": self.error}


def is_ip_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _unique(items: list[str]) -> list[str]:
    """Remove duplicates but keep the original order (the resolver's preference order)."""
    return list(dict.fromkeys(items))


def lookup(name: str, resolver: Optional[Callable[..., list]] = None) -> LookupResult:
    """Resolve a host name to its IPv4 and IPv6 addresses."""
    # Looked up at call time (not as a default argument), see hosts.resolve.
    resolve_fn: Callable[..., list] = resolver if resolver is not None else socket.getaddrinfo
    result = LookupResult(name)
    start = time.perf_counter()
    try:
        # SOCK_STREAM stops getaddrinfo returning the same address once per socket type.
        answers = resolve_fn(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        result.error = f"lookup failed: {exc.strerror or exc}"
        return result
    finally:
        result.elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    v4 = [a[4][0] for a in answers if a[0] == socket.AF_INET]
    v6 = [a[4][0] for a in answers if a[0] == socket.AF_INET6]
    result.ipv4, result.ipv6 = _unique(v4), _unique(v6)
    if not result.ok:
        result.error = "no addresses found"
    return result


def reverse_lookup(ip: str, resolver: Callable[[str], tuple] = socket.gethostbyaddr) -> ReverseResult:
    """Find the host name registered for an IP address (its PTR record)."""
    if not is_ip_address(ip):
        return ReverseResult(ip, error="not a valid IP address")
    try:
        hostname, aliases, _ = resolver(ip)
    except (socket.herror, socket.gaierror) as exc:
        return ReverseResult(ip, error=f"no reverse record: {exc.strerror or exc}")
    except OSError as exc:
        return ReverseResult(ip, error=str(exc))
    return ReverseResult(ip, hostname, list(aliases))
