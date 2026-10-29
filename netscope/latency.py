"""Latency summary: how quickly do a few well-known public servers answer?

This is a quick "is my internet OK?" check. It times TCP connections (see
``ping.tcp_ping``) to large public DNS providers on port 443, which are fast,
reliable and reachable from almost every network. All targets are checked at
the same time with a small thread pool, so the whole check takes a few seconds.

It measures **latency** (delay), not download **speed**; a bandwidth test
would need to move megabytes of data and is on the roadmap.

Added in v0.1.0
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .ping import PingResult, tcp_ping

DEFAULT_TARGETS: list[tuple[str, str, int]] = [
    ("Cloudflare", "1.1.1.1", 443),
    ("Google DNS", "8.8.8.8", 443),
    ("Quad9", "9.9.9.9", 443),
]


def rate_latency(avg_ms: Optional[float]) -> str:
    """Describe a round-trip time in everyday words."""
    if avg_ms is None:
        return "unreachable"
    if avg_ms < 30:
        return "excellent"
    if avg_ms < 80:
        return "good"
    if avg_ms < 150:
        return "fair"
    return "poor"


@dataclass
class LatencyEntry:
    name: str
    result: PingResult

    def to_dict(self) -> dict[str, Any]:
        data = {"name": self.name, **self.result.to_dict()}
        data["rating"] = rate_latency(self.result.avg_ms)
        return data


def summary(
    targets: Optional[list[tuple[str, str, int]]] = None,
    count: int = 3,
    timeout: float = 2.0,
    pinger: Callable[..., PingResult] = tcp_ping,
) -> list[LatencyEntry]:
    """Time ``count`` TCP connections to each target, all targets in parallel."""
    targets = targets or DEFAULT_TARGETS

    def run(target: tuple[str, str, int]) -> LatencyEntry:
        name, host, port = target
        return LatencyEntry(name, pinger(host, port=port, count=count, timeout=timeout))

    with ThreadPoolExecutor(max_workers=len(targets)) as pool:
        return list(pool.map(run, targets))
