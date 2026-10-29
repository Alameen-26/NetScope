"""Tests for netscope.latency with a fake pinger."""
from __future__ import annotations

import pytest

from netscope.latency import DEFAULT_TARGETS, rate_latency, summary
from netscope.ping import PingResult


@pytest.mark.parametrize("ms, rating", [(None, "unreachable"), (5, "excellent"), (50, "good"),
                                        (120, "fair"), (400, "poor")])
def test_rate_latency(ms, rating):
    assert rate_latency(ms) == rating


def test_summary_checks_every_target_in_order():
    calls = []

    def fake(host, port, count, timeout):
        calls.append((host, port, count))
        return PingResult(host, "tcp", count, [10.0] * count, port=port)
    entries = summary(count=2, pinger=fake)
    assert [e.result.host for e in entries] == [t[1] for t in DEFAULT_TARGETS]
    assert sorted(calls) == sorted((t[1], t[2], 2) for t in DEFAULT_TARGETS)
    data = entries[0].to_dict()
    assert data["name"] == "Cloudflare" and data["rating"] == "excellent"


def test_summary_custom_targets_and_unreachable():
    fake = lambda host, port, count, timeout: PingResult(host, "tcp", count, port=port)
    entries = summary([("Router", "192.168.1.1", 80)], pinger=fake)
    assert entries[0].to_dict()["rating"] == "unreachable"
