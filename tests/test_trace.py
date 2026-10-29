"""Tests for netscope.trace using recorded output from each traceroute tool."""
from __future__ import annotations

import socket
import subprocess

import pytest

from netscope.trace import (TraceUnavailable, build_trace_command, find_tool,
                            parse_trace_output, trace)

TRACEROUTE = """traceroute to example.com (93.184.216.34), 20 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms
 2  10.20.0.1  8.511 ms
 3  *
 4  93.184.216.34  21.9 ms
"""

TRACERT = """
Tracing route to example.com [93.184.216.34]
over a maximum of 20 hops:

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     9 ms     8 ms    10 ms  10.20.0.1
  3     *        *        *     Request timed out.
  4    22 ms    21 ms    22 ms  93.184.216.34

Trace complete.
"""

TRACEPATH = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.1.1                                           0.512ms
 1:  192.168.1.1                                           0.430ms
 2:  no reply
 3:  2001:db8::1                                          12.100ms reached
     Resume: pmtu 1500 hops 3 back 3
"""


def test_parse_traceroute():
    hops = parse_trace_output(TRACEROUTE)
    assert [h.number for h in hops] == [1, 2, 3, 4]
    assert hops[0].address == "192.168.1.1" and hops[0].avg_ms == 1.23
    assert hops[2].address is None and hops[2].avg_ms is None
    assert hops[3].address == "93.184.216.34"


def test_parse_tracert_windows():
    hops = parse_trace_output(TRACERT)
    assert [h.address for h in hops] == ["192.168.1.1", "10.20.0.1", None, "93.184.216.34"]
    assert hops[0].times_ms == [0.5, 0.5, 0.5]   # "<1 ms" is stored as 0.5
    assert hops[1].avg_ms == 9.0


def test_parse_tracepath_with_ipv6_and_duplicates():
    hops = parse_trace_output(TRACEPATH)
    assert [h.number for h in hops] == [1, 2, 3]
    assert hops[0].address == "192.168.1.1" and hops[0].times_ms == [0.512]
    assert hops[1].address is None
    assert hops[2].address == "2001:db8::1"


def test_parse_ignores_garbage():
    assert parse_trace_output("hello\nworld\n") == []


@pytest.mark.parametrize("system, which, expected", [
    ("Windows", {"tracert"}, "tracert"),
    ("Linux", {"traceroute", "tracepath"}, "traceroute"),
    ("Linux", {"tracepath"}, "tracepath"),
    ("Darwin", set(), None),
])
def test_find_tool(system, which, expected):
    assert find_tool(system, which=lambda n: n if n in which else None) == expected


def test_build_commands():
    assert build_trace_command("tracert", "h", 10, 1.5)[:6] == ["tracert", "-d", "-h", "10", "-w", "1500"]
    assert build_trace_command("tracepath", "h", 10, 1)[-1] == "h"
    tr = build_trace_command("traceroute", "h", 10, 2)
    assert "-n" in tr and "-q" in tr and tr[-1] == "h"


def runner_returning(stdout, returncode=0, stderr=""):
    return lambda cmd, **k: subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)


def fake_resolve(host):
    """Stand-in for hosts.resolve, so these tests never do a real DNS lookup."""
    return "192.0.2.1", socket.AF_INET


def test_trace_runs_tool_and_parses():
    result = trace("example.com", tool="traceroute", runner=runner_returning(TRACEROUTE),
                   resolver=fake_resolve)
    assert result.error is None and len(result.hops) == 4
    assert result.to_dict()["hops"][0]["address"] == "192.168.1.1"


def test_trace_reports_tool_error():
    result = trace("bad", tool="traceroute",
                   runner=runner_returning("", 2, "bad: Name or service not known"),
                   resolver=fake_resolve)
    assert result.hops == [] and "Name or service" in result.error


def test_trace_timeout():
    def slow(cmd, **k):
        raise subprocess.TimeoutExpired(cmd, 1)
    assert "too long" in trace("h", tool="traceroute", runner=slow, resolver=fake_resolve).error


def test_trace_unavailable(monkeypatch):
    monkeypatch.setattr("netscope.trace.find_tool", lambda: None)
    with pytest.raises(TraceUnavailable, match="administrator"):
        trace("h")


def test_trace_tool_vanished():
    def missing(cmd, **k):
        raise FileNotFoundError()
    with pytest.raises(TraceUnavailable):
        trace("h", tool="traceroute", runner=missing, resolver=fake_resolve)


def test_trace_rejects_bad_hops():
    with pytest.raises(ValueError):
        trace("h", max_hops=0, tool="traceroute")
