"""Tests for netscope.ping - no real network: recorded output and fake runners/sockets."""
from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import pytest

from netscope import ping as ping_mod
from netscope.ping import (PingResult, PingUnavailable, build_ping_command, parse_ping_output,
                           ping, system_ping, tcp_ping)

DATA = Path(__file__).parent / "data"


def read(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


# ---- building the command for each OS

@pytest.mark.parametrize("system, expected", [
    ("Windows", ["ping", "-n", "3", "-w", "1500", "h"]),
    ("Darwin", ["ping", "-c", "3", "-W", "1500", "h"]),
    ("Linux", ["ping", "-c", "3", "-W", "2", "h"]),
])
def test_build_ping_command(system, expected):
    assert build_ping_command("h", 3, 1.5, system=system) == expected


def test_linux_timeout_is_at_least_one_second():
    assert build_ping_command("h", 1, 0.2, system="Linux")[4] == "1"


# ---- parsing recorded output in several languages

@pytest.mark.parametrize("fixture, expected", [
    ("ping_linux_en.txt", [1.42, 1.10, 2.05]),
    ("ping_windows_en.txt", [3.0, 0.5, 5.0]),     # "<1ms" is stored as 0.5
    ("ping_windows_fr.txt", [4.0, 0.5, 12.0]),
    ("ping_windows_de.txt", [7.0, 0.5]),
    ("ping_linux_de.txt", [0.512, 0.734]),       # comma decimals
    ("ping_windows_unreachable.txt", []),        # "unreachable" reply has no TTL
])
def test_parse_localized_output(fixture, expected):
    assert parse_ping_output(read(fixture)) == pytest.approx(expected)


def test_summary_lines_are_not_counted_as_replies():
    text = "Minimum = 1ms, Maximum = 5ms, Average = 2ms\nrtt min/avg/max/mdev = 1.1/1.5/2.0/0.3 ms"
    assert parse_ping_output(text) == []


# ---- system_ping with a fake subprocess runner

def fake_runner(stdout: str = "", returncode: int = 0, exc: Exception | None = None):
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if exc:
            raise exc
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")
    run.calls = calls
    return run


def test_system_ping_success():
    runner = fake_runner(read("ping_linux_en.txt"))
    result = system_ping("192.168.1.1", count=3, runner=runner)
    assert result.method == "icmp"
    assert result.received == 3 and result.loss_percent == 0
    assert result.min_ms == 1.1 and result.max_ms == 2.05
    assert result.error is None
    assert runner.calls[0][-1] == "192.168.1.1"


def test_system_ping_partial_loss_windows():
    result = system_ping("192.168.1.1", count=4, runner=fake_runner(read("ping_windows_en.txt"), 0))
    assert result.received == 3
    assert result.loss_percent == 25.0


def test_system_ping_no_replies_reports_ping_message():
    out = "ping: unknown host nowhere.invalid"
    result = system_ping("nowhere.invalid", count=2, runner=fake_runner(out, 2))
    assert not result.reachable
    assert result.loss_percent == 100.0
    assert "unknown host" in result.error


def test_system_ping_missing_program_raises():
    with pytest.raises(PingUnavailable):
        system_ping("h", runner=fake_runner(exc=FileNotFoundError()))


def test_system_ping_permission_denied_raises():
    with pytest.raises(PingUnavailable):
        system_ping("h", runner=fake_runner(exc=PermissionError()))


def test_system_ping_hung_process_is_reported():
    result = system_ping("h", runner=fake_runner(exc=subprocess.TimeoutExpired("ping", 1)))
    assert not result.reachable and "too long" in result.error


# ---- tcp_ping with fake connect functions

class FakeSock:
    def close(self):
        pass


def test_tcp_ping_all_connect():
    result = tcp_ping("h", count=3, connect=lambda *a, **k: FakeSock(), sleep=lambda s: None)
    assert result.method == "tcp" and result.port == 80
    assert result.received == 3 and result.error is None


def test_tcp_ping_refused_still_counts_as_reachable():
    def refuse(*a, **k):
        raise ConnectionRefusedError()
    result = tcp_ping("h", count=2, connect=refuse, sleep=lambda s: None)
    assert result.reachable and result.received == 2


def test_tcp_ping_timeouts_are_loss():
    def timeout(*a, **k):
        raise socket.timeout("timed out")
    result = tcp_ping("h", count=3, connect=timeout, sleep=lambda s: None)
    assert result.received == 0 and result.loss_percent == 100.0
    assert "timed out" in result.error


def test_tcp_ping_bad_name_stops_early():
    attempts = []

    def bad(*a, **k):
        attempts.append(1)
        raise socket.gaierror(-2, "Name or service not known")
    result = tcp_ping("nowhere.invalid", count=4, connect=bad, sleep=lambda s: None)
    assert len(attempts) == 1
    assert "could not resolve" in result.error


def test_tcp_ping_some_loss_is_not_an_error():
    answers = iter([FakeSock(), socket.timeout(), FakeSock()])

    def flaky(*a, **k):
        item = next(answers)
        if isinstance(item, Exception):
            raise item
        return item
    result = tcp_ping("h", count=3, connect=flaky, sleep=lambda s: None)
    assert result.received == 2 and result.error is None
    assert result.loss_percent == pytest.approx(33.3)


def test_tcp_ping_real_local_server(listening_port):
    result = tcp_ping("127.0.0.1", port=listening_port, count=2, interval=0)
    assert result.reachable and result.received == 2


# ---- statistics

def test_stats_and_jitter():
    r = PingResult("h", "icmp", 4, [10.0, 20.0, 10.0])
    assert r.min_ms == 10 and r.max_ms == 20 and r.avg_ms == pytest.approx(13.33)
    assert r.jitter_ms == 10.0
    assert r.loss_percent == 25.0


def test_stats_are_none_without_replies():
    r = PingResult("h", "icmp", 2)
    assert r.avg_ms is None and r.jitter_ms is None
    d = r.to_dict()
    assert d["reachable"] is False and d["received"] == 0


def test_single_reply_has_zero_jitter():
    assert PingResult("h", "tcp", 1, [5.0]).jitter_ms == 0.0


# ---- ping() chooses the method

def fake_resolve(host):
    """Stand-in for hosts.resolve, so these tests never do a real DNS lookup."""
    return "192.0.2.1", socket.AF_INET


def test_auto_falls_back_to_tcp():
    result = ping("h", count=1, method="auto", runner=fake_runner(exc=FileNotFoundError()),
                  connect=lambda *a, **k: FakeSock(), resolver=fake_resolve)
    assert result.method == "tcp"


def test_icmp_only_does_not_fall_back():
    with pytest.raises(PingUnavailable):
        ping("h", method="icmp", runner=fake_runner(exc=FileNotFoundError()),
             resolver=fake_resolve)


def test_auto_prefers_system_ping():
    result = ping("192.168.1.1", count=3, runner=fake_runner(read("ping_linux_en.txt")))
    assert result.method == "icmp"


@pytest.mark.parametrize("kwargs", [{"count": 0}, {"method": "udp"}])
def test_invalid_arguments(kwargs):
    with pytest.raises(ValueError):
        ping("h", **kwargs)


def test_module_defaults_are_sensible():
    assert ping_mod.DEFAULT_COUNT >= 1 and ping_mod.DEFAULT_TIMEOUT > 0
