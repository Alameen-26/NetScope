"""Tests for netscope.portscan, using real sockets on 127.0.0.1 and fake ones."""
from __future__ import annotations

import socket
import threading

import pytest

from netscope import portscan
from netscope.hosts import UnknownHost
from netscope.portscan import (CLOSED, COMMON_PORTS, FILTERED, OPEN, PortResult, check_port,
                               parse_ports, resolve_target, scan_ports, service_name)


# ---- parsing the --ports option

@pytest.mark.parametrize("spec, expected", [
    ("22", [22]),
    ("80,22,443", [22, 80, 443]),
    ("8000-8003", [8000, 8001, 8002, 8003]),
    ("22, 22 ,80", [22, 80]),        # spaces and duplicates
    ("1-3,2-4", [1, 2, 3, 4]),
])
def test_parse_ports(spec, expected):
    assert parse_ports(spec) == expected


def test_parse_common_and_all():
    assert parse_ports("common") == sorted(COMMON_PORTS)
    assert parse_ports("COMMON,9999") == sorted(COMMON_PORTS + [9999])
    assert len(parse_ports("all")) == 65535


@pytest.mark.parametrize("spec, message", [
    ("", "no ports"), (",", "no ports"), ("abc", "not a port"), ("0", "out of range"),
    ("65536", "out of range"), ("90-80", "backwards"), ("1-x", "not a port"),
])
def test_parse_ports_errors(spec, message):
    with pytest.raises(ValueError, match=message):
        parse_ports(spec)


# ---- service names

def test_service_name_known_and_fallback(monkeypatch):
    service_name.cache_clear()
    assert service_name(80) == "http"

    def unknown(port, proto):
        raise OSError("not found")
    monkeypatch.setattr(portscan.socket, "getservbyport", unknown)
    service_name.cache_clear()
    assert service_name(6379) == "redis"
    assert service_name(65000) == "unknown"
    service_name.cache_clear()


def test_service_name_is_consistent_across_threads():
    """Regression: getservbyport isn't thread-safe; names must not get mixed up."""
    service_name.cache_clear()
    expected = {p: service_name(p) for p in COMMON_PORTS}
    service_name.cache_clear()
    seen: dict[int, set[str]] = {p: set() for p in COMMON_PORTS}

    def worker():
        for p in COMMON_PORTS:
            seen[p].add(service_name(p))
    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(seen[p] == {expected[p]} for p in COMMON_PORTS)


# ---- checking single ports

def test_check_port_open(listening_port):
    result = check_port("127.0.0.1", listening_port, timeout=1)
    assert result.state == OPEN and result.latency_ms is not None


def test_check_port_closed(closed_port):
    result = check_port("127.0.0.1", closed_port, timeout=5)
    assert result.state == CLOSED


class FakeSocket:
    def __init__(self, code=None, exc=None):
        self.code, self.exc, self.closed = code, exc, False

    def settimeout(self, t):
        self.timeout = t

    def connect_ex(self, addr):
        if self.exc:
            raise self.exc
        return self.code

    def close(self):
        self.closed = True


@pytest.mark.parametrize("code, state", [(0, OPEN), (111, CLOSED), (61, CLOSED), (10061, CLOSED),
                                         (11, FILTERED), (113, FILTERED)])
def test_check_port_error_codes(code, state):
    sock = FakeSocket(code=code)
    assert check_port("10.0.0.1", 22, socket_factory=lambda *a: sock).state == state
    assert sock.closed  # sockets are always closed, even on errors


def test_check_port_exception_is_filtered():
    sock = FakeSocket(exc=socket.timeout())
    assert check_port("10.0.0.1", 22, socket_factory=lambda *a: sock).state == FILTERED
    assert sock.closed


# ---- resolving and scanning

def test_resolve_prefers_ipv4(monkeypatch):
    answers = [(socket.AF_INET6, 1, 6, "", ("::1", 0, 0, 0)),
               (socket.AF_INET, 1, 6, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(portscan.socket, "getaddrinfo", lambda *a, **k: answers)
    assert resolve_target("localhost") == ("127.0.0.1", socket.AF_INET)


def test_resolve_ipv6_only(monkeypatch):
    answers = [(socket.AF_INET6, 1, 6, "", ("::1", 0, 0, 0))]
    monkeypatch.setattr(portscan.socket, "getaddrinfo", lambda *a, **k: answers)
    assert resolve_target("v6host") == ("::1", socket.AF_INET6)


def test_resolve_failure(monkeypatch):
    def fail(*a, **k):
        raise socket.gaierror(-2, "Name or service not known")
    monkeypatch.setattr(portscan.socket, "getaddrinfo", fail)
    with pytest.raises(UnknownHost, match="could not resolve"):
        resolve_target("nowhere.invalid")


def test_scan_ports_with_fake_checker_keeps_order_and_counts():
    states = {22: OPEN, 80: CLOSED, 443: FILTERED, 8080: OPEN}

    def checker(ip, port, timeout, family):
        return PortResult(port, states[port], "svc")
    result = scan_ports("box", [8080, 22, 80, 443], checker=checker,
                        resolver=lambda h: ("10.0.0.2", socket.AF_INET))
    assert [r.port for r in result.results] == [8080, 22, 80, 443]
    assert result.counts() == {"open": 2, "closed": 1, "filtered": 1}
    assert [r.port for r in result.open_ports] == [8080, 22]
    data = result.to_dict()
    assert data["ip"] == "10.0.0.2" and len(data["ports"]) == 2
    assert len(result.to_dict(include_closed=True)["ports"]) == 4


def test_scan_ports_real_localhost(listening_port, closed_port):
    result = scan_ports("127.0.0.1", sorted([listening_port, closed_port]), timeout=5, workers=4)
    by_port = {r.port: r.state for r in result.results}
    assert by_port == {listening_port: OPEN, closed_port: CLOSED}


def test_scan_ports_needs_ports():
    with pytest.raises(ValueError):
        scan_ports("127.0.0.1", [])


def test_scan_never_starts_more_threads_than_ports(monkeypatch):
    created = []
    real = portscan.ThreadPoolExecutor

    def spy(max_workers):
        created.append(max_workers)
        return real(max_workers=max_workers)
    monkeypatch.setattr(portscan, "ThreadPoolExecutor", spy)
    scan_ports("x", [1, 2], workers=100, checker=lambda *a: PortResult(a[1], CLOSED, "s"),
               resolver=lambda h: ("127.0.0.1", socket.AF_INET))
    assert created == [2]
