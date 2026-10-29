"""Tests for netscope.dns with fake resolvers (no real DNS queries)."""
from __future__ import annotations

import socket

from netscope.dns import is_ip_address, lookup, reverse_lookup


def answers(*addrs):
    out = []
    for a in addrs:
        fam = socket.AF_INET6 if ":" in a else socket.AF_INET
        out.append((fam, socket.SOCK_STREAM, 6, "", (a, 0)))
    return out


def test_lookup_splits_ipv4_and_ipv6_and_dedupes():
    fake = lambda *a: answers("93.184.216.34", "2606:2800::1", "93.184.216.34")
    result = lookup("example.com", resolver=fake)
    assert result.ok and result.error is None
    assert result.ipv4 == ["93.184.216.34"] and result.ipv6 == ["2606:2800::1"]
    assert result.elapsed_ms is not None
    assert result.to_dict()["name"] == "example.com"


def test_lookup_keeps_resolver_order():
    result = lookup("x", resolver=lambda *a: answers("10.0.0.2", "10.0.0.1"))
    assert result.ipv4 == ["10.0.0.2", "10.0.0.1"]


def test_lookup_failure():
    def fail(*a):
        raise socket.gaierror(-2, "Name or service not known")
    result = lookup("nowhere.invalid", resolver=fail)
    assert not result.ok and "Name or service not known" in result.error
    assert result.elapsed_ms is not None


def test_lookup_no_addresses():
    result = lookup("empty", resolver=lambda *a: [])
    assert not result.ok and result.error == "no addresses found"


def test_lookup_passes_stream_type_to_avoid_duplicates():
    seen = {}

    def spy(name, port, family, socktype):
        seen.update(name=name, family=family, socktype=socktype)
        return answers("127.0.0.1")
    lookup("localhost", resolver=spy)
    assert seen == {"name": "localhost", "family": socket.AF_UNSPEC, "socktype": socket.SOCK_STREAM}


def test_reverse_lookup_success():
    result = reverse_lookup("8.8.8.8", resolver=lambda ip: ("dns.google", ["alias"], [ip]))
    assert result.ok and result.hostname == "dns.google" and result.aliases == ["alias"]


def test_reverse_lookup_no_record():
    def fail(ip):
        raise socket.herror(1, "Unknown host")
    result = reverse_lookup("10.1.2.3", resolver=fail)
    assert not result.ok and "no reverse record" in result.error


def test_reverse_lookup_other_os_error():
    def fail(ip):
        raise OSError("boom")
    assert reverse_lookup("10.1.2.3", resolver=fail).error == "boom"


def test_reverse_lookup_rejects_non_ip():
    result = reverse_lookup("example.com", resolver=lambda ip: 1 / 0)
    assert result.error == "not a valid IP address"


def test_is_ip_address():
    assert is_ip_address("127.0.0.1") and is_ip_address("::1")
    assert not is_ip_address("localhost")


def test_real_localhost_lookup():
    # Resolves through the hosts file, so it works offline.
    result = lookup("localhost")
    assert result.ok and ("127.0.0.1" in result.ipv4 or "::1" in result.ipv6)
