"""The test suite's own safety net (see conftest.py) really blocks the outside network.

The guard raises *before* the real socket call, so no packet is sent. The
address used is from 192.0.2.0/24, a range reserved for documentation.
"""
from __future__ import annotations

import socket

import pytest

import conftest


def test_outside_connect_is_blocked_and_recorded():
    with socket.socket() as sock:
        with pytest.raises(AssertionError, match="network"):
            sock.connect(("192.0.2.1", 80))
        with pytest.raises(AssertionError, match="network"):
            sock.connect_ex(("192.0.2.1", 80))
    assert conftest._blocked   # written down, so the test would fail even if swallowed
    conftest._blocked.clear()  # (this test expects it, so don't fail at teardown)


def test_real_dns_is_blocked():
    with pytest.raises(AssertionError, match="DNS"):
        socket.getaddrinfo("example.com", 80)
    conftest._blocked.clear()


def test_loopback_is_allowed(listening_port):
    with socket.create_connection(("127.0.0.1", listening_port), timeout=2):
        pass
    assert not conftest._blocked
