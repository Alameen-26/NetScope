"""Tests for netscope.netinfo with a fake psutil and fake sockets."""
from __future__ import annotations

import socket
from types import SimpleNamespace

from netscope import netinfo


class FakeUdp:
    def __init__(self, fail=False):
        self.fail, self.closed, self.target = fail, False, None

    def connect(self, addr):
        if self.fail:
            raise OSError("Network is unreachable")
        self.target = addr

    def getsockname(self):
        return ("192.168.1.42", 50000)

    def close(self):
        self.closed = True


def test_local_ip_uses_udp_trick_without_sending():
    sock = FakeUdp()
    assert netinfo.get_local_ip(lambda *a: sock) == "192.168.1.42"
    assert sock.target == netinfo._PROBE_ADDRESS and sock.closed


def test_local_ip_offline_returns_none():
    sock = FakeUdp(fail=True)
    assert netinfo.get_local_ip(lambda *a: sock) is None and sock.closed


def fake_psutil():
    addr = lambda fam, a: SimpleNamespace(family=fam, address=a)
    return SimpleNamespace(
        AF_LINK=-1,
        net_if_addrs=lambda: {
            "wlan0": [addr(socket.AF_INET, "192.168.1.42"), addr(socket.AF_INET6, "fe80::1%wlan0"),
                      addr(-1, "aa:bb:cc:dd:ee:ff")],
            "lo": [addr(socket.AF_INET, "127.0.0.1")],
        },
        net_if_stats=lambda: {"wlan0": SimpleNamespace(isup=True, speed=300),
                              "lo": SimpleNamespace(isup=True, speed=0)},
    )


def test_interfaces_from_psutil():
    interfaces, note = netinfo.get_interfaces(fake_psutil())
    assert note is None
    assert [i.name for i in interfaces] == ["lo", "wlan0"]  # sorted by name
    wlan = interfaces[1]
    assert wlan.ipv4 == ["192.168.1.42"] and wlan.ipv6 == ["fe80::1"]
    assert wlan.mac == "aa:bb:cc:dd:ee:ff" and wlan.speed_mbps == 300 and wlan.is_up
    assert interfaces[0].speed_mbps is None  # 0 means unknown


def test_interfaces_without_psutil(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_psutil(name, *a, **k):
        if name == "psutil":
            raise ImportError
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_psutil)
    interfaces, note = netinfo.get_interfaces()
    assert interfaces == [] and "pip install psutil" in note


def test_collect_puts_it_together():
    info = netinfo.collect(fake_psutil(), socket_factory=lambda *a: FakeUdp())
    data = info.to_dict()
    assert data["local_ip"] == "192.168.1.42" and data["hostname"]
    assert len(data["interfaces"]) == 2
