"""Host validation, IPv6 forms of IPv4 addresses, big ranges, the probe cap and EMFILE.

Nothing here sends a packet anywhere: names are "resolved" by fakes and the
guard rail decides before any connection is made.
"""
from __future__ import annotations

import errno
import ipaddress
import socket
import time

import pytest

from netscope import __main__ as cli
from netscope import hosts, portscan, safety
from netscope.hosts import InvalidHost, UnknownHost, resolve, validate_host
from netscope.portscan import OPEN, PortResult, TooManyOpenFiles, check_port, default_timeout, scan_ports


def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# ---- host names

@pytest.mark.parametrize("good", ["localhost", "192.168.1.1", "::1", "fe80::1%eth0", "my-pc.lan", "a_b"])
def test_valid_hosts(good):
    assert validate_host(f" {good} ") == good


@pytest.mark.parametrize("bad", ["", "   ", "-c1", "--help", "a b", "host;rm", "x$(id)", "a" * 254, "ho/st"])
def test_invalid_hosts(bad):
    with pytest.raises(InvalidHost):
        validate_host(bad, system="Linux")


def test_windows_slash_options_are_refused():
    with pytest.raises(InvalidHost, match="option"):
        validate_host("/n", system="Windows")


def test_resolve_prefers_ipv4():
    info = [(socket.AF_INET6, 1, 6, "", ("::1", 0, 0, 0)), (socket.AF_INET, 1, 6, "", ("127.0.0.1", 0))]
    assert resolve("localhost", lambda *a, **k: info) == ("127.0.0.1", socket.AF_INET)
    assert resolve("v6only", lambda *a, **k: info[:1]) == ("::1", socket.AF_INET6)


@pytest.mark.parametrize("error", [socket.gaierror(-2, "Name or service not known"), UnicodeError("bad label")])
def test_resolve_failures_are_unknown_host(error):
    def fail(*a, **k):
        raise error
    with pytest.raises(UnknownHost, match="could not resolve"):
        resolve("nowhere.invalid", fail)
    with pytest.raises(UnknownHost):
        resolve("empty", lambda *a, **k: [])


def test_unknown_host_is_exit_4_everywhere(monkeypatch, capsys):
    def unknown(host, resolver=None):
        raise UnknownHost(f"could not resolve '{host}': not known")
    monkeypatch.setattr(hosts, "resolve", unknown)
    monkeypatch.setattr(portscan.hosts, "resolve", unknown)
    monkeypatch.setattr("netscope.ping.hosts.resolve", unknown)
    monkeypatch.setattr("netscope.trace.find_tool", lambda: "traceroute")
    # ping and trace take the resolver as a default argument, so patch the callers' view too.
    import netscope.ping as ping_mod
    import netscope.trace as trace_mod
    monkeypatch.setattr(cli, "do_ping", lambda host, **kw: ping_mod.ping(host, resolver=unknown, **kw))
    real_trace = trace_mod.trace
    monkeypatch.setattr(cli.trace_mod, "trace", lambda host, **kw: real_trace(host, resolver=unknown, **kw))
    for argv in (["ping", "nowhere.invalid"], ["scan", "nowhere.invalid"], ["trace", "nowhere.invalid"]):
        code, _, err = run(capsys, *argv)
        assert code == cli.EXIT_NETWORK, argv
        assert "could not resolve" in err


def test_bad_host_is_usage_error(capsys):
    for argv in (["ping", "--", "-x"], ["scan", "a;b"], ["trace", "a b"]):
        code, _, err = run(capsys, *argv)
        assert code == cli.EXIT_USAGE, argv


def test_ping_passes_resolved_ip_to_the_tool():
    seen = []

    def runner(cmd, **kw):
        seen.append(cmd)
        import subprocess
        return subprocess.CompletedProcess(cmd, 0, b"64 bytes from 192.0.2.7: ttl=64 time=1.0 ms\n", b"")
    from netscope.ping import ping
    result = ping("printer.lan", count=1, method="icmp", runner=runner,
                  resolver=lambda h: ("192.0.2.7", socket.AF_INET))
    assert seen[0][-1] == "192.0.2.7" and result.host == "printer.lan" and result.address == "192.0.2.7"


def test_ping_rejects_bad_port():
    from netscope.ping import ping
    for port in (0, 65536):
        with pytest.raises(ValueError, match="port"):
            ping("localhost", method="tcp", port=port)


# ---- IPv6 forms of IPv4 addresses (M1). Same answers on every Python version.

@pytest.mark.parametrize("ip, kind", [
    ("::ffff:127.0.0.1", safety.LOOPBACK),
    ("::ffff:192.168.1.5", safety.PRIVATE),
    ("::ffff:1.1.1.1", safety.PUBLIC),
    ("::ffff:100.64.1.1", safety.SHARED),
    ("64:ff9b::8.8.8.8", safety.PUBLIC),        # NAT64
    ("64:ff9b::10.0.0.1", safety.PRIVATE),
    ("2002:c0a8:0101::1", safety.PRIVATE),       # 6to4 for 192.168.1.1
    ("2002:6440:0101::1", safety.SHARED),        # 6to4 for 100.64.1.1
    ("2002:0808:0808::1", safety.PUBLIC),        # 6to4 for 8.8.8.8
])
def test_embedded_ipv4_is_classified_as_ipv4(ip, kind):
    assert safety.classify_address(ip) == kind


def test_embedded_ipv4_ranges():
    assert safety.embedded_ipv4(ipaddress.ip_network("::ffff:8.8.8.0/120")) == ipaddress.ip_network("8.8.8.0/24")
    assert safety.embedded_ipv4(ipaddress.ip_network("2002:c0a8:0100::/40")) == ipaddress.ip_network("192.168.1.0/24")
    assert safety.embedded_ipv4(ipaddress.ip_network("10.0.0.0/8")) is None
    assert safety.embedded_ipv4(ipaddress.ip_network("fd00::/64")) is None


def test_mapped_public_range_is_refused_like_ipv4():
    # 1024 public IPv4 addresses hidden in a mapped range: the /24 public limit applies.
    decision = safety.check_target(ipaddress.ip_network("::ffff:8.8.8.0/118"))
    assert not decision.allowed and "8.8.8.0/22" in decision.message


def test_mapped_cgnat_is_refused():
    decision = safety.check_target(ipaddress.ip_network("::ffff:100.64.1.1/128"))
    assert not decision.allowed and decision.kind == safety.SHARED


# ---- huge ranges are refused before any list of addresses is built (H3)

@pytest.mark.parametrize("target", ["10.0.0.0/8", "::/64", "fd00::/48", "0.0.0.0/0"])
def test_huge_range_refused_instantly(capsys, target):
    start = time.perf_counter()
    code, _, err = run(capsys, "scan", target, "-p", "80")
    assert code == cli.EXIT_REFUSED and "refused" in err
    assert time.perf_counter() - start < 1.0   # would take minutes (or run out of memory) if expanded


def test_parse_target_does_not_expand():
    network, name = cli.parse_target("10.0.0.0/8")
    assert network.num_addresses == 2 ** 24 and name is None
    assert list(cli.iter_hosts(ipaddress.ip_network("127.0.0.1/32"))) == ["127.0.0.1"]
    assert list(cli.iter_hosts(ipaddress.ip_network("127.0.0.0/30"))) == ["127.0.0.1", "127.0.0.2"]


# ---- probe cap (L5)

def test_probe_cap_refuses_large_scans(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(portscan, "scan_ports", lambda *a, **k: called.append(1))
    # 254 hosts x 1024 ports = 260,096 attempts > 65,536.
    code, _, err = run(capsys, "scan", "127.0.0.0/24", "-p", "1-1024")
    assert code == cli.EXIT_REFUSED and "--max-probes" in err and "65,536" in err and not called


def test_probe_cap_can_be_lowered(monkeypatch, capsys):
    monkeypatch.setattr(portscan, "scan_ports", lambda *a, **k: pytest.fail("should not scan"))
    code, _, err = run(capsys, "scan", "127.0.0.1", "-p", "1-100", "--max-probes", "50")
    assert code == cli.EXIT_REFUSED and "100 connection attempts" in err


def test_probe_cap_can_be_raised(monkeypatch, capsys):
    def fake_scan(host, ports, **kw):
        return portscan.ScanResult(host, host, len(ports), 0.0, [PortResult(p, "closed", "x") for p in ports])
    monkeypatch.setattr(portscan, "scan_ports", fake_scan)
    code, _, _ = run(capsys, "scan", "127.0.0.0/24", "-p", "1-300", "--max-probes", "100000")
    assert code == cli.EXIT_OK


# ---- out of file handles (L3)

def test_check_port_reports_emfile():
    def no_sockets(*a):
        raise OSError(errno.EMFILE, "Too many open files")
    with pytest.raises(TooManyOpenFiles):
        check_port("127.0.0.1", 80, socket_factory=no_sockets)


def test_check_port_windows_wsaemfile():
    def no_sockets(*a):
        raise OSError(10024, "WSAEMFILE")
    with pytest.raises(TooManyOpenFiles):
        check_port("127.0.0.1", 80, socket_factory=no_sockets)


def test_check_port_other_socket_error_is_filtered():
    def broken(*a):
        raise OSError(errno.EACCES, "denied")
    assert check_port("127.0.0.1", 80, socket_factory=broken).state == "filtered"


def test_scan_slows_down_when_out_of_handles():
    calls = {"n": 0}

    def checker(ip, port, timeout, family):
        calls["n"] += 1
        if calls["n"] <= 5:      # the first few attempts run out of handles
            raise TooManyOpenFiles(errno.EMFILE, "too many open files")
        return PortResult(port, OPEN, "x", 1.0)
    result = scan_ports("127.0.0.1", list(range(1, 21)), workers=8, checker=checker,
                        resolver=lambda h: ("127.0.0.1", socket.AF_INET))
    assert [r.port for r in result.results] == list(range(1, 21))
    assert all(r.state == OPEN for r in result.results)
    assert result.workers_used is not None and result.workers_used < 8


def test_scan_without_handle_trouble_reports_no_slowdown():
    # Fewer ports than workers used to look like a slowdown; it must not.
    def checker(ip, port, timeout, family):
        return PortResult(port, OPEN, "x", 1.0)
    result = scan_ports("127.0.0.1", [1, 2, 3], workers=100, checker=checker,
                        resolver=lambda h: ("127.0.0.1", socket.AF_INET))
    assert result.workers_used is None


def test_cli_scan_of_few_ports_prints_no_slowdown_note(monkeypatch, capsys):
    real = portscan.scan_ports

    def few(host, ports, **kwargs):
        kwargs["checker"] = lambda ip, port, timeout, family: PortResult(port, OPEN, "x", 1.0)
        return real(host, ports, **kwargs)
    monkeypatch.setattr(portscan, "scan_ports", few)
    code, out, _ = run(capsys, "scan", "127.0.0.1", "-p", "80,443")
    assert code == cli.EXIT_OK and "ran out of open files" not in out


def test_scan_gives_up_at_one_worker():
    def checker(ip, port, timeout, family):
        raise TooManyOpenFiles(errno.EMFILE, "too many open files")
    with pytest.raises(TooManyOpenFiles, match="1 worker"):
        scan_ports("127.0.0.1", [1, 2, 3], workers=4, checker=checker,
                   resolver=lambda h: ("127.0.0.1", socket.AF_INET))


def test_cli_out_of_handles_is_exit_4(monkeypatch, capsys):
    def fail(*a, **k):
        raise TooManyOpenFiles(errno.EMFILE, "ran out of open files even with 1 worker")
    monkeypatch.setattr(portscan, "scan_ports", fail)
    code, _, err = run(capsys, "scan", "127.0.0.1", "-p", "80")
    assert code == cli.EXIT_NETWORK and "--workers" in err


# ---- Windows default timeout (M8)

def test_default_timeout_per_os():
    assert default_timeout("Windows") == 3.0
    assert default_timeout("Linux") == 0.5 and default_timeout("Darwin") == 0.5
