"""Tests for the command-line interface (netscope.__main__).

Feature functions are swapped for fakes with monkeypatch, so these tests check
argument handling, output, reports and exit codes - not the network.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from netscope import __main__ as cli
from netscope import RESPONSIBLE_USE
from netscope.dns import LookupResult, ReverseResult
from netscope.httpcheck import CertInfo, HttpResult
from netscope.netinfo import Interface, NetInfo
from netscope.ping import PingResult, PingUnavailable
from netscope.trace import Hop, TraceResult, TraceUnavailable

COMMANDS = ["ping", "scan", "dns", "trace", "info", "http", "latency"]


def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


# ---- help and usage

def test_no_command_prints_help(capsys):
    code, out, _ = run(capsys)
    assert code == cli.EXIT_USAGE and "usage: netscope" in out


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_has_help(command, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--json" in out and "--save" in out and "exit codes" in out


def test_scan_help_mentions_responsible_use(capsys):
    with pytest.raises(SystemExit):
        cli.main(["scan", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "--i-own-this" in out and "written permission" in out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0 and "netscope 0.1.0" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [
    ["ping", "h", "--count", "0"], ["ping", "h", "--timeout", "-1"], ["scan", "h", "--workers", "0"],
    ["scan", "h", "--workers", "501"], ["info", "--save", "report.txt"], ["bogus"],
])
def test_bad_arguments_exit_2(argv):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2


def test_module_runs_as_script():
    proc = subprocess.run([sys.executable, "-m", "netscope", "--help"], capture_output=True, text=True)
    assert proc.returncode == 0 and "netscope" in proc.stdout


# ---- ping

def test_ping_reachable(monkeypatch, capsys):
    monkeypatch.setattr(cli, "do_ping", lambda host, **k: PingResult(host, "tcp", 2, [1.0, 3.0], port=80))
    code, out, _ = run(capsys, "ping", "router")
    assert code == 0 and "reachable" in out and "TCP connect to port 80" in out and "2.0 ms" in out


def test_ping_unreachable_is_a_finding(monkeypatch, capsys):
    monkeypatch.setattr(cli, "do_ping", lambda host, **k: PingResult(host, "icmp", 2, error="timed out"))
    code, out, _ = run(capsys, "ping", "10.0.0.99")
    assert code == cli.EXIT_FINDINGS and "unreachable" in out and "Note: timed out" in out


def test_ping_unavailable_is_network_error(monkeypatch, capsys):
    def boom(host, **k):
        raise PingUnavailable("the 'ping' program is not installed")
    monkeypatch.setattr(cli, "do_ping", boom)
    code, _, err = run(capsys, "ping", "h", "--method", "icmp")
    assert code == cli.EXIT_NETWORK and "--method tcp" in err


def test_ping_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "do_ping", lambda host, **k: PingResult(host, "tcp", 1, [2.0], port=80))
    code, out, _ = run(capsys, "ping", "h", "--json")
    doc = json.loads(out)
    assert doc["schema_version"] == "1.0" and doc["command"] == "ping"
    assert doc["data"]["avg_ms"] == 2.0


# ---- scan (real sockets on 127.0.0.1)

def test_scan_localhost_finds_open_port(listening_port, closed_port, capsys):
    code, out, err = run(capsys, "scan", "127.0.0.1", "-p", f"{listening_port},{closed_port}", "-t", "5")
    assert code == 0 and f"{listening_port}/tcp" in out and "1 open, 1 closed" in out
    assert err == ""  # no warning for your own machine


def test_scan_show_closed_and_json(listening_port, closed_port, capsys):
    code, out, _ = run(capsys, "scan", "127.0.0.1", "-p", f"{listening_port},{closed_port}",
                       "-t", "5", "--show-closed", "--json")
    doc = json.loads(out)
    assert doc["data"]["kind"] == "loopback"
    states = {p["port"]: p["state"] for p in doc["data"]["hosts"][0]["ports"]}
    assert states == {listening_port: "open", closed_port: "closed"}


def test_scan_small_loopback_range(listening_port, capsys):
    code, out, _ = run(capsys, "scan", "127.0.0.0/30", "-p", str(listening_port))
    assert code == 0 and "2 addresses scanned in 127.0.0.0/30 (loopback)" in out


def test_scan_bad_ports_is_usage_error(capsys):
    code, _, err = run(capsys, "scan", "127.0.0.1", "-p", "99999")
    assert code == cli.EXIT_USAGE and "out of range" in err


def test_scan_bad_network_is_usage_error(capsys):
    code, _, err = run(capsys, "scan", "300.1.1.0/24")
    assert code == cli.EXIT_USAGE


@pytest.mark.parametrize("target", ["8.8.0.0/23", "100.64.0.1", "100.64.0.0/28"])
def test_scan_guard_rail_refuses_with_exit_3(target, monkeypatch, capsys):
    # If the guard rail failed, this fake would make the test fail instead of touching the network.
    monkeypatch.setattr(cli.portscan, "scan_ports", lambda *a, **k: pytest.fail("scan should be refused"))
    code, _, err = run(capsys, "scan", target)
    assert code == cli.EXIT_REFUSED and "refused" in err and RESPONSIBLE_USE in err


def test_scan_flag_allows_and_prints_responsible_use(monkeypatch, capsys):
    calls = []
    from netscope.portscan import ScanResult
    monkeypatch.setattr(cli.portscan, "scan_ports",
                        lambda host, ports, **k: calls.append(host) or ScanResult(host, host, len(ports), 0.0))
    code, out, err = run(capsys, "scan", "100.64.0.1", "-p", "80", "--i-own-this")
    assert code == 0 and calls == ["100.64.0.1"]
    assert "--i-own-this given" in err and RESPONSIBLE_USE in err


def test_scan_unresolvable_host_is_network_error(monkeypatch, capsys):
    def fail(host):
        raise ValueError("could not resolve 'nowhere.invalid'")
    monkeypatch.setattr(cli.portscan, "resolve_target", fail)
    code, _, err = run(capsys, "scan", "nowhere.invalid")
    assert code == cli.EXIT_NETWORK and "could not resolve" in err


# ---- dns

def test_dns_forward_with_reverse(monkeypatch, capsys):
    monkeypatch.setattr(cli.dns_mod, "lookup",
                        lambda n: LookupResult(n, ["93.184.216.34"], ["2606:2800::1"], 3.2))
    monkeypatch.setattr(cli.dns_mod, "reverse_lookup", lambda ip: ReverseResult(ip, "edge.example"))
    code, out, _ = run(capsys, "dns", "example.com", "--reverse")
    assert code == 0 and "AAAA" in out and "edge.example" in out


def test_dns_unknown_name_is_a_network_error(monkeypatch, capsys):
    monkeypatch.setattr(cli.dns_mod, "lookup", lambda n: LookupResult(n, error="lookup failed: nope"))
    code, out, _ = run(capsys, "dns", "nowhere.invalid")
    assert code == cli.EXIT_NETWORK and "lookup failed" in out


def test_dns_ip_does_reverse_lookup(monkeypatch, capsys):
    monkeypatch.setattr(cli.dns_mod, "reverse_lookup", lambda ip: ReverseResult(ip, "dns.google"))
    code, out, _ = run(capsys, "dns", "8.8.8.8")
    assert code == 0 and "dns.google" in out


# ---- trace

def test_trace_output(monkeypatch, capsys):
    result = TraceResult("h", "traceroute", [Hop(1, "192.168.1.1", [1.0]), Hop(2, None)])
    monkeypatch.setattr(cli.trace_mod, "trace", lambda host, **k: result)
    code, out, _ = run(capsys, "trace", "h")
    assert code == 0 and "192.168.1.1" in out and "no reply" in out


def test_trace_unavailable(monkeypatch, capsys):
    def none(host, **k):
        raise TraceUnavailable("no traceroute program found")
    monkeypatch.setattr(cli.trace_mod, "trace", none)
    code, _, err = run(capsys, "trace", "h")
    assert code == cli.EXIT_NETWORK and "skipped" in err


def test_trace_failed(monkeypatch, capsys):
    monkeypatch.setattr(cli.trace_mod, "trace", lambda h, **k: TraceResult(h, "traceroute", error="bad host"))
    code, out, _ = run(capsys, "trace", "h")
    assert code == cli.EXIT_NETWORK and "bad host" in out


# ---- info

def test_info(monkeypatch, capsys):
    info = NetInfo("laptop", "laptop.local", "192.168.1.42", "Linux 6",
                   [Interface("wlan0", True, 300, ["192.168.1.42"], [], "aa:bb")])
    monkeypatch.setattr(cli.netinfo, "collect", lambda: info)
    code, out, _ = run(capsys, "info")
    assert code == 0 and "192.168.1.42" in out and "wlan0" in out and "300 Mb/s" in out


def test_info_without_psutil(monkeypatch, capsys):
    info = NetInfo("laptop", "laptop", None, "Windows 11", [], "install psutil to list interfaces")
    monkeypatch.setattr(cli.netinfo, "collect", lambda: info)
    code, out, _ = run(capsys, "info")
    assert "offline" in out and "install psutil" in out


# ---- http

def test_http_local_server(http_server, capsys):
    code, out, _ = run(capsys, "http", http_server + "/")
    assert code == 0 and "200 OK" in out and "content-type" in out


def test_http_404_is_a_finding(http_server, capsys):
    code, out, _ = run(capsys, "http", http_server + "/missing")
    assert code == cli.EXIT_FINDINGS and "404" in out


def test_http_connection_error(closed_port, capsys):
    code, out, _ = run(capsys, "http", f"http://127.0.0.1:{closed_port}/")
    assert code == cli.EXIT_NETWORK and "refused" in out


def test_http_bad_scheme(capsys):
    code, _, err = run(capsys, "http", "ftp://example.com")
    assert code == cli.EXIT_USAGE and "only http" in err


def test_http_expiring_certificate_is_a_finding(monkeypatch, capsys):
    result = HttpResult("https://a.test", "https://a.test", 200, "OK", 10.0, 12.0,
                        cert=CertInfo("a.test", "CA", "2026-11-01", 3, "TLSv1.3"))
    monkeypatch.setattr(cli.httpcheck, "check_url", lambda url, **k: result)
    code, out, _ = run(capsys, "http", "https://a.test")
    assert code == cli.EXIT_FINDINGS and "3 days left, critical" in out


# ---- latency

def test_latency(monkeypatch, capsys):
    from netscope.latency import LatencyEntry
    entries = [LatencyEntry("Cloudflare", PingResult("1.1.1.1", "tcp", 3, [10.0], port=443))]
    monkeypatch.setattr(cli.latency, "summary", lambda **k: entries)
    code, out, _ = run(capsys, "latency")
    assert code == 0 and "excellent" in out


def test_latency_all_down_is_network_error(monkeypatch, capsys):
    from netscope.latency import LatencyEntry
    entries = [LatencyEntry("Cloudflare", PingResult("1.1.1.1", "tcp", 3, port=443))]
    monkeypatch.setattr(cli.latency, "summary", lambda **k: entries)
    code, out, _ = run(capsys, "latency")
    assert code == cli.EXIT_NETWORK and "unreachable" in out


# ---- saving reports

@pytest.mark.parametrize("name", ["report.json", "report.html"])
def test_save_report(name, http_server, tmp_path, capsys):
    path = tmp_path / name
    code, _, err = run(capsys, "http", http_server + "/", "--save", str(path))
    assert code == 0 and path.exists() and "Report saved" in err
    if name.endswith(".json"):
        assert json.loads(path.read_text(encoding="utf-8"))["data"]["status"] == 200


def test_save_report_unwritable(monkeypatch, http_server, capsys):
    def fail(path, doc, force=False):
        raise PermissionError("read-only")
    monkeypatch.setattr(cli, "save_report", fail)
    code, out, err = run(capsys, "http", http_server + "/", "--save", "x.json")
    # The check itself worked, so its exit code stands; the failed save is only a warning.
    assert code == cli.EXIT_OK and "could not save report" in err and "200 OK" in out
