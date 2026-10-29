"""Argument checks, exit codes, reports and printing for the command line.

The feature functions are replaced by fakes, so nothing touches the network.
"""
from __future__ import annotations

import io
import json
import sys

import pytest

from netscope import __main__ as cli
from netscope.dns import LookupResult
from netscope.output import fmt_ms
from netscope.ping import PingResult
from netscope.report import check_report_path, render_html, save_report
from netscope.output import envelope
from netscope.trace import Hop, TraceResult


def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def usage_error(capsys, *argv) -> str:
    with pytest.raises(SystemExit) as exc:
        cli.main(list(argv))
    assert exc.value.code == cli.EXIT_USAGE
    return capsys.readouterr().err


# ---- argument checks (M2, M6)

@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-1", "61", "1e9", "abc"])
@pytest.mark.parametrize("command", [["ping", "localhost"], ["scan", "localhost"], ["trace", "localhost"],
                                     ["http", "http://127.0.0.1/"], ["latency"]])
def test_bad_timeouts_are_refused(capsys, command, value):
    assert "--timeout" in usage_error(capsys, *command, f"--timeout={value}")


def test_timeout_limit_is_allowed(monkeypatch, capsys):
    monkeypatch.setattr(cli, "do_ping", lambda host, **kw: PingResult(host, "tcp", 1, [1.0], port=80))
    assert run(capsys, "ping", "localhost", "-t", "60")[0] == cli.EXIT_OK


@pytest.mark.parametrize("value", ["0", "65", "-3", "x"])
def test_bad_max_hops(capsys, value):
    assert "--max-hops" in usage_error(capsys, "trace", "localhost", f"--max-hops={value}")


@pytest.mark.parametrize("value", ["0", "70000", "65536", "-1"])
def test_bad_port(capsys, value):
    assert "--port" in usage_error(capsys, "ping", "localhost", "--method", "tcp", f"--port={value}")


def test_bad_deadline_and_probes(capsys):
    assert "--deadline" in usage_error(capsys, "http", "http://127.0.0.1/", "--deadline", "nan")
    assert "--max-probes" in usage_error(capsys, "scan", "localhost", "--max-probes", "0")


# ---- last-resort handlers (M2)

def test_unexpected_error_is_one_line_and_exit_4(monkeypatch, capsys):
    def boom(args, color):
        raise RuntimeError("something odd")
    monkeypatch.setitem(cli.HANDLERS, "info", boom)
    code, out, err = run(capsys, "info")
    assert code == cli.EXIT_NETWORK
    assert err.strip() == "netscope: unexpected error: RuntimeError: something odd"
    assert "Traceback" not in err


def test_ctrl_c_is_exit_130(monkeypatch, capsys):
    def interrupted(args, color):
        raise KeyboardInterrupt
    monkeypatch.setitem(cli.HANDLERS, "info", interrupted)
    code, _, err = run(capsys, "info")
    assert code == cli.EXIT_INTERRUPTED == 130 and "Stopped" in err


def test_exit_codes_are_in_help(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "130" in capsys.readouterr().out


# ---- exit codes (M3)

def fake_ping(times, sent=4, duplicates=0):
    return lambda host, **kw: PingResult(host, "icmp", sent, list(times), duplicates=duplicates,
                                         address="127.0.0.1")


@pytest.mark.parametrize("times, code", [
    ([1.0, 1.0, 1.0, 1.0], cli.EXIT_OK),
    ([1.0, 1.0, 1.0], cli.EXIT_FINDINGS),    # partial loss
    ([], cli.EXIT_FINDINGS),                 # unreachable
])
def test_ping_exit_codes(monkeypatch, capsys, times, code):
    monkeypatch.setattr(cli, "do_ping", fake_ping(times))
    got, out, _ = run(capsys, "ping", "localhost")
    assert got == code
    if code and times:
        assert "packet loss" in out


def test_ping_duplicates_are_mentioned(monkeypatch, capsys):
    monkeypatch.setattr(cli, "do_ping", fake_ping([1.0], sent=3, duplicates=2))
    code, out, _ = run(capsys, "ping", "localhost")
    assert code == cli.EXIT_FINDINGS and "2 duplicate replies ignored" in out and "66.7%" in out


def test_trace_with_only_stars_is_a_finding(monkeypatch, capsys):
    hops = [Hop(1, None), Hop(2, None), Hop(3, None)]
    monkeypatch.setattr(cli.trace_mod, "trace", lambda host, **kw: TraceResult(host, "traceroute", hops))
    code, out, _ = run(capsys, "trace", "localhost")
    assert code == cli.EXIT_FINDINGS and "No router answered" in out


def test_trace_with_replies_is_ok_and_shows_extra_addresses(monkeypatch, capsys):
    hops = [Hop(1, "192.168.1.1", [1.0]), Hop(2, "10.0.0.1", [5.0, 6.0], other_addresses=["10.0.0.2"])]
    monkeypatch.setattr(cli.trace_mod, "trace", lambda host, **kw: TraceResult(host, "traceroute", hops))
    code, out, _ = run(capsys, "trace", "localhost")
    assert code == cli.EXIT_OK and "(also 10.0.0.2)" in out


def test_dns_lookup_failure_is_exit_4(monkeypatch, capsys):
    monkeypatch.setattr(cli.dns_mod, "lookup", lambda n: LookupResult(n, error="lookup failed: not known"))
    assert run(capsys, "dns", "nowhere.invalid")[0] == cli.EXIT_NETWORK


# ---- --save (nits) and saving before printing (M5)

def ok_dns(monkeypatch, name_ips=("127.0.0.1",)):
    monkeypatch.setattr(cli.dns_mod, "lookup", lambda n: LookupResult(n, ipv4=list(name_ips), elapsed_ms=0.2))


def test_save_needs_an_existing_folder(monkeypatch, capsys, tmp_path):
    ok_dns(monkeypatch)
    err = usage_error(capsys, "dns", "localhost", "--save", str(tmp_path / "nope" / "r.json"))
    assert "folder" in err and not (tmp_path / "nope").exists()


def test_save_will_not_overwrite_without_force(monkeypatch, capsys, tmp_path):
    ok_dns(monkeypatch)
    target = tmp_path / "r.json"
    target.write_text("keep me", encoding="utf-8")
    assert "--force" in usage_error(capsys, "dns", "localhost", "--save", str(target))
    assert target.read_text(encoding="utf-8") == "keep me"
    code, _, err = run(capsys, "dns", "localhost", "--save", str(target), "--force")
    assert code == cli.EXIT_OK and json.loads(target.read_text(encoding="utf-8"))["command"] == "dns"


def test_save_path_is_checked_before_the_work(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli.dns_mod, "lookup", lambda n: pytest.fail("should not run"))
    usage_error(capsys, "dns", "localhost", "--save", str(tmp_path / "r.txt"))


def test_failed_save_warns_and_keeps_the_exit_code(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli.dns_mod, "lookup", lambda n: LookupResult(n, error="lookup failed"))

    def fail(path, doc, force=False):
        raise OSError("disk full")
    monkeypatch.setattr(cli, "save_report", fail)
    code, _, err = run(capsys, "dns", "nowhere.invalid", "--save", str(tmp_path / "r.json"))
    assert code == cli.EXIT_NETWORK and "Warning: could not save report: disk full" in err


def test_report_is_saved_before_printing(monkeypatch, capsys, tmp_path):
    ok_dns(monkeypatch)
    target = tmp_path / "r.json"

    def to_json(document, ascii_only=False):
        assert target.exists(), "the report should already be on disk"
        raise OSError("console went away")
    monkeypatch.setattr(cli, "to_json", to_json)
    code, _, _ = run(capsys, "dns", "localhost", "--json", "--save", str(target))
    assert code == cli.EXIT_NETWORK and target.exists()


def test_check_report_path_rules(tmp_path):
    with pytest.raises(ValueError, match=".json or .html"):
        check_report_path(tmp_path / "r.txt")
    with pytest.raises(ValueError, match="folder"):
        check_report_path(tmp_path / "missing" / "r.json")
    (tmp_path / "dir.json").mkdir()
    with pytest.raises(ValueError):
        check_report_path(tmp_path / "dir.json", force=True)
    (tmp_path / "r.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="--force"):
        save_report(tmp_path / "r.json", {"x": 1})
    save_report(tmp_path / "r.json", envelope("dns", {}), force=True)


# ---- JSON and console encoding (M5)

def test_json_is_ascii_when_not_a_terminal(monkeypatch, capsys):
    monkeypatch.setattr(cli.dns_mod, "lookup", lambda n: LookupResult("bücher中.test", ipv4=["127.0.0.1"]))
    _, out, _ = run(capsys, "dns", "localhost", "--json")
    assert out.isascii() and "\\u4e2d" in out
    assert json.loads(out)["data"]["lookup"]["name"] == "bücher中.test"


def test_json_keeps_characters_on_a_terminal(monkeypatch, capsys):
    monkeypatch.setattr(cli.dns_mod, "lookup", lambda n: LookupResult("bücher中.test", ipv4=["127.0.0.1"]))
    monkeypatch.setattr(cli, "_is_terminal", lambda: True)
    _, out, _ = run(capsys, "dns", "localhost", "--json")
    assert "bücher中.test" in out


def test_cp1252_console_does_not_crash(monkeypatch):
    # A Windows console that can only show cp1252: "中" must not raise UnicodeEncodeError.
    raw = io.BytesIO()
    console = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", console)
    monkeypatch.setattr(cli.dns_mod, "lookup", lambda n: LookupResult(n, ipv4=["127.0.0.1"]))
    code = cli.main(["dns", "bücher中.test"])
    console.flush()
    assert code == cli.EXIT_OK
    printed = raw.getvalue().decode("cp1252")
    assert "bücher\\u4e2d.test" in printed


# ---- small display fixes

def test_sub_millisecond_times():
    assert fmt_ms(0.5) == "<1 ms" and fmt_ms(0.04) == "<1 ms"
    assert fmt_ms(1.0) == "1.0 ms" and fmt_ms(None) == "-"


def test_html_report_has_csp():
    html_text = render_html(envelope("dns", {"name": "x"}))
    assert '<meta http-equiv="Content-Security-Policy"' in html_text
    assert "default-src 'none'" in html_text
