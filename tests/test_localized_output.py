"""Windows console encodings, other languages, IPv6 and duplicate replies.

The ``.bin`` fixtures are raw bytes in the Windows console code page (cp850
for German/French, cp866 for Russian), as ping.exe and tracert.exe write
them. They are stored base64-encoded as ``<name>.bin.b64`` so the repository
holds only text files; ``fixture_bytes`` decodes them back to the exact bytes.
They go through the real decode path with a fake ``subprocess.run``
and a pretend Windows console - nothing is actually run.
"""
from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import base64

import pytest

from netscope import syscmd
from netscope.ping import (build_ping_command, parse_ping_replies, ping, system_ping)
from netscope.syscmd import console_encoding, decode_output, run_tool
from netscope.trace import build_trace_command, parse_trace_output, trace

DATA = Path(__file__).parent / "data"


def fixture_bytes(name: str) -> bytes:
    """Raw console bytes for ``name`` (stored base64-encoded as ``name.b64``)."""
    return base64.b64decode((DATA / (name + ".b64")).read_text(encoding="ascii"))


def fake_runner(data: bytes, returncode: int = 0):
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, returncode, data, b"")
    run.calls = calls  # type: ignore[attr-defined]
    return run


def windows_console(monkeypatch, page: int) -> None:
    """Pretend we're on Windows with console code page ``page``."""
    monkeypatch.setattr(syscmd, "console_encoding",
                        lambda: console_encoding("Windows", get_console_cp=lambda: page))


def local(ip: str):
    return lambda host: (ip, socket.AF_INET6 if ":" in ip else socket.AF_INET)


# ---- choosing the encoding

def test_windows_uses_console_code_page():
    assert console_encoding("Windows", get_console_cp=lambda: 850) == "cp850"
    assert console_encoding("Windows", get_console_cp=lambda: 866) == "cp866"


def test_windows_without_console_falls_back(monkeypatch):
    # 0 means "no console". Off Windows there is no "oem" codec, so the locale is used.
    monkeypatch.setattr(syscmd, "_codec_exists", lambda name: name == "oem")
    assert console_encoding("Windows", get_console_cp=lambda: 0) == "oem"
    monkeypatch.setattr(syscmd, "_codec_exists", lambda name: False)
    monkeypatch.setattr(syscmd.locale, "getpreferredencoding", lambda do_setlocale: "cp1252")
    assert console_encoding("Windows", get_console_cp=lambda: 0) == "cp1252"


def test_windows_unknown_code_page_or_failed_call(monkeypatch):
    monkeypatch.setattr(syscmd.locale, "getpreferredencoding", lambda do_setlocale: "UTF-8")

    def broken():
        raise OSError("no kernel32")
    # cp99999 isn't a real codec; neither case may crash.
    assert console_encoding("Windows", get_console_cp=lambda: 99999) in ("oem", "UTF-8")
    assert console_encoding("Windows", get_console_cp=broken) in ("oem", "UTF-8")


def test_other_systems_use_locale(monkeypatch):
    monkeypatch.setattr(syscmd.locale, "getpreferredencoding", lambda do_setlocale: "UTF-8")
    assert console_encoding("Linux") == "UTF-8"
    monkeypatch.setattr(syscmd.locale, "getpreferredencoding", lambda do_setlocale: "")
    assert console_encoding("Darwin") == "utf-8"


def test_decode_never_raises():
    assert decode_output(b"f\x81r", "cp850") == "für"
    assert "?" in decode_output(b"\xff\xfe\x81", "ascii") or "\ufffd" in decode_output(b"\xff", "ascii")
    assert decode_output(None, "utf-8") == "" and decode_output("text", "utf-8") == "text"


def test_old_way_would_have_crashed():
    # Why this matters: decoding cp850 output as cp1252 (Python's guess) fails.
    data = fixture_bytes("ping_windows_de_cp850.bin")
    with pytest.raises(UnicodeDecodeError):
        data.decode("cp1252")


def test_run_tool_captures_bytes_not_text():
    runner = fake_runner(b"ok")
    assert run_tool(["x"], 5, runner, encoding="utf-8") == ("ok", "", 0)
    _, kwargs = runner.calls[0]
    assert kwargs["capture_output"] is True and "text" not in kwargs and kwargs["timeout"] == 5


# ---- ping in other languages (bytes -> numbers)

@pytest.mark.parametrize("name, page, expected", [
    ("ping_windows_de_cp850.bin", 850, [3.0, 0.5, 9.0]),
    ("ping_windows_fr_cp850.bin", 850, [4.0, 0.5]),
    ("ping_windows_ru_cp866.bin", 866, [2.0, 0.5]),        # "мс" instead of "ms"
    ("ping_windows_de_ipv6_cp850.bin", 850, [0.5, 2.0]),   # IPv6: no TTL= on the line
])
def test_windows_ping_bytes(monkeypatch, name, page, expected):
    windows_console(monkeypatch, page)
    monkeypatch.setattr("netscope.ping.platform.system", lambda: "Windows")
    result = system_ping("192.168.1.1", count=len(expected) + 1, runner=fake_runner(fixture_bytes(name)))
    assert result.times_ms == expected


def test_fixture_text_really_is_localised(monkeypatch):
    text = decode_output(fixture_bytes("ping_windows_fr_cp850.bin"), "cp850")
    assert "Réponse" in text and "Délai d'attente" in text
    assert "für" in decode_output(fixture_bytes("ping_windows_de_cp850.bin"), "cp850")
    assert "мс" in decode_output(fixture_bytes("ping_windows_ru_cp866.bin"), "cp866")


def test_wrong_code_page_still_does_not_crash():
    # Even decoded with the wrong code page the numbers survive.
    text = decode_output(fixture_bytes("ping_windows_de_cp850.bin"), "ascii")
    assert parse_ping_replies(text)[0] == [3.0, 0.5, 9.0]


def test_russian_summary_line_is_not_a_reply():
    text = decode_output(fixture_bytes("ping_windows_ru_cp866.bin"), "cp866")
    times, _ = parse_ping_replies(text)
    assert len(times) == 2   # "Минимальное = 0мсек ..." must not be counted


# ---- IPv6 replies

@pytest.mark.parametrize("name, expected", [
    ("ping_windows_en_ipv6.txt", [0.5, 0.5, 3.0, 0.5]),   # "Reply from ::1: time<1ms"
    ("ping_macos_ipv6.txt", [0.062, 0.11, 0.084]),        # ping6 says hlim=, not ttl=
])
def test_ipv6_replies(name, expected):
    times, duplicates = parse_ping_replies((DATA / name).read_text(encoding="utf-8"))
    assert times == expected and duplicates == 0


def test_summary_lines_with_several_times_are_ignored():
    text = "    Minimum = 0ms, Maximum = 3ms, Average = 0ms\nrtt min/avg/max = 1.0/2.0/3.0 ms\n"
    assert parse_ping_replies(text) == ([], 0)


def test_linux_ipv6_reply():
    line = "64 bytes from ::1: icmp_seq=1 ttl=64 time=0.040 ms\n"
    assert parse_ping_replies(line)[0] == [0.04]


def test_macos_uses_ping6_for_ipv6():
    assert build_ping_command("::1", 3, 1.0, "Darwin", ipv6=True) == ["ping6", "-c", "3", "::1"]
    assert build_ping_command("127.0.0.1", 3, 1.0, "Darwin")[0] == "ping"
    # Linux and Windows handle IPv6 with the normal ping.
    assert build_ping_command("::1", 3, 1.0, "Linux", ipv6=True)[0] == "ping"
    assert build_ping_command("::1", 3, 1.0, "Windows", ipv6=True)[0] == "ping"


def test_system_ping_picks_ping6_on_macos(monkeypatch):
    monkeypatch.setattr("netscope.ping.platform.system", lambda: "Darwin")
    runner = fake_runner((DATA / "ping_macos_ipv6.txt").read_bytes())
    result = system_ping("::1", count=3, runner=runner)
    assert runner.calls[0][0][0] == "ping6" and result.received == 3


# ---- duplicate replies

def test_duplicates_do_not_hide_loss():
    times, duplicates = parse_ping_replies((DATA / "ping_linux_dup.txt").read_text(encoding="utf-8"))
    assert times == [0.512] and duplicates == 2


def test_duplicates_through_ping(monkeypatch):
    monkeypatch.setattr("netscope.ping.platform.system", lambda: "Linux")
    runner = fake_runner((DATA / "ping_linux_dup.txt").read_bytes())
    result = ping("router.lan", count=3, method="icmp", runner=runner, resolver=local("192.168.1.1"))
    assert result.received == 1 and result.duplicates == 2
    assert round(result.loss_percent) == 67 and result.partial_loss
    assert result.to_dict()["duplicates"] == 2


# ---- tracert in other languages

@pytest.mark.parametrize("name", ["tracert_windows_de_cp850.bin", "tracert_windows_fr_cp850.bin"])
def test_windows_tracert_bytes(monkeypatch, name):
    windows_console(monkeypatch, 850)
    runner = fake_runner(fixture_bytes(name))
    result = trace("10.20.0.1", tool="tracert", runner=runner, resolver=local("10.20.0.1"))
    assert [h.number for h in result.hops] == [1, 2, 3]
    assert result.hops[0].times_ms == [0.5, 0.5, 0.5] and result.hops[0].address == "192.168.1.1"
    assert result.hops[1].address is None and result.hops[1].times_ms == []
    assert result.hops[2].address == "10.20.0.1"
    assert not result.no_replies


def test_tracert_ms_in_russian():
    hops = parse_trace_output("  1    <1 мс    <1 мс     2 мс  192.168.1.1\n")
    assert hops[0].times_ms == [0.5, 0.5, 2.0] and hops[0].address == "192.168.1.1"


# ---- macOS traceroute: several routers answering for one hop

def test_macos_continuation_lines_are_kept():
    hops = parse_trace_output((DATA / "traceroute_macos_multi.txt").read_text(encoding="utf-8"))
    assert [h.number for h in hops] == [1, 2, 3, 4]
    assert hops[1].address == "10.0.0.1" and hops[1].other_addresses == ["10.0.0.2"]
    assert hops[1].times_ms == [10.105, 11.21]
    assert hops[2].address == "10.30.0.1" and hops[2].other_addresses == ["10.30.0.2"]
    assert hops[0].other_addresses == [] and hops[0].to_dict()["other_addresses"] == []


def test_macos_traceroute6_for_ipv6():
    assert build_trace_command("traceroute", "::1", 10, 1.0, "Darwin")[0] == "traceroute6"
    assert build_trace_command("traceroute", "127.0.0.1", 10, 1.0, "Darwin")[0] == "traceroute"
    assert build_trace_command("traceroute", "::1", 10, 1.0, "Linux")[0] == "traceroute"
