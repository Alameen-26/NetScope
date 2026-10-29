"""Tests for table/JSON output and saved reports."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from netscope import __version__
from netscope.output import (SCHEMA_VERSION, envelope, fmt_ms, format_pairs, format_table,
                             paint, use_color)
from netscope.report import render_html, save_report


def test_format_table_aligns_columns():
    text = format_table(["PORT", "STATE"], [[22, "open"], [8080, None]])
    lines = text.splitlines()
    assert lines[0] == "PORT  STATE"
    assert lines[1] == "----  -----"
    assert lines[2] == "22    open"
    assert lines[3] == "8080  -"


def test_format_pairs():
    assert format_pairs([("A", 1), ("Long", None)]) == "A    : 1\nLong : -"


def test_fmt_ms():
    assert fmt_ms(None) == "-" and fmt_ms(1.234) == "1.2 ms"


def test_envelope_has_schema_version():
    doc = envelope("scan", {"x": 1}, now=datetime(2026, 10, 29, tzinfo=timezone.utc))
    assert doc["schema_version"] == SCHEMA_VERSION
    assert doc["tool"] == "netscope" and doc["version"] == __version__
    assert doc["generated_at"] == "2026-10-29T00:00:00+00:00"


def test_paint_and_no_color(monkeypatch):
    assert paint("x", "green", False) == "x"
    assert paint("x", "green", True) == "\033[32mx\033[0m"

    class Tty:
        def isatty(self):
            return True
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert use_color(Tty())
    monkeypatch.setenv("NO_COLOR", "1")
    assert not use_color(Tty())


def test_save_json_report(tmp_path):
    doc = envelope("dns", {"name": "example.com"})
    path = save_report(tmp_path / "r.json", doc)
    assert json.loads(path.read_text(encoding="utf-8"))["data"]["name"] == "example.com"


def test_save_html_report_escapes_values(tmp_path):
    doc = envelope("http", {"headers": {"x-test": "<script>alert(1)</script>"},
                            "ports": [{"port": 22, "state": "open"}]})
    path = save_report(tmp_path / "r.html", doc)
    html_text = path.read_text(encoding="utf-8")
    assert "<script>alert" not in html_text and "&lt;script&gt;" in html_text
    assert "<th>port</th>" in html_text and "Made by NiyiSoft" in html_text
    assert "permission" in html_text  # responsible-use note


def test_html_handles_lists_and_empty_values():
    html_text = render_html(envelope("x", {"list": [1, 2], "empty": [], "none": None}))
    assert "1, 2" in html_text and "<td>-</td>" in html_text


def test_save_report_rejects_unknown_extension(tmp_path):
    with pytest.raises(ValueError):
        save_report(tmp_path / "r.txt", envelope("x", {}))


def test_table_ignores_colour_codes_when_aligning():
    from netscope.output import format_table, paint
    plain = format_table(["STATE", "X"], [["open", "a"]])
    coloured = format_table(["STATE", "X"], [[paint("open", "green", True), "a"]])
    import re
    assert re.sub(r"\033\[[0-9;]*m", "", coloured) == plain
