"""Save results to a file: JSON for programs, HTML for people.

The format is picked from the file extension (``.json`` or ``.html``). The
HTML report is a single self-contained file (no internet needed to view it)
built with plain string formatting. Every value goes through
``html.escape`` first, so a strange server header can't inject HTML/JS into
the report - a small but real security habit.

Added in v0.1.0
"""
from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .output import to_json

_STYLE = """
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem auto;max-width:960px;color:#1f2937;padding:0 1rem}
h1{margin-bottom:.2rem}.meta{color:#6b7280;margin-top:0}
table{border-collapse:collapse;margin:.5rem 0 1.2rem;width:100%}
th,td{border:1px solid #e5e7eb;padding:.35rem .6rem;text-align:left;vertical-align:top;font-size:.92rem}
th{background:#f3f4f6}code{font-family:ui-monospace,Consolas,monospace}
.note{background:#fff7ed;border-left:4px solid #f97316;padding:.6rem .8rem}
footer{margin-top:2rem;color:#6b7280;font-size:.85rem}
"""


def check_report_path(path: str | Path, force: bool = False) -> Path:
    """Make sure a report can be saved at ``path`` BEFORE any work is done.

    - the name must end in .json or .html
    - the folder must already exist (we don't create folders: a typo in the
      path should be an error, not a surprise new folder)
    - an existing file is only replaced when ``force`` is True
    Raises ValueError explaining the problem.
    """
    path = Path(path)
    if path.suffix.lower() not in (".json", ".html", ".htm"):
        raise ValueError("report file must end in .json or .html")
    parent = path.parent if str(path.parent) else Path(".")
    if not parent.is_dir():
        raise ValueError(f"folder '{parent}' does not exist")
    if path.is_dir():
        raise ValueError(f"'{path}' is a folder")
    if path.exists() and not force:
        raise ValueError(f"'{path}' already exists (add --force to replace it)")
    return path


def save_report(path: str | Path, document: dict[str, Any], force: bool = False) -> Path:
    """Write ``document`` (an output envelope) as JSON or HTML, based on the extension."""
    path = check_report_path(path, force)
    if path.suffix.lower() == ".json":
        content = to_json(document) + "\n"
    else:
        content = render_html(document)
    # "x" mode refuses to replace a file, even one created a moment ago.
    with open(path, "w" if force else "x", encoding="utf-8") as handle:
        handle.write(content)
    return path


def _cell(value: Any) -> str:
    """Render one table cell; nested lists/dicts become compact text."""
    if value is None:
        return "-"
    if isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            return html.escape(", ".join(str(v) for v in value)) or "-"
        return _render(value)
    if isinstance(value, dict):
        return _render(value)
    return html.escape(str(value))


def _render(value: Any) -> str:
    """Render any JSON-like value: dicts become two-column tables, lists of dicts become tables."""
    if isinstance(value, dict):
        rows = "".join(f"<tr><th>{html.escape(str(k))}</th><td>{_cell(v)}</td></tr>"
                       for k, v in value.items())
        return f"<table>{rows}</table>"
    if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
        keys: list[str] = []
        for item in value:  # union of keys, in first-seen order
            keys.extend(k for k in item if k not in keys)
        head = "".join(f"<th>{html.escape(k)}</th>" for k in keys)
        body = "".join("<tr>" + "".join(f"<td>{_cell(item.get(k))}</td>" for k in keys) + "</tr>"
                       for item in value)
        return f"<table><tr>{head}</tr>{body}</table>"
    return _cell(value)


def render_html(document: dict[str, Any]) -> str:
    """Build the whole HTML page for a report."""
    from . import RESPONSIBLE_USE

    command = html.escape(str(document.get("command", "")))
    meta = (f"Generated {html.escape(str(document.get('generated_at', '')))} by NetScope "
            f"v{html.escape(str(document.get('version', '')))} "
            f"(schema {html.escape(str(document.get('schema_version', '')))})")
    return (
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        # Content-Security-Policy: the page may not load or run anything at all
        # (no scripts, images or network requests) - only its own inline styles.
        "<meta http-equiv=\"Content-Security-Policy\" "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>NetScope report - {command}</title><style>{_STYLE}</style></head><body>"
        f"<h1>NetScope report: <code>{command}</code></h1><p class=\"meta\">{meta}</p>"
        f"{_render(document.get('data'))}"
        f"<p class=\"note\">{html.escape(RESPONSIBLE_USE)}</p>"
        "<footer>Made by NiyiSoft</footer></body></html>\n"
    )
