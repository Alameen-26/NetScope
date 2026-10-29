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

_STYLE = r"""
/* NetScope report theme: light + dark, following the system setting.
   Inline only: the report CSP is default-src 'none'; style-src 'unsafe-inline',
   so no images, web fonts, url() or scripts. Print always uses the light theme.
   Added in v0.2.0. Made by NiyiSoft. */
:root{color-scheme:light dark;
--bg:#F4F4F2;--surface:#FFFFFF;--text:#111315;--muted:#5A5F66;--border:#D9DBDE;--border-soft:#E8E9EB;
--head:#ECEDEF;--zebra:#F8F8F7;--key:#3A3F45;--red:#B3122B;--red-tint:#FBE9EC;--green:#0B6B3A;
--gold:#8A6A10;--gold-tint:#FBF5E3;--band:#111315;--band-text:#F4F4F2;--band-muted:#A2A8AE;--scope:#E5384F;--crown:#D4A72C;
--mono:ui-monospace,"JetBrains Mono","Cascadia Mono","Cascadia Code",Consolas,"SFMono-Regular",Menlo,monospace;
--sans:"Segoe UI Variable Text","Segoe UI",Inter,system-ui,-apple-system,Roboto,Arial,sans-serif}
@media (prefers-color-scheme:dark){:root{
--bg:#0A0B0C;--surface:#131517;--text:#ECEEF0;--muted:#A2A8AE;--border:#2A2E33;--border-soft:#22262A;
--head:#1A1D21;--zebra:#16181B;--key:#C5CAD0;--red:#FF5A6E;--red-tint:#2B1418;--green:#3FC27A;
--gold:#E0B43C;--gold-tint:#221D0E;--band:#000000;--band-text:#ECEEF0;--band-muted:#8E959C;--scope:#FF4D63;--crown:#E0B43C}}
@media print{:root{color-scheme:light;
--bg:#FFFFFF;--surface:#FFFFFF;--text:#111315;--muted:#5A5F66;--border:#C9CCD0;--border-soft:#E0E2E4;--head:#ECEDEF;--zebra:#FFFFFF;--key:#3A3F45;
--red:#B3122B;--red-tint:#FFFFFF;--green:#0B6B3A;--gold:#8A6A10;--gold-tint:#FFFFFF;--band:#111315;--band-text:#FFFFFF;--band-muted:#C9CCD0;--scope:#E5384F;--crown:#8A6A10}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
html{background:var(--bg)}
body{font-family:var(--sans);font-size:15px;line-height:1.5;margin:0 auto;max-width:1120px;padding:1.5rem 1.25rem 2.5rem;color:var(--text);background:var(--bg)}
/* brand band with the scope reticle (pure CSS gradients) */
body::before{content:"NETSCOPE \00B7  NETWORK REPORT";display:block;white-space:pre;margin:0 0 1.6rem;padding:1.05rem 1.2rem 1.05rem 4.4rem;border-radius:10px;
background-color:var(--band);color:var(--band-text);font:700 .8rem/1.2 var(--mono);letter-spacing:.22em;
box-shadow:inset 0 -3px 0 var(--scope);
background-image:
 radial-gradient(circle at 2.1rem 50%,var(--scope) 0 3px,transparent 3.6px),
 radial-gradient(circle at 2.1rem 50%,transparent 0 10px,var(--scope) 10.6px 12.2px,transparent 12.8px),
 radial-gradient(circle at 2.1rem 50%,transparent 0 17px,var(--band-muted) 17.5px 18.3px,transparent 18.9px),
 linear-gradient(var(--band-muted),var(--band-muted)),linear-gradient(var(--band-muted),var(--band-muted));
background-repeat:no-repeat;
background-size:auto,auto,auto,1px 42px,42px 1px;
background-position:0 0,0 0,0 0,calc(2.1rem - .5px) 50%,calc(2.1rem - 21px) 50%}
h1{font:700 1.75rem/1.2 var(--sans);letter-spacing:-.015em;margin:0 0 .35rem}
h1 code{font:700 .82em/1 var(--mono);color:var(--red);background:var(--red-tint);border:1px solid var(--red);border-radius:6px;padding:.12em .42em;margin-left:.15em;vertical-align:.06em}
code{font-family:var(--mono)}
.meta{font:500 .8rem/1.4 var(--mono);color:var(--muted);margin:0 0 1.5rem;padding-bottom:1rem;border-bottom:1px solid var(--border)}
.meta::before{content:"";display:inline-block;width:.5rem;height:.5rem;border-radius:50%;background:var(--green);margin-right:.55rem;vertical-align:.05em;box-shadow:0 0 0 3px color-mix(in srgb,var(--green) 22%,transparent)}
/* tables: the top-level table scrolls sideways when wide, nested ones sit flat */
table{border-collapse:separate;border-spacing:0;width:100%;margin:.4rem 0 1.4rem;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}
body>table,td>table{display:block;overflow-x:auto;max-width:100%}
body>table>tbody,td>table>tbody{display:table;width:100%;border-collapse:separate;border-spacing:0}
th,td{padding:.5rem .75rem;text-align:left;vertical-align:top;font-size:.9rem;border:0;border-bottom:1px solid var(--border-soft)}
tr:last-child>th,tr:last-child>td{border-bottom:0}
td{font-family:var(--mono);font-size:.84rem;color:var(--text);overflow-wrap:break-word}
/* key column of key/value tables */
tr>th:first-child:not(:last-child):has(+td){width:1%;white-space:nowrap;font:600 .78rem/1.5 var(--mono);color:var(--key);background:var(--head);border-right:1px solid var(--border-soft);padding-top:.58rem}
/* header row of list tables */
th:has(+th),th+th{font:700 .74rem/1.4 var(--mono);letter-spacing:.01em;color:var(--muted);background:var(--head);border-bottom:2px solid var(--red);white-space:nowrap;padding:.5rem .55rem}
tr:has(>th+th)~tr>td{padding:.5rem .55rem}
tr:has(>th+th)~tr:nth-child(odd)>td{background:var(--zebra)}
td table{margin:0;border-radius:8px;font-size:.95em}
td:has(>table){padding:.4rem}
.note{position:relative;margin:1.8rem 0 0;padding:.8rem 1rem .8rem 1.1rem;background:var(--gold-tint);border:1px solid color-mix(in srgb,var(--gold) 40%,transparent);border-left:4px solid var(--gold);border-radius:8px;color:var(--text);font-size:.9rem}
.note::before{content:"RESPONSIBLE USE";display:block;font:700 .68rem/1.4 var(--mono);letter-spacing:.14em;color:var(--gold);margin-bottom:.2rem}
footer{margin-top:2.2rem;padding-top:1rem;border-top:1px solid var(--border);text-align:right;color:var(--text);font:400 1.35rem/1.2 "Segoe Script","Great Vibes","Brush Script MT","Lucida Handwriting",cursive}
footer::before{content:"\265B";color:var(--crown);font:1rem/1 var(--sans);margin-right:.45rem;vertical-align:.2em}
@media (max-width:640px){body{padding:1rem .75rem 2rem}
tr:has(>th:first-child+td:last-child)>th,tr:has(>th:first-child+td:last-child)>td{display:block;width:auto}
tr:has(>th:first-child+td:last-child)>th{border-right:0;border-bottom:0;padding-bottom:.2rem}
h1{font-size:1.35rem}body::before{letter-spacing:.14em}}
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
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
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
