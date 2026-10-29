"""Turn results into something people (tables) or programs (JSON) can read.

- ``format_table`` lines up columns using plain ASCII, so it looks right in
  any terminal, including the classic Windows console.
- ``envelope`` wraps every JSON result in the same outer shape, with a
  ``schema_version``, so scripts that read our JSON can tell when the format
  changes.
- Colour is optional: it's skipped when output goes to a file/pipe or when
  the NO_COLOR environment variable is set (https://no-color.org).

Added in v0.1.0
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Optional, Sequence, TextIO

from . import __version__

# Bump the major number if a field is removed or renamed; the minor number for new fields.
SCHEMA_VERSION = "1.0"

# Matches ANSI colour codes such as "\033[32m", so we can measure the visible width of text.
_ANSI = re.compile(r"\033\[[0-9;]*m")

_COLORS = {"green": "32", "red": "31", "yellow": "33", "cyan": "36", "bold": "1", "dim": "2"}


def use_color(stream: TextIO = sys.stdout) -> bool:
    """Colour only for a real terminal, and never when NO_COLOR is set."""
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def paint(text: str, color: str, enabled: bool) -> str:
    """Wrap ``text`` in an ANSI colour code when colour is enabled."""
    if not enabled or color not in _COLORS:
        return text
    return f"\033[{_COLORS[color]}m{text}\033[0m"


def fmt_ms(value: Optional[float]) -> str:
    """Show milliseconds nicely: "-" when there's no value, "<1 ms" below one millisecond.

    Showing 0.2 ms as "0.2 ms" suggests more precision than a busy computer's
    timer really gives, and Windows itself only reports "<1ms".
    """
    if value is None:
        return "-"
    if value < 1:
        return "<1 ms"
    return f"{value:.1f} ms"


def visible_len(text: str) -> int:
    """Length of ``text`` as it appears on screen, ignoring colour codes."""
    return len(_ANSI.sub("", text))


def pad(text: str, width: int) -> str:
    """Like ``str.ljust`` but colour codes don't count towards the width."""
    return text + " " * max(0, width - visible_len(text))


def format_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Return a plain-text table with columns padded to the widest value.

    Example::

        PORT  STATE  SERVICE
        ----  -----  -------
        22    open   ssh
    """
    text_rows = [["-" if c is None else str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in text_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], visible_len(cell))
    lines = ["  ".join(pad(h, w) for h, w in zip(headers, widths)).rstrip(),
             "  ".join("-" * w for w in widths)]
    for row in text_rows:
        lines.append("  ".join(pad(c, w) for c, w in zip(row, widths)).rstrip())
    return "\n".join(lines)


def format_pairs(pairs: Sequence[tuple[str, Any]]) -> str:
    """Key/value lines, aligned on the colon: ``Host name : my-laptop``."""
    width = max((len(k) for k, _ in pairs), default=0)
    return "\n".join(f"{k.ljust(width)} : {'-' if v is None else v}" for k, v in pairs)


def envelope(command: str, data: Any, now: Optional[datetime] = None) -> dict[str, Any]:
    """The standard outer wrapper for all JSON output and saved reports."""
    now = now or datetime.now(timezone.utc)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "netscope",
        "version": __version__,
        "command": command,
        "generated_at": now.isoformat(timespec="seconds"),
        "data": data,
    }


def to_json(document: dict[str, Any], ascii_only: bool = False) -> str:
    """JSON text. ``ascii_only`` writes "é" as "\\u00e9", which survives any encoding."""
    return json.dumps(document, indent=2, ensure_ascii=ascii_only)
