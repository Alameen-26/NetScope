"""Running the system's own tools (ping, tracert, traceroute) and reading their output.

The tricky part is the text encoding. On Windows, console programs such as
``ping.exe`` and ``tracert.exe`` write in the console's "OEM code page"
(cp850 in Western Europe, cp437 in the US, cp866 in Russia...), *not* the
cp1252 "ANSI" code page Python would guess. German "für" written in cp850 is
the byte 0x81, which doesn't exist in cp1252, so decoding with
``text=True`` crashes with UnicodeDecodeError.

So we capture raw bytes and decode them ourselves, with the console's own code
page, and ``errors="replace"`` so one odd byte can never crash the program
(it becomes "?" - harmless, since we only need the numbers).

Added in v0.1.0
"""
from __future__ import annotations

import codecs
import locale
import platform
import subprocess
from typing import Callable, Optional


def _windows_console_cp() -> int:
    """Ask Windows which code page the console uses (0 if there's no console)."""
    import ctypes
    windll = getattr(ctypes, "windll")  # only exists on Windows (AttributeError elsewhere)
    return int(windll.kernel32.GetConsoleOutputCP())


def _codec_exists(name: str) -> bool:
    try:
        codecs.lookup(name)
        return True
    except LookupError:
        return False


def console_encoding(system: Optional[str] = None,
                     get_console_cp: Callable[[], int] = _windows_console_cp) -> str:
    """The encoding the system's console tools write their output in.

    Windows: the console output code page (e.g. "cp850"). If there's no
    console attached (0) or the call fails, fall back to Python's "oem" codec
    (Windows-only, means "the system OEM code page"), then the locale's.
    Other systems: the locale's encoding (almost always UTF-8).
    """
    system = system or platform.system()
    if system == "Windows":
        try:
            page = get_console_cp()
        except (OSError, AttributeError, ImportError):
            page = 0
        if page and _codec_exists(f"cp{page}"):
            return f"cp{page}"
        if _codec_exists("oem"):
            return "oem"
    return locale.getpreferredencoding(False) or "utf-8"


def decode_output(data: bytes | str | None, encoding: str) -> str:
    """Bytes -> text, never raising: bytes that don't fit become "?"."""
    if data is None:
        return ""
    if isinstance(data, str):  # already text (some test doubles return str)
        return data
    return data.decode(encoding, errors="replace")


def run_tool(cmd: list[str], timeout: float,
             runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
             encoding: Optional[str] = None) -> tuple[str, str, int]:
    """Run ``cmd`` and return (stdout, stderr, exit code) as text.

    Exceptions from ``runner`` (FileNotFoundError, TimeoutExpired...) are
    left to the caller, which knows what they mean for its tool.
    """
    proc = runner(cmd, capture_output=True, timeout=timeout)  # bytes: no text=True on purpose
    encoding = encoding or console_encoding()
    return (decode_output(proc.stdout, encoding), decode_output(proc.stderr, encoding),
            proc.returncode)
