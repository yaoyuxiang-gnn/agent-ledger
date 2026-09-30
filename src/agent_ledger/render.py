"""Terminal rendering with no dependencies.

The demo is the front door of this project, so it has to look like somebody
cared. Pulling in ``rich`` would have been easier and would have cost the
zero-dependency property that makes ``uvx`` installs instant. A little ANSI is
a better trade.

Two portability problems are handled here rather than at every call site:

* Windows consoles frequently default to a legacy code page (GBK, CP1252), so
  a stray ``✓`` raises ``UnicodeEncodeError`` and kills the process. We try to
  reconfigure the streams to UTF-8 and fall back to ASCII glyphs if we cannot.
* ``NO_COLOR`` (https://no-color.org) must be honoured, because escape codes
  in a CI log make the output unreadable.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterable, Sequence

__all__ = [
    "BLUE",
    "BOLD",
    "CYAN",
    "DIM",
    "GREEN",
    "MAGENTA",
    "RED",
    "RESET",
    "YELLOW",
    "bar",
    "bullet",
    "g",
    "header",
    "kv",
    "rule",
    "supports_color",
    "supports_unicode",
    "tree",
    "width",
]

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"


# --------------------------------------------------------------------------- #
# Capability detection
# --------------------------------------------------------------------------- #


def _ensure_utf8_streams() -> None:
    """Best-effort switch of stdout/stderr to UTF-8.

    On Windows this is what turns a crash into correct output. Failure is fine:
    :func:`supports_unicode` will notice and the ASCII glyph table takes over.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError, AttributeError):
            continue


_ensure_utf8_streams()

_COLOR_ENABLED: bool | None = None
_UNICODE_ENABLED: bool | None = None

_PROBE = "✓─▎█·→▲▼"


def supports_color() -> bool:
    global _COLOR_ENABLED
    if _COLOR_ENABLED is None:
        if os.environ.get("NO_COLOR"):
            _COLOR_ENABLED = False
        elif os.environ.get("FORCE_COLOR"):
            _COLOR_ENABLED = True
        else:
            _COLOR_ENABLED = bool(getattr(sys.stdout, "isatty", lambda: False)())
    return _COLOR_ENABLED


def supports_unicode() -> bool:
    global _UNICODE_ENABLED
    if _UNICODE_ENABLED is None:
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        try:
            _PROBE.encode(encoding)
            _UNICODE_ENABLED = True
        except (UnicodeEncodeError, LookupError):
            _UNICODE_ENABLED = False
    return _UNICODE_ENABLED


_GLYPHS: dict[str, tuple[str, str]] = {
    # name: (unicode, ascii)
    "check": ("✓", "+"),
    "cross": ("✗", "x"),
    "bar": ("▎", "|"),
    "hbar": ("─", "-"),
    "block": ("█", "#"),
    "dot": ("·", "."),
    "arrow": ("→", "->"),
    "up": ("▲", "^"),
    "down": ("▼", "v"),
    "flat": ("─", "-"),
    "ge": ("≥", ">="),
    "le": ("≤", "<="),
    "bullet": ("•", "*"),
    "connector": ("└─", "\\-"),
    "ellipsis": ("…", "..."),
}


def g(name: str) -> str:
    """Return a glyph, ASCII-folded when the output stream cannot encode it."""
    unicode_form, ascii_form = _GLYPHS.get(name, ("?", "?"))
    return unicode_form if supports_unicode() else ascii_form


def c(text: str, *codes: str) -> str:
    """Wrap *text* in ANSI *codes*, or return it plainly when colour is off."""
    if not codes or not supports_color():
        return text
    return "".join(codes) + text + RESET


# --------------------------------------------------------------------------- #
# Layout
# --------------------------------------------------------------------------- #


def width(default: int = 78) -> int:
    try:
        return max(40, min(shutil.get_terminal_size().columns, 100))
    except OSError:  # pragma: no cover - unusual tty
        return default


def rule(title: str = "") -> str:
    """A horizontal rule, optionally captioned."""
    total = width()
    dash = g("hbar")
    if not title:
        return c(dash * total, DIM)
    label = f" {title} "
    left = 3
    right = max(0, total - left - len(label))
    return c(dash * left, DIM) + c(label, BOLD) + c(dash * right, DIM)


def header(index: int, title: str) -> str:
    """Numbered step heading used by the demo narrative."""
    return "\n" + c(f"{g('bar')}{index}. ", CYAN, BOLD) + c(title, BOLD)


def kv(key: str, value: str, *, key_width: int = 18, indent: int = 2) -> str:
    return " " * indent + c(key.ljust(key_width), DIM) + value


def bar(value: float, *, span: int = 18) -> str:
    """Render a ``[0, 1]`` score as a small inline meter."""
    filled = max(0, min(span, round(value * span)))
    return c(g("block") * filled, CYAN) + c(g("dot") * (span - filled), DIM)


def tree(lines: Sequence[tuple[int, str]], *, connector: str | None = None) -> str:
    """Indent ``(depth, text)`` pairs into something that reads as a chain."""
    connector = connector or g("connector")
    out: list[str] = []
    for depth, text in lines:
        if depth == 0:
            out.append(text)
        else:
            out.append("   " * depth + c(connector + " ", DIM) + text)
    return "\n".join(out)


def bullet(items: Iterable[str], *, marker: str | None = None, indent: int = 2) -> str:
    marker = marker or g("bullet")
    return "\n".join(" " * indent + c(marker, DIM) + " " + item for item in items)
