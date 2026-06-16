"""Output formatting, TTY prompts, and colors."""
from __future__ import annotations

import os
import sys

# ANSI color codes — disabled when stdout is not a TTY
_USE_COLOR: bool = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

RED: str = "\033[0;31m" if _USE_COLOR else ""
GREEN: str = "\033[0;32m" if _USE_COLOR else ""
YELLOW: str = "\033[1;33m" if _USE_COLOR else ""
BLUE: str = "\033[0;34m" if _USE_COLOR else ""
NC: str = "\033[0m" if _USE_COLOR else ""


def print_header(msg: str) -> None:
    print(f"\n{BLUE}{'=' * 51}{NC}")
    print(f"{BLUE}  {msg}{NC}")
    print(f"{BLUE}{'=' * 51}{NC}\n")


def print_success(msg: str) -> None:
    print(f"{GREEN}\u2713{NC} {msg}")


def print_error(msg: str) -> None:
    print(f"{RED}\u2717{NC} {msg}", file=sys.stderr)


def print_warning(msg: str) -> None:
    print(f"{YELLOW}\u26a0{NC} {msg}")


def print_info(msg: str) -> None:
    print(f"{BLUE}\u2139{NC} {msg}")


# ---------------------------------------------------------------------------
# TTY input helpers — open /dev/tty so prompts work when stdin is piped
# (curl | bash scenario). Falls back to sys.stdin if /dev/tty is unavailable.
# ---------------------------------------------------------------------------

_NONINTERACTIVE_WARNED: bool = False


def _interactive_input_stream():
    """Return an interactive input stream, or None when none is available.

    Prefers /dev/tty (works even when stdin is a pipe, e.g. curl | bash). Falls
    back to stdin only when it is itself a TTY — never to a piped/closed stdin,
    which would otherwise hang or spin on EOF.
    """
    try:
        return open("/dev/tty", "r")
    except OSError:
        if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
            return sys.stdin
        return None


def _tty_input(prompt_text: str, default: str = "") -> str:
    """Read a line from an interactive stream.

    When no interactive stream is available (no TTY and stdin is piped/closed),
    return ``default`` with a one-time warning instead of blocking, so
    unattended runs proceed with documented defaults.
    """
    global _NONINTERACTIVE_WARNED
    stream = _interactive_input_stream()
    if stream is None:
        if not _NONINTERACTIVE_WARNED:
            print_warning("No interactive terminal detected — using default answers for prompts.")
            _NONINTERACTIVE_WARNED = True
        return default

    try:
        sys.stderr.write(prompt_text)
        sys.stderr.flush()
        line = stream.readline()
        if line == "":  # EOF
            return default
        return line.rstrip("\n")
    finally:
        if stream is not sys.stdin:
            stream.close()


def prompt_yes_no(prompt: str, default: str = "n") -> bool:
    """Prompt for y/n confirmation. Returns True for yes."""
    suffix = " [Y/n]: " if default == "y" else " [y/N]: "
    response = _tty_input(prompt + suffix, default).strip()
    if not response:
        response = default
    return response.lower() in ("y", "yes")


def prompt_input(prompt: str, default: str = "") -> str:
    """Prompt for a text value with optional default."""
    if default:
        text = f"{prompt} [{default}]: "
    else:
        text = f"{prompt}: "
    response = _tty_input(text, default).strip()
    return response if response else default
