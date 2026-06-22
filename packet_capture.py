#!/usr/bin/env python3
"""Backward-compatible launcher. Prefer: ``python -m meshcore_packet_capture``."""

from __future__ import annotations

import sys
from pathlib import Path

# Running from a git checkout without ``pip install -e .``
_src = Path(__file__).resolve().parent / "src"
if _src.is_dir():
    sys.path.insert(0, str(_src))

from meshcore_packet_capture.__main__ import cli

if __name__ == "__main__":
    cli()
