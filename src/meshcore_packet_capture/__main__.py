"""CLI entry: ``python -m meshcore_packet_capture``."""

from __future__ import annotations

import asyncio

from .packet_capture import main


def cli() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    cli()
