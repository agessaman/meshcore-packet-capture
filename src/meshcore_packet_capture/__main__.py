"""CLI entry: ``python -m meshcore_packet_capture``."""

from __future__ import annotations

import asyncio

from .cli import parse_args


def cli() -> None:
    args = parse_args()
    if args is None:
        return
    from .packet_capture import main

    asyncio.run(main(args))


if __name__ == "__main__":
    cli()
