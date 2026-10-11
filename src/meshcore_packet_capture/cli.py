"""Argument parsing shared by the console script and compatibility entry points."""

from __future__ import annotations

import argparse

from .systemd import render_user_unit


def parse_args() -> argparse.Namespace | None:
    parser = argparse.ArgumentParser(description='MeshCore Packet Capture Script')
    parser.add_argument('--output', help='Output file path (optional)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output (shows JSON packet data)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output (shows all detailed debugging info)')
    parser.add_argument('--no-mqtt', action='store_true', help='Disable MQTT publishing')
    parser.add_argument('--no-env-files', action='store_true',
                        help='Skip legacy .env and .env.local loading (default for generated services without a checkout).')
    parser.add_argument(
        '--neighbors-now', action='store_true',
        help='Run one neighbors discovery + scopes cycle immediately, ignoring the '
             'schedule (the equivalent of the firmware\'s "discover.neighbors"). '
             'Combine with --neighbors-exit to run just that and quit.',
    )
    parser.add_argument(
        '--neighbors-exit', action='store_true',
        help='With --neighbors-now, exit once the cycle finishes instead of continuing to capture.',
    )
    parser.add_argument(
        '--config', action='append', dest='config_files', metavar='PATH',
        help='TOML config file (repeatable). If set, only these files are loaded, not /etc defaults.',
    )
    parser.add_argument(
        '--user-config', action='store_true',
        help='Select checkout-local TOML using MESHCORE_PACKETCAPTURE_ENV_DIR, '
             'or overlay /etc config with XDG user config. --config and '
             'PACKETCAPTURE_CONFIG_DIR take precedence.',
    )
    parser.add_argument(
        '--print-systemd-unit', action='store_true',
        help='Print a systemd unit for this Python environment and exit (requires --user).',
    )
    parser.add_argument(
        '--user', action='store_true',
        help='Generate a user service with --print-systemd-unit.',
    )
    args = parser.parse_args()
    if args.user and not args.print_systemd_unit:
        parser.error('--user requires --print-systemd-unit; use --user-config for capture')
    if args.print_systemd_unit:
        if not args.user:
            parser.error('system unit generation is not supported; use --print-systemd-unit --user '
                         'or the managed installer for a system service')
        try:
            unit = render_user_unit(args)
        except ValueError as exc:
            parser.error(str(exc))
        print(unit, end='')
        return None
    return args
