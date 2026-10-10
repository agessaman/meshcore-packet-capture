"""Render a user service without reading configuration or changing the filesystem."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _escape(value: str) -> str:
    if any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value):
        raise ValueError('systemd unit values cannot contain control characters')
    return value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')


def _quote(value: str, *, exec_arg: bool = False) -> str:
    escaped = _escape(value)
    # ExecStart expands environment variables even inside quotes.
    if exec_arg:
        escaped = escaped.replace('$', '$$')
    return f'"{escaped}"'


def _absolute(value: str) -> str:
    _escape(value)
    # Preserve the venv executable path; resolving its symlink loses the venv.
    return os.path.abspath(os.path.expanduser(value))


def render_user_unit(args: argparse.Namespace) -> str:
    command = [sys.executable, '-m', 'meshcore_packet_capture', '--user-config']
    command[0] = _absolute(command[0])
    for path in args.config_files or []:
        command.extend(['--config', _absolute(path)])
    if args.output is not None:
        command.extend(['--output', _absolute(args.output)])
    for option in ('verbose', 'debug', 'no_mqtt', 'neighbors_now', 'neighbors_exit'):
        if getattr(args, option):
            command.append('--' + option.replace('_', '-'))

    environment = []
    checkout = None
    for variable in ('MESHCORE_PACKETCAPTURE_ENV_DIR', 'PACKETCAPTURE_CONFIG_DIR', 'XDG_CONFIG_HOME'):
        value = os.environ.get(variable, '')
        _escape(value)
        if not value.strip():
            continue
        # Config discovery ignores relative XDG_CONFIG_HOME values.
        if variable == 'XDG_CONFIG_HOME' and not os.path.isabs(value):
            continue
        if variable == 'MESHCORE_PACKETCAPTURE_ENV_DIR':
            value = value.strip()
        value = _absolute(value)
        environment.append(f'Environment={_quote(variable + "=" + value)}')
        if variable == 'MESHCORE_PACKETCAPTURE_ENV_DIR':
            checkout = value

    data_dir = os.environ.get('PACKETCAPTURE_DATA_DIR', '')
    _escape(data_dir)
    data_dir = data_dir.strip()
    if not data_dir:
        state_home = os.environ.get('XDG_STATE_HOME', '')
        _escape(state_home)
        if not os.path.isabs(state_home):
            state_home = str(Path.home() / '.local' / 'state')
        data_dir = os.path.join(state_home, 'meshcore-packet-capture')
    environment.append(f'Environment={_quote("PACKETCAPTURE_DATA_DIR=" + _absolute(data_dir))}')

    working_directory = _quote(checkout) if checkout else '%h'
    exec_start = 'env ' + ' '.join(_quote(arg, exec_arg=True) for arg in command)
    return '\n'.join([
        '[Unit]',
        'Description=MeshCore Packet Capture (user)',
        'After=network-online.target bluetooth.target',
        'Wants=network-online.target',
        '',
        '[Service]',
        'Type=exec',
        f'WorkingDirectory={working_directory}',
        *environment,
        f'ExecStart={exec_start}',
        'Environment=PATH=/usr/local/bin:/usr/bin:/bin',
        'Restart=always',
        'RestartSec=10',
        'NoNewPrivileges=true',
        'PrivateTmp=true',
        '',
        '[Install]',
        'WantedBy=default.target',
        '',
    ])
