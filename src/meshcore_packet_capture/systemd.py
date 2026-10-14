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


def _quote(value: str) -> str:
    return f'"{_escape(value)}"'


def unescape_working_directory(value: str) -> str:
    """Inverse of the unquoted WorkingDirectory encoding."""
    out = []
    index = 0
    while index < len(value):
        if value.startswith('\\\\', index):
            out.append('\\')
            index += 2
        elif value.startswith('\\"', index):
            out.append('"')
            index += 2
        elif value.startswith('%%', index):
            out.append('%')
            index += 2
        else:
            out.append(value[index])
            index += 1
    return ''.join(out)


def _absolute(value: str) -> str:
    _escape(value)
    # Preserve the venv executable path; resolving its symlink loses the venv.
    return os.path.abspath(os.path.expanduser(value))


def render_user_unit(args: argparse.Namespace) -> str:
    if args.neighbors_now or args.neighbors_exit:
        raise ValueError('--neighbors-now and --neighbors-exit are manual actions; '
                         'they cannot be saved in a restarting service')
    command = [sys.executable, '-m', 'meshcore_packet_capture', '--user-config']
    command[0] = _absolute(command[0])
    for path in args.config_files or []:
        command.extend(['--config', _absolute(path)])
    if args.output is not None:
        command.extend(['--output', _absolute(args.output)])
    for option in ('verbose', 'debug', 'no_mqtt', 'no_env_files'):
        if getattr(args, option, False):
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

    if not checkout and '--no-env-files' not in command:
        command.append('--no-env-files')

    data_dir = os.environ.get('PACKETCAPTURE_DATA_DIR', '')
    _escape(data_dir)
    data_dir = data_dir.strip()
    if data_dir:
        environment.append(f'Environment={_quote("PACKETCAPTURE_DATA_DIR=" + _absolute(data_dir))}')
    elif not checkout:
        state_home = os.environ.get('XDG_STATE_HOME', '')
        _escape(state_home)
        if not os.path.isabs(state_home):
            state_home = str(Path.home() / '.local' / 'state')
        data_dir = os.path.join(state_home, 'meshcore-packet-capture')
        environment.append(f'Environment={_quote("PACKETCAPTURE_DEFAULT_DATA_DIR=" + _absolute(data_dir))}')

    # A quoted WorkingDirectory fails systemd's absolute-path check. The value
    # is one path, so spaces stay literal; %, ", and \ are escaped in place.
    working_directory = _escape(checkout) if checkout else '%h'
    # systemd rejects quotes, backslashes, and '=' in the executable path.
    # The interpreter is an argument of /usr/bin/env. The ':' prefix disables
    # environment substitution, so a literal '$' in a path is preserved.
    exec_start = ':/usr/bin/env ' + ' '.join(_quote(arg) for arg in command)
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
        # Home stays visible so config, the interpreter, and first-save state
        # creation keep working. PrivateDevices would hide serial nodes.
        'UMask=0077',
        'NoNewPrivileges=true',
        'PrivateTmp=true',
        'ProtectKernelTunables=true',
        'ProtectKernelModules=true',
        'ProtectKernelLogs=true',
        'ProtectControlGroups=true',
        'ProtectClock=true',
        'ProtectHostname=true',
        'RestrictSUIDSGID=true',
        'LockPersonality=true',
        'RestrictRealtime=true',
        'RemoveIPC=true',
        'CapabilityBoundingSet=',
        'SystemCallArchitectures=native',
        '',
        '[Install]',
        'WantedBy=default.target',
        '',
    ])
