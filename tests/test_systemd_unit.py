"""User-unit generation, including an install containing only the built wheel."""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
import venv

import pytest

from meshcore_packet_capture.systemd import render_user_unit


ROOT = Path(__file__).resolve().parents[1]


def _args(**kwargs):
    values = dict(config_files=None, output=None, verbose=False, debug=False,
                  no_mqtt=False, neighbors_now=False, neighbors_exit=False)
    return argparse.Namespace(**(values | kwargs))


def _environment(unit):
    result = {}
    for line in unit.splitlines():
        if line.startswith('Environment='):
            key, value = shlex.split(line.partition('=')[2])[0].split('=', 1)
            result[key] = value.replace('%%', '%')
    return result


def _command(unit):
    line = next(line for line in unit.splitlines() if line.startswith('ExecStart='))
    assert line.startswith('ExecStart=:')
    return [arg.replace('%%', '%') for arg in shlex.split(line.partition('=')[2][1:])]


def test_preserves_paths_and_capture_options(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    special = 'with spaces %n $HOME "quote" back\\slash'
    python = tmp_path / special / 'bin/python'
    monkeypatch.setattr(sys, 'executable', str(python))
    monkeypatch.setenv('PACKETCAPTURE_CONFIG_DIR', special)
    monkeypatch.setenv('MESHCORE_PACKETCAPTURE_ENV_DIR', 'checkout')
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / special))
    monkeypatch.setenv('PACKETCAPTURE_DATA_DIR', 'state')
    unit = render_user_unit(_args(config_files=[special, 'second.toml'], output='out.json',
                                  verbose=True, debug=True, no_mqtt=True))
    assert _command(unit) == [str(python), '-m', 'meshcore_packet_capture', '--user-config',
                              '--config', str(tmp_path / special), '--config', str(tmp_path / 'second.toml'),
                              '--output', str(tmp_path / 'out.json'), '--verbose', '--debug', '--no-mqtt']
    assert _environment(unit) == {
        'MESHCORE_PACKETCAPTURE_ENV_DIR': str(tmp_path / 'checkout'),
        'PACKETCAPTURE_CONFIG_DIR': str(tmp_path / special),
        'XDG_CONFIG_HOME': str(tmp_path / special),
        'PACKETCAPTURE_DATA_DIR': str(tmp_path / 'state'),
        'PATH': '/usr/local/bin:/usr/bin:/bin',
    }


@pytest.mark.parametrize('xdg', [None, 'relative', '/custom/state'])
def test_user_state_directory(tmp_path, monkeypatch, xdg):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.delenv('XDG_STATE_HOME', raising=False)
    if xdg is not None:
        monkeypatch.setenv('XDG_STATE_HOME', xdg)
    unit = render_user_unit(_args())
    root = Path(xdg) if xdg and xdg.startswith('/') else tmp_path / '.local/state'
    assert _environment(unit)['PACKETCAPTURE_DEFAULT_DATA_DIR'] == str(root / 'meshcore-packet-capture')
    assert 'WorkingDirectory=%h\n' in unit
    assert 'User=' not in unit and 'Group=' not in unit and 'ProtectHome=' not in unit
    assert not (tmp_path / '.local').exists()


@pytest.mark.parametrize('variable', ['PACKETCAPTURE_CONFIG_DIR', 'MESHCORE_PACKETCAPTURE_ENV_DIR',
                                     'XDG_CONFIG_HOME', 'PACKETCAPTURE_DATA_DIR', 'XDG_STATE_HOME'])
@pytest.mark.parametrize('control', ['\n', '\r', '\t', '\x7f'])
def test_rejects_unit_injection(monkeypatch, variable, control):
    monkeypatch.setenv(variable, '/path' + control + 'Environment=INJECTED=1')
    with pytest.raises(ValueError, match='control characters'):
        render_user_unit(_args())


def test_rejects_control_characters_in_argument():
    with pytest.raises(ValueError, match='control characters'):
        render_user_unit(_args(config_files=['config\n.toml']))


def test_rejects_trailing_control_character_in_data_directory(monkeypatch):
    monkeypatch.setenv('PACKETCAPTURE_DATA_DIR', '/state\n')
    with pytest.raises(ValueError, match='control characters'):
        render_user_unit(_args())


def test_capture_persists_state_in_generated_user_directory(tmp_path, monkeypatch):
    from meshcore_packet_capture.packet_capture import PacketCapture

    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path / 'state'))
    unit = render_user_unit(_args())
    for key, value in _environment(unit).items():
        monkeypatch.setenv(key, value)
    capture = PacketCapture.__new__(PacketCapture)
    capture.logger = logging.getLogger('state-test')
    capture.debug = False
    capture._write_state_updates({'last_advert_time': 123}, 'test')
    state = tmp_path / 'state/meshcore-packet-capture/advert_state.json'
    assert json.loads(state.read_text())['last_advert_time'] == 123


@pytest.fixture(scope='module')
def wheel_install(tmp_path_factory):
    root = tmp_path_factory.mktemp('wheel-only')
    staging = root / 'build-source'
    staging.mkdir()
    shutil.copytree(ROOT / 'src/meshcore_packet_capture', staging / 'src/meshcore_packet_capture',
                    ignore=shutil.ignore_patterns('__pycache__'))
    for name in ('pyproject.toml', 'README.md', 'LICENSE'):
        shutil.copy2(ROOT / name, staging / name)
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    build = subprocess.run([sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
                            '--wheel-dir', str(root / 'wheels'), str(staging)],
                           env=env, capture_output=True, text=True)
    assert build.returncode == 0, build.stdout + build.stderr
    installed = root / 'tool'
    venv.EnvBuilder(with_pip=True).create(installed)
    python = installed / 'bin/python'
    wheel = next((root / 'wheels').glob('*.whl'))
    install = subprocess.run([str(python), '-m', 'pip', 'install', '--no-deps', str(wheel)],
                             env=env, capture_output=True, text=True)
    assert install.returncode == 0, install.stdout + install.stderr
    shutil.rmtree(staging)
    return installed


def _run(wheel_install, tmp_path, *args, extra_env=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith('PACKETCAPTURE_')
           and k not in ('MESHCORE_PACKETCAPTURE_ENV_DIR', 'PYTHONPATH', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME')}
    env['HOME'] = str(tmp_path)
    env.update(extra_env or {})
    return subprocess.run([str(wheel_install / 'bin/meshcore-packet-capture'), *args],
                          cwd=tmp_path, env=env, capture_output=True, text=True)


def test_wheel_only_generation_needs_no_runtime_dependencies_or_config(wheel_install, tmp_path):
    # These would fail if generation initialized the capture environment.
    (tmp_path / '.env').mkdir()
    (tmp_path / 'invalid.toml').write_text('not valid TOML!')
    result = _run(wheel_install, tmp_path, '--print-systemd-unit', '--user',
                  '--config', 'invalid.toml', '--config', 'later.toml', '--no-mqtt')
    assert result.returncode == 0, result.stderr
    assert result.stderr == ''
    assert result.stdout.startswith('[Unit]\n')
    assert _command(result.stdout) == [str(wheel_install / 'bin/python'), '-m',
                                       'meshcore_packet_capture', '--user-config', '--config',
                                       str(tmp_path / 'invalid.toml'), '--config',
                                       str(tmp_path / 'later.toml'), '--no-mqtt', '--no-env-files']
    assert sorted(p.name for p in tmp_path.iterdir()) == ['.env', 'invalid.toml']


@pytest.mark.parametrize('args', [('--user',), ('--print-systemd-unit',)])
def test_unsupported_modes_fail_without_output(wheel_install, tmp_path, args):
    result = _run(wheel_install, tmp_path, *args)
    assert result.returncode == 2
    assert result.stdout == ''
    assert '--print-systemd-unit' in result.stderr


@pytest.mark.parametrize('selector', ['XDG_CONFIG_HOME', 'PACKETCAPTURE_CONFIG_DIR'])
def test_wheel_unit_discovers_config_changes_at_each_start(wheel_install, tmp_path, run_user_unit, selector):
    selected = tmp_path / 'selected'
    tree = selected / 'meshcore-packet-capture' if selector == 'XDG_CONFIG_HOME' else selected
    (tree / 'config.d').mkdir(parents=True)
    (tree / 'config.toml').write_text('[general]\niata="BASE"\n')
    result = _run(wheel_install, tmp_path, '--print-systemd-unit', '--user',
                  extra_env={selector: str(selected)})
    assert result.returncode == 0, result.stderr
    override = tree / 'config.d/99-user.toml'
    for expected in ('BASE', 'ADDED', 'CHANGED', 'BASE'):
        if expected == 'BASE':
            override.unlink(missing_ok=True)
        else:
            override.write_text(f'[general]\niata="{expected}"\n')
        restart = run_user_unit(result.stdout)
        assert restart.returncode == 0, restart.stderr
        snapshot = json.loads(restart.stdout)
        assert snapshot['env']['PACKETCAPTURE_IATA'] == expected
        assert str(wheel_install) in snapshot['module']


@pytest.mark.parametrize('options', [{'neighbors_now': True}, {'neighbors_exit': True},
                                    {'neighbors_now': True, 'neighbors_exit': True}])
def test_rejects_manual_neighbors_actions(options):
    with pytest.raises(ValueError, match='manual actions'):
        render_user_unit(_args(**options))


def test_executes_python_path_with_equals(tmp_path, monkeypatch):
    python = tmp_path / 'foo=bar/python'
    python.parent.mkdir()
    python.symlink_to(sys.executable)
    monkeypatch.setattr(sys, 'executable', str(python))
    command = _command(render_user_unit(_args()))
    # Keep the generated interpreter; substitute a harmless probe.
    result = subprocess.run(command[:1] + ['-c', 'print("reached Python")'],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout == 'reached Python\n'


def test_wheel_service_skips_home_env_and_respects_toml_state(wheel_install, tmp_path, run_user_unit):
    tree = tmp_path / '.config/meshcore-packet-capture'
    tree.mkdir(parents=True)
    state = tmp_path / 'toml-state'
    state.mkdir()
    previous = {'last_advert_time': time.time() - 60, 'last_neighbors_publish': time.time() - 120}
    (state / 'advert_state.json').write_text(json.dumps(previous))
    (tree / 'config.toml').write_text(f'[capture]\ndata_dir={json.dumps(str(state))}\n'
                                     '[general]\niata="USER"\n')
    (tmp_path / '.env').write_text('PACKETCAPTURE_CONFIG_DIR=/invalid\nPACKETCAPTURE_IATA=HOME\n')
    (tmp_path / '.env.local').write_text('PACKETCAPTURE_DATA_DIR=/unrelated\n')
    generated = _run(wheel_install, tmp_path, '--print-systemd-unit', '--user')
    assert generated.returncode == 0, generated.stderr
    started = run_user_unit(generated.stdout)
    assert started.returncode == 0, started.stderr
    snapshot = json.loads(started.stdout)
    assert snapshot['env']['PACKETCAPTURE_IATA'] == 'USER'
    assert 'PACKETCAPTURE_CONFIG_DIR' not in snapshot['env']
    assert snapshot['state_path'] == str(state / 'advert_state.json')
    assert snapshot['previous_state'] == previous
    assert snapshot['advert_timestamp'] == previous['last_advert_time']
    assert snapshot['neighbors_timestamp'] == previous['last_neighbors_publish']


def test_checkout_unit_keeps_legacy_state_path(tmp_path, monkeypatch):
    from meshcore_packet_capture import packet_capture as pc

    monkeypatch.setenv('MESHCORE_PACKETCAPTURE_ENV_DIR', str(tmp_path))
    unit = render_user_unit(_args())
    assert 'PACKETCAPTURE_DATA_DIR' not in _environment(unit)
    assert 'PACKETCAPTURE_DEFAULT_DATA_DIR' not in _environment(unit)
    package = tmp_path / 'src/meshcore_packet_capture'
    package.mkdir(parents=True)
    monkeypatch.setattr(pc, '__file__', str(package / 'packet_capture.py'))
    capture = pc.PacketCapture.__new__(pc.PacketCapture)
    capture.debug = False
    capture.logger = logging.getLogger('checkout-state-test')
    previous = {'last_advert_time': time.time() - 60, 'last_neighbors_publish': time.time() - 120}
    state = package / 'advert_state.json'
    state.write_text(json.dumps(previous))
    assert capture._get_state_file_path() == str(package / 'advert_state.json')
    assert capture._load_advert_state() == previous['last_advert_time']
    assert capture._load_neighbors_state() == previous['last_neighbors_publish']
    (package / 'data').mkdir()
    state.rename(package / 'data/advert_state.json')
    assert capture._get_state_file_path() == str(package / 'data/advert_state.json')
    assert capture._load_advert_state() == previous['last_advert_time']
    assert capture._load_neighbors_state() == previous['last_neighbors_publish']


@pytest.mark.skipif(shutil.which('systemd-analyze') is None, reason='systemd-analyze is not installed')
def test_systemd_analyze_accepts_special_executable_paths(tmp_path, monkeypatch):
    python = tmp_path / 'foo=bar with spaces %n $HOME "quote" back\\slash' / 'python'
    python.parent.mkdir()
    python.symlink_to(sys.executable)
    monkeypatch.setattr(sys, 'executable', str(python))
    unit = tmp_path / 'probe.service'
    unit.write_text(render_user_unit(_args(config_files=['config with %n $HOME.toml'])))
    result = subprocess.run(['systemd-analyze', '--user', 'verify', str(unit)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
