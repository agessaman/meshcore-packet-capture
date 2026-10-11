"""Shared pytest fixtures and dependency stubs."""
from __future__ import annotations

import os
from pathlib import Path
import shlex
import site
import subprocess
import sys
import textwrap
import types

import pytest


def _install_dependency_stubs() -> None:
    if "meshcore" not in sys.modules:
        meshcore_stub = types.ModuleType("meshcore")
        # Mirror the real EventType members the package references, so modules
        # importing them (e.g. neighbors.py) behave the same under the stub.
        meshcore_stub.EventType = type(
            "EventType",
            (),
            {
                "ERROR": "ERROR",
                "DISCOVER_RESPONSE": "discover_response",
                "DEFAULT_FLOOD_SCOPE": "default_flood_scope",
            },
        )
        sys.modules["meshcore"] = meshcore_stub

    if "paho" not in sys.modules:
        paho_module = types.ModuleType("paho")
        mqtt_module = types.ModuleType("paho.mqtt")
        mqtt_client_module = types.ModuleType("paho.mqtt.client")
        # Constants/helpers safe_publish() consults on every publish.
        mqtt_client_module.MQTT_ERR_SUCCESS = 0
        mqtt_client_module.error_string = lambda rc: f"rc={rc}"
        mqtt_module.client = mqtt_client_module
        paho_module.mqtt = mqtt_module
        sys.modules["paho"] = paho_module
        sys.modules["paho.mqtt"] = mqtt_module
        sys.modules["paho.mqtt.client"] = mqtt_client_module


_install_dependency_stubs()


@pytest.fixture(autouse=True)
def isolate_packetcapture_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep PACKETCAPTURE_* env keys from leaking across tests."""
    for key in list(os.environ):
        if key.startswith("PACKETCAPTURE_") or key == "MESHCORE_PACKETCAPTURE_ENV_DIR":
            monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def isolate_system_config(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from meshcore_packet_capture import config_loader
    monkeypatch.setattr(config_loader, "DEFAULT_CONFIG_FILE", str(tmp_path / "system/config.toml"))
    monkeypatch.setattr(config_loader, "DEFAULT_CONFIG_D", str(tmp_path / "system/config.d"))


@pytest.fixture
def run_user_unit(tmp_path):
    """Execute rendered argv through the real CLI, replacing radio/MQTT work.

    Quoting/specifier decoding here is only a subprocess approximation of
    systemd; it does not validate the manager's own parsing or restart behavior.
    """
    probe = tmp_path / "service-probe"
    probe.mkdir()
    code = f"import sys; sys.path.extend({site.getsitepackages()!r})\n" + textwrap.dedent('''
        import json, logging, os, sys, types
        meshcore = types.ModuleType('meshcore')
        meshcore.EventType = types.SimpleNamespace()
        sys.modules['meshcore'] = meshcore
        for name in ('paho', 'paho.mqtt', 'paho.mqtt.client'):
            sys.modules[name] = types.ModuleType(name)
        sys.modules['paho'].mqtt = sys.modules['paho.mqtt']
        sys.modules['paho.mqtt'].client = sys.modules['paho.mqtt.client']
        from meshcore_packet_capture import config_loader as cl
        cl.DEFAULT_CONFIG_FILE = os.path.join(os.environ['PROBE_SYSTEM_DIR'], 'config.toml')
        cl.DEFAULT_CONFIG_D = os.path.join(os.environ['PROBE_SYSTEM_DIR'], 'config.d')
        from meshcore_packet_capture import packet_capture as pc
        class ProbeCapture(pc.PacketCapture):
            def __init__(self, **kwargs):
                self.logger = logging.getLogger('service-probe')
                self.debug = False
            async def start(self):
                print(json.dumps({
                    'env': {k: v for k, v in os.environ.items() if k.startswith('PACKETCAPTURE_')},
                    'state_path': self._get_state_file_path(),
                    'previous_state': self._read_state_dict(),
                    'advert_timestamp': self._load_advert_state(),
                    'neighbors_timestamp': self._load_neighbors_state(),
                    'module': pc.__file__,
                }))
            async def stop(self):
                pass
        pc.PacketCapture = ProbeCapture
    ''')
    (probe / "sitecustomize.py").write_text(
        "try:\n" + textwrap.indent(code, "    ") +
        "except BaseException:\n    import os, traceback\n    traceback.print_exc()\n    os._exit(90)\n"
    )

    def run(unit, *, system=None, extra_env=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith('PACKETCAPTURE_')
               and k not in ('MESHCORE_PACKETCAPTURE_ENV_DIR', 'XDG_CONFIG_HOME', 'PYTHONPATH')}
        env.update(HOME=str(tmp_path), PROBE_SYSTEM_DIR=str(system or tmp_path / 'missing-system'),
                   PYTHONPATH=str(probe), PYTHONDONTWRITEBYTECODE='1')
        command = None
        working = tmp_path
        for line in unit.splitlines():
            if line.startswith('Environment='):
                key, value = shlex.split(line.partition('=')[2])[0].split('=', 1)
                env[key] = value.replace('%%', '%')
            elif line.startswith('ExecStart='):
                assert line.startswith('ExecStart=:')
                command = [arg.replace('%%', '%')
                           for arg in shlex.split(line.partition('=')[2][1:])]
            elif line.startswith('WorkingDirectory='):
                value = line.partition('=')[2]
                working = tmp_path if value == '%h' else Path(shlex.split(value)[0].replace('%%', '%'))
        env.update(extra_env or {})
        assert command is not None
        return subprocess.run(command, cwd=working, env=env, capture_output=True, text=True, timeout=15)
    return run
