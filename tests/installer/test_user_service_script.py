"""Behavioral tests for the local-checkout user service installer."""
from __future__ import annotations

import os
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "install.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash not available"
)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def _write_python(path: Path) -> None:
    code = (
        'import sys; sys.executable = sys.argv[1]; '
        'sys.argv = ["meshcore-packet-capture", *sys.argv[2:]]; '
        'from meshcore_packet_capture.__main__ import cli; cli()'
    )
    _write_executable(path, '\n'.join([
        '#!/bin/bash',
        'if [ "${2:-}" = "pip" ]; then exit 0; fi',
        f'export PYTHONPATH={shlex.quote(str(REPO_ROOT / "src"))}"${{PYTHONPATH:+:$PYTHONPATH}}"',
        f'exec {shlex.quote(sys.executable)} -c {shlex.quote(code)} "$0" "${{@:3}}"',
        '',
    ]))


def _escape_unit_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")


def _quote_unit_value(value: str) -> str:
    return f'"{_escape_unit_value(value)}"'


def _quote_exec_arg(value: str) -> str:
    escaped = _escape_unit_value(value)
    return f'"{escaped}"'


def test_user_service_normalizes_and_quotes_repo_path(tmp_path: Path) -> None:
    cdpath_root = tmp_path / "cdpath-root"
    repo_dir = cdpath_root / 'repo with spaces %n $HOME "quoted" back\\slash'
    python = repo_dir / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    _write_python(python)
    (repo_dir / "pyproject.toml").write_text("[project]\nname = 'test'\n")
    (repo_dir / "config.toml").write_text("[capture]\n")

    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "systemctl",
        (
            "#!/bin/bash\n"
            'if [ "${2:-}" = "is-active" ]; then\n'
            "    exit 3\n"
            "fi\n"
            "exit 0\n"
        ),
    )

    config_home = tmp_path / "config-home"
    env = os.environ.copy()
    env.pop("PACKETCAPTURE_CONFIG_DIR", None)
    env["CDPATH"] = str(cdpath_root)
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env["XDG_CONFIG_HOME"] = str(config_home)
    working_dir = tmp_path / "working"
    working_dir.mkdir()
    # The initial -d check sees this path, while Bash's CDPATH selects repo_dir.
    (working_dir / repo_dir.name).mkdir()

    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--user-service",
            "--repo-dir",
            repo_dir.name,
        ],
        cwd=working_dir,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    unit_path = (
        config_home / "systemd" / "user" / "meshcore-packet-capture.service"
    )
    unit = unit_path.read_text()
    expected_exec = ":" + " ".join(
        [
            _quote_exec_arg(str(python)),
            _quote_exec_arg("-m"),
            _quote_exec_arg("meshcore_packet_capture"),
            _quote_exec_arg("--user-config"),
        ]
    )

    assert f"WorkingDirectory={_quote_unit_value(str(repo_dir))}" in unit
    assert (
        "Environment="
        + _quote_unit_value(f"MESHCORE_PACKETCAPTURE_ENV_DIR={repo_dir}")
    ) in unit
    assert f"ExecStart={expected_exec}" in unit
    assert "--config " not in unit

    systemd_analyze = shutil.which("systemd-analyze")
    if systemd_analyze:
        verify = subprocess.run(
            [systemd_analyze, "--user", "verify", str(unit_path)],
            capture_output=True,
            text=True,
        )
        assert verify.returncode == 0, verify.stderr


def test_user_service_rejects_control_characters_in_repo_path(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo-trailing\n"
    repo_dir.mkdir()
    config_home = tmp_path / "config-home"
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(config_home)

    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--user-service",
            "--repo-dir",
            str(repo_dir),
        ],
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "repository path cannot contain control characters" in result.stderr
    assert not (
        config_home / "systemd" / "user" / "meshcore-packet-capture.service"
    ).exists()


def _install_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, local_config: bool = True, check: bool = True):
    repo = tmp_path / "checkout"
    python = repo / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    _write_python(python)
    (repo / "pyproject.toml").write_text("[project]\nname='fixture'\n")
    if local_config:
        (repo / "config.toml").write_text('[general]\niata="BASE"\n')
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(fake_bin / "systemctl", '#!/bin/bash\n[ "${2:-}" != "is-active" ]\n')
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")
    result = subprocess.run(
        ["bash", str(SCRIPT), "--user-service", "--repo-dir", str(repo)],
        capture_output=True, text=True,
    )
    if not check:
        return result
    assert result.returncode == 0, result.stderr
    unit = xdg / "systemd" / "user" / "meshcore-packet-capture.service"
    return repo, xdg, unit


def _restart_config(unit: Path, run_user_unit, *, system: Path | None = None):
    result = run_user_unit(unit.read_text(), system=system)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)['env']


@pytest.mark.parametrize("local_config", [False, True])
def test_generated_unit_discovers_configs_added_after_install(tmp_path, monkeypatch, run_user_unit, local_config):
    repo, _, unit = _install_fixture(tmp_path, monkeypatch, local_config=local_config)
    original_unit = unit.read_text()
    system = tmp_path / "system"
    system.mkdir()
    (system / "config.toml").write_text('[general]\niata="SYSTEM"\n')
    assert _restart_config(unit, run_user_unit, system=system).get("PACKETCAPTURE_IATA") == ("BASE" if local_config else None)
    (repo / "config.d").mkdir()
    override = repo / "config.d" / "99-user.toml"
    override.write_text('[general]\niata="ADDED"\n')
    assert _restart_config(unit, run_user_unit, system=system)["PACKETCAPTURE_IATA"] == "ADDED"
    override.write_text('[general]\niata="CHANGED"\n')
    assert _restart_config(unit, run_user_unit, system=system)["PACKETCAPTURE_IATA"] == "CHANGED"
    override.unlink()
    assert _restart_config(unit, run_user_unit, system=system).get("PACKETCAPTURE_IATA") == ("BASE" if local_config else None)
    assert unit.read_text() == original_unit


def test_generated_unit_empty_checkout_stays_isolated(tmp_path, monkeypatch, run_user_unit):
    repo, xdg, unit = _install_fixture(tmp_path, monkeypatch, local_config=False)
    user = xdg / "meshcore-packet-capture"
    user.mkdir()
    (user / "config.toml").write_text('[general]\niata="XDG"\n')
    assert "PACKETCAPTURE_IATA" not in _restart_config(unit, run_user_unit)
    (repo / "config.toml").write_text('[general]\niata="CHECKOUT"\n')
    assert _restart_config(unit, run_user_unit)["PACKETCAPTURE_IATA"] == "CHECKOUT"
    (repo / "config.toml").unlink()
    assert "PACKETCAPTURE_IATA" not in _restart_config(unit, run_user_unit)


def test_generated_unit_persists_and_quotes_directory_override(tmp_path, monkeypatch, run_user_unit):
    selected = tmp_path / 'config with spaces %n $HOME "quotes" back\\slash'
    selected.mkdir()
    (selected / "config.toml").write_text('[general]\niata="SELECTED"\n')
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", str(selected))
    _, _, unit = _install_fixture(tmp_path, monkeypatch)
    assert "Environment=" + _quote_unit_value(f"PACKETCAPTURE_CONFIG_DIR={selected}") in unit.read_text()
    assert _restart_config(unit, run_user_unit)["PACKETCAPTURE_IATA"] == "SELECTED"


@pytest.mark.parametrize("variable", ["PACKETCAPTURE_CONFIG_DIR", "XDG_CONFIG_HOME"])
def test_user_service_rejects_control_characters_in_directory_override(tmp_path, monkeypatch, variable):
    # XDG_CONFIG_HOME is normally set by the fixture; inject the bad value only
    # into the installer's subprocess environment.
    original_run = subprocess.run
    def run_with_invalid_path(*args, **kwargs):
        env = os.environ.copy()
        env[variable] = "invalid\npath"
        kwargs["env"] = env
        return original_run(*args, **kwargs)
    monkeypatch.setattr(subprocess, "run", run_with_invalid_path)
    result = _install_fixture(tmp_path, monkeypatch, check=False)
    assert result.returncode != 0
    assert "configuration paths cannot contain control characters" in result.stderr
    assert not (tmp_path / "xdg" / "systemd" / "user" / "meshcore-packet-capture.service").exists()


def test_generated_unit_resolves_relative_directory_at_install_time(tmp_path, monkeypatch, run_user_unit):
    selected = tmp_path / "selected"
    selected.mkdir()
    (selected / "config.toml").write_text('[general]\niata="RELATIVE"\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PACKETCAPTURE_CONFIG_DIR", "selected")
    _, _, unit = _install_fixture(tmp_path, monkeypatch)
    assert "Environment=" + _quote_unit_value(f"PACKETCAPTURE_CONFIG_DIR={selected}") in unit.read_text()
    assert _restart_config(unit, run_user_unit)["PACKETCAPTURE_IATA"] == "RELATIVE"


def test_relative_xdg_config_home_replaces_unit_in_home(tmp_path, monkeypatch):
    repo, _, _ = _install_fixture(tmp_path, monkeypatch)
    home = tmp_path / "home"
    old_unit = home / ".config/systemd/user/meshcore-packet-capture.service"
    old_unit.parent.mkdir(parents=True)
    old_unit.write_text("stale unit\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative-xdg")
    result = subprocess.run(["bash", str(SCRIPT), "--user-service", "--repo-dir", str(repo)],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert old_unit.read_text().startswith("[Unit]\n")
    assert 'Environment="XDG_CONFIG_HOME=' not in old_unit.read_text()
    assert not (tmp_path / "relative-xdg").exists()
    uninstalled = subprocess.run(["bash", str(REPO_ROOT / "uninstall.sh"), "--user-service",
                                 "--repo-dir", str(repo)], cwd=tmp_path, capture_output=True, text=True)
    assert uninstalled.returncode == 0, uninstalled.stderr
    assert not old_unit.exists()


def test_failed_render_preserves_existing_unit(tmp_path, monkeypatch):
    repo, _, unit = _install_fixture(tmp_path, monkeypatch)
    original = unit.read_text()
    # The renderer validates state overrides, which the shell does not inspect.
    monkeypatch.setenv('PACKETCAPTURE_DATA_DIR', '/invalid\nstate')
    result = subprocess.run(
        ['bash', str(SCRIPT), '--user-service', '--repo-dir', str(repo)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert 'control characters' in result.stderr
    assert unit.read_text() == original
    assert list(unit.parent.glob('.meshcore-packet-capture.*')) == []
