"""Behavioral tests for the local-checkout user service installer."""
from __future__ import annotations

import os
import shutil
import subprocess
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


def _escape_unit_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")


def _quote_unit_value(value: str) -> str:
    return f'"{_escape_unit_value(value)}"'


def _quote_exec_arg(value: str) -> str:
    escaped = _escape_unit_value(value).replace("$", "$$")
    return f'"{escaped}"'


def test_user_service_normalizes_and_quotes_repo_path(tmp_path: Path) -> None:
    cdpath_root = tmp_path / "cdpath-root"
    repo_dir = cdpath_root / 'repo with spaces %n $HOME "quoted" back\\slash'
    python = repo_dir / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    _write_executable(python, "#!/bin/bash\nexit 0\n")
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
    expected_exec = " ".join(
        [
            "env",
            _quote_exec_arg(str(python)),
            "-m",
            "meshcore_packet_capture",
            _quote_exec_arg("--config"),
            _quote_exec_arg(str(repo_dir / "config.toml")),
        ]
    )

    assert f"WorkingDirectory={_escape_unit_value(str(repo_dir))}" in unit
    assert (
        "Environment="
        + _quote_unit_value(f"MESHCORE_PACKETCAPTURE_ENV_DIR={repo_dir}")
    ) in unit
    assert f"ExecStart={expected_exec}" in unit

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
