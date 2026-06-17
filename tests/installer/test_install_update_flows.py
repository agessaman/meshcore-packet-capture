"""Installer flow tests with mocked side effects."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from installer import InstallerContext
from installer import install_cmd as ic
from installer import update_cmd as uc


@dataclass
class _CmdResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


def _write_repo_fixture(repo: Path) -> None:
    """Create a minimal local repo fixture for installer copy flows."""
    (repo / "src" / "meshcore_packet_capture").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "meshcore_packet_capture" / "__init__.py").write_text('__version__ = "9.9.9"\n')
    (repo / "pyproject.toml").write_text("[project]\nname='meshcore-packet-capture'\n")
    (repo / "config.toml.example").write_text("[general]\niata='AAA'\n")
    (repo / "uninstall.sh").write_text("#!/usr/bin/env bash\n")
    (repo / "requirements.txt").write_text("pytest\n")
    (repo / "presets").mkdir(exist_ok=True)
    (repo / "presets" / "letsmesh.toml").write_text('[[broker]]\nname = "letsmesh-us"\nenabled = true\n')
    (repo / "packaging" / "systemd").mkdir(parents=True, exist_ok=True)
    (repo / "packaging" / "systemd" / "meshcore-packet-capture.service").write_text("[Service]\n")
    (repo / "packaging" / "systemd" / "ble-disconnect.sh").write_text("#!/bin/bash\nexit 0\n")
    (repo / "packaging" / "launchd").mkdir(parents=True, exist_ok=True)
    (repo / "packaging" / "launchd" / "com.meshcore.meshcore_packet_capture.plist").write_text("<plist/>")


def test_do_install_local_copy_and_pip_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_repo_fixture(repo)

    install_dir = tmp_path / "opt" / "meshcore-packet-capture"
    config_dir = tmp_path / "etc" / "meshcore-packet-capture"
    config_d = config_dir / "config.d"
    config_d.mkdir(parents=True, exist_ok=True)
    user_toml = config_d / "99-user.toml"
    user_toml.write_text('[[broker]]\nname = "ok"\n')

    ctx = InstallerContext(
        local_install=str(repo),
        install_dir=str(install_dir),
        config_dir=str(config_dir),
    )

    pip_calls: list[tuple[str, bool]] = []
    install_service_calls: list[str] = []

    monkeypatch.setattr(ic.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(ic, "run_migrate", lambda _ctx: False)
    monkeypatch.setattr(ic, "migrate_user_config_filename", lambda _cfg: user_toml)
    monkeypatch.setattr(ic, "prompt_input", lambda *_a, **_k: "3")
    monkeypatch.setattr(ic, "_check_python_version", lambda: None)
    monkeypatch.setattr(ic, "create_venv", lambda *_a, **_k: None)
    monkeypatch.setattr(ic, "create_version_info", lambda *_a, **_k: None)
    monkeypatch.setattr(ic, "configure_mqtt_brokers", lambda *_a, **_k: None)
    monkeypatch.setattr(
        ic,
        "pip_install_project",
        lambda install_dir, upgrade=False: pip_calls.append((install_dir, upgrade)),
    )
    monkeypatch.setattr(
        ic,
        "_install_new_service",
        lambda _ctx: install_service_calls.append(_ctx.install_method),
    )
    monkeypatch.setattr(ic, "_print_install_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(ic, "run_cmd", lambda *_a, **_k: _CmdResult(returncode=0))

    work_tmp = tmp_path / "tmp"
    work_tmp.mkdir(parents=True, exist_ok=True)
    ic._do_install(ctx, str(work_tmp))

    assert (install_dir / "src" / "meshcore_packet_capture" / "__init__.py").exists()
    assert (install_dir / "pyproject.toml").exists()
    assert (install_dir / "presets" / "letsmesh.toml").exists()
    assert (install_dir / "meshcore-packet-capture.service").exists()
    assert (install_dir / "com.meshcore.meshcore_packet_capture.plist").exists()
    assert (install_dir / "ble-disconnect.sh").exists()
    assert (config_dir / "config.toml").exists()
    assert pip_calls == [(str(install_dir), False)]
    assert install_service_calls == ["3"]


def test_do_install_compile_failure_aborts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_repo_fixture(repo)

    install_dir = tmp_path / "opt" / "meshcore-packet-capture"
    config_dir = tmp_path / "etc" / "meshcore-packet-capture"
    config_d = config_dir / "config.d"
    config_d.mkdir(parents=True, exist_ok=True)
    user_toml = config_d / "99-user.toml"
    user_toml.write_text('[[broker]]\nname = "ok"\n')

    ctx = InstallerContext(
        local_install=str(repo),
        install_dir=str(install_dir),
        config_dir=str(config_dir),
    )

    monkeypatch.setattr(ic.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(ic, "run_migrate", lambda _ctx: False)
    monkeypatch.setattr(ic, "migrate_user_config_filename", lambda _cfg: user_toml)
    monkeypatch.setattr(ic, "prompt_input", lambda *_a, **_k: "3")
    monkeypatch.setattr(ic, "_check_python_version", lambda: None)
    monkeypatch.setattr(ic, "create_venv", lambda *_a, **_k: None)
    monkeypatch.setattr(ic, "_print_install_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(ic, "run_cmd", lambda *_a, **_k: _CmdResult(returncode=1, stderr="bad syntax"))

    work_tmp = tmp_path / "tmp"
    work_tmp.mkdir(parents=True, exist_ok=True)
    with pytest.raises(SystemExit):
        ic._do_install(ctx, str(work_tmp))


def test_run_update_requires_existing_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ctx = InstallerContext(
        install_dir=str(tmp_path / "opt" / "missing"),
        config_dir=str(tmp_path / "etc" / "meshcore-packet-capture"),
    )
    monkeypatch.setattr(uc, "run_cmd", lambda *_a, **_k: _CmdResult(returncode=1))

    with pytest.raises(SystemExit):
        uc.run_update(ctx)


def test_do_update_non_docker_reinstalls_package(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write_repo_fixture(repo)

    install_dir = tmp_path / "opt" / "meshcore-packet-capture"
    config_dir = tmp_path / "etc" / "meshcore-packet-capture"
    (config_dir / "config.d").mkdir(parents=True, exist_ok=True)
    user_toml = config_dir / "config.d" / "99-user.toml"
    user_toml.write_text('[[broker]]\nname = "ok"\n')

    ctx = InstallerContext(
        local_install=str(repo),
        install_dir=str(install_dir),
        config_dir=str(config_dir),
        update_mode=True,
    )
    install_dir.mkdir(parents=True, exist_ok=True)

    pip_calls: list[tuple[str, bool]] = []

    monkeypatch.setattr(uc.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(uc, "detect_system_type", lambda *_a, **_k: "manual")
    monkeypatch.setattr(uc, "create_venv", lambda *_a, **_k: None)
    monkeypatch.setattr(uc, "cleanup_legacy_nvm", lambda *_a, **_k: None)
    monkeypatch.setattr(uc, "pip_install_project", lambda d, upgrade=False: pip_calls.append((d, upgrade)))
    monkeypatch.setattr(uc, "migrate_user_config_filename", lambda *_a, **_k: user_toml)
    monkeypatch.setattr(uc, "create_version_info", lambda *_a, **_k: None)
    monkeypatch.setattr(uc, "set_permissions", lambda *_a, **_k: None)
    monkeypatch.setattr(uc, "install_systemd_service", lambda *_a, **_k: True)
    monkeypatch.setattr(uc, "prompt_yes_no", lambda *_a, **_k: False)
    monkeypatch.setattr(uc, "configure_mqtt_brokers", lambda *_a, **_k: None)
    monkeypatch.setattr(uc, "update_owner_info", lambda *_a, **_k: None)
    monkeypatch.setattr(uc, "token_preset_brokers", lambda *_a, **_k: False)
    monkeypatch.setattr(uc, "_print_update_summary", lambda *_a, **_k: None)
    monkeypatch.setattr(uc, "run_cmd", lambda *_a, **_k: _CmdResult(returncode=0, stdout=""))

    work_tmp = tmp_path / "tmp"
    work_tmp.mkdir(parents=True, exist_ok=True)
    uc._do_update(ctx, str(work_tmp))

    assert (install_dir / "src" / "meshcore_packet_capture" / "__init__.py").exists()
    ble_disconnect = install_dir / "ble-disconnect.sh"
    assert ble_disconnect.exists()
    assert ble_disconnect.stat().st_mode & 0o111
    assert pip_calls == [(str(install_dir), True)]
