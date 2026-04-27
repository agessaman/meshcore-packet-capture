"""Update an existing MeshCore Packet Capture installation."""

from __future__ import annotations

import os
import platform
import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from . import extract_version_from_file
from .config import (
    configure_mqtt_brokers,
    update_owner_info,
    migrate_user_config_filename,
    token_preset_brokers,
    user_config_path,
)
from .system import (
    LOCAL_IMAGE,
    check_service_health,
    cleanup_legacy_nvm,
    create_system_user,
    create_version_info,
    create_venv,
    detect_service_user,
    detect_system_type,
    download_repo_archive,
    install_systemd_service,
    pip_install_project,
    pull_or_build_docker_image,
    run_cmd,
    set_permissions,
)
from .ui import (
    print_error,
    print_header,
    print_info,
    print_success,
    prompt_yes_no,
)

if TYPE_CHECKING:
    from . import InstallerContext


def run_update(ctx: InstallerContext) -> None:
    """Update an existing installation."""

    venv_py = Path(ctx.install_dir, "venv", "bin", "python3")
    has_pkg = False
    if venv_py.is_file():
        r = run_cmd(
            [str(venv_py), "-m", "pip", "show", "meshcore-packet-capture"],
            check=False,
            capture=True,
        )
        has_pkg = r.returncode == 0
    legacy_flat = Path(ctx.install_dir, "packet_capture.py").exists()
    if not (has_pkg or legacy_flat):
        print_error(f"No installation found at {ctx.install_dir}")
        print_info("Run the installer to create a new installation.")
        raise SystemExit(1)

    # Create temp directory for downloads
    tmp_dir = tempfile.mkdtemp()
    try:
        _do_update(ctx, tmp_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _do_update(ctx: InstallerContext, tmp_dir: str) -> None:
    # Download repo archive (or use local install path)
    if ctx.local_install:
        repo_dir = ctx.local_install
    else:
        repo_dir = download_repo_archive(ctx.repo, ctx.branch, tmp_dir)

    ctx.repo_dir = repo_dir

    ver_src = os.path.join(repo_dir, "src", "meshcore_packet_capture", "__init__.py")
    if not os.path.isfile(ver_src):
        print_error("Repository missing package (expected src/meshcore_packet_capture/__init__.py)")
        raise SystemExit(1)
    ctx.script_version = extract_version_from_file(ver_src)

    print_header(f"MeshCore Packet Capture Updater v{ctx.script_version}")
    print_info(f"Installation directory: {ctx.install_dir}")
    print_info(f"Configuration directory: {ctx.config_dir}")
    print()

    # Detect existing installation type
    system_type = detect_system_type(ctx.install_dir)
    print_info(f"Detected installation type: {system_type}")

    if platform.system() != "Darwin" and ctx.svc_user:
        ctx.svc_user = detect_service_user(ctx)
        create_system_user(ctx.svc_user, ctx.install_dir)

    # ---------------------------------------------------------------------------
    # Install files from repo
    # ---------------------------------------------------------------------------
    print_header("Updating Files")

    if ctx.local_install:
        print_info(f"Installing from local directory: {repo_dir}")
    else:
        print_info(f"Installing from GitHub ({ctx.repo} @ {ctx.branch})...")

    shutil.copy2(os.path.join(repo_dir, "pyproject.toml"), os.path.join(tmp_dir, "pyproject.toml"))
    src_from = os.path.join(repo_dir, "src")
    src_tmp = os.path.join(tmp_dir, "src")
    if os.path.isdir(src_tmp):
        shutil.rmtree(src_tmp)
    shutil.copytree(src_from, src_tmp)
    shutil.copy2(os.path.join(repo_dir, "config.toml.example"), os.path.join(tmp_dir, "config.toml.example"))
    shutil.copy2(os.path.join(repo_dir, "uninstall.sh"), os.path.join(tmp_dir, "uninstall.sh"))
    req_src = os.path.join(repo_dir, "requirements.txt")
    if os.path.isfile(req_src):
        shutil.copy2(req_src, os.path.join(tmp_dir, "requirements.txt"))

    for svc_name in ("meshcore-packet-capture.service", "com.meshcore.meshcore_packet_capture.plist"):
        for candidate in (
            os.path.join(repo_dir, "packaging", "systemd", svc_name),
            os.path.join(repo_dir, "packaging", "launchd", svc_name),
            os.path.join(repo_dir, svc_name),
        ):
            if os.path.isfile(candidate):
                shutil.copy2(candidate, os.path.join(tmp_dir, svc_name))
                break

    print_success("Files ready")

    print_info("Verifying Python syntax...")
    src_pkg = os.path.join(tmp_dir, "src", "meshcore_packet_capture")
    result = run_cmd(["python3", "-m", "compileall", "-q", src_pkg], check=False, capture=True)
    if result.returncode != 0:
        print_error("Syntax errors in meshcore_packet_capture package")
        raise SystemExit(1)

    dest_src = os.path.join(ctx.install_dir, "src")
    if os.path.isdir(dest_src):
        shutil.rmtree(dest_src)
    shutil.copytree(os.path.join(tmp_dir, "src"), dest_src)
    shutil.copy2(os.path.join(tmp_dir, "pyproject.toml"), os.path.join(ctx.install_dir, "pyproject.toml"))
    tmp_req = os.path.join(tmp_dir, "requirements.txt")
    if os.path.isfile(tmp_req):
        shutil.copy2(tmp_req, os.path.join(ctx.install_dir, "requirements.txt"))
    presets_src = os.path.join(repo_dir, "presets")
    presets_dest = os.path.join(ctx.install_dir, "presets")
    if os.path.isdir(presets_src):
        if os.path.exists(presets_dest):
            shutil.rmtree(presets_dest)
        shutil.copytree(presets_src, presets_dest)
    shutil.copy2(os.path.join(tmp_dir, "uninstall.sh"), f"{ctx.install_dir}/")
    for f in ("meshcore-packet-capture.service", "com.meshcore.meshcore_packet_capture.plist"):
        src = os.path.join(tmp_dir, f)
        if os.path.exists(src):
            shutil.copy2(src, f"{ctx.install_dir}/")
    os.chmod(f"{ctx.install_dir}/uninstall.sh", 0o755)

    # Update base config (overwrite config.toml, preserve user overrides)
    shutil.copy2(os.path.join(tmp_dir, "config.toml.example"), f"{ctx.config_dir}/config.toml")
    print_success(f"Base config updated at {ctx.config_dir}/config.toml")
    print_success(f"Files updated in {ctx.install_dir}")

    # ---------------------------------------------------------------------------
    # Update dependencies (skip for Docker)
    # ---------------------------------------------------------------------------
    if system_type != "docker":
        print_header("Updating Dependencies")
        create_venv(ctx.install_dir, ctx.svc_user)
        cleanup_legacy_nvm(ctx.install_dir)
        print_info("Upgrading application package in virtual environment...")
        pip_install_project(ctx.install_dir, upgrade=True)

    # ---------------------------------------------------------------------------
    # Configuration
    # ---------------------------------------------------------------------------
    print_header("Configuration")

    user_toml = migrate_user_config_filename(ctx.config_dir)
    if user_toml.exists():
        if ctx.update_mode:
            print_info("Keeping existing configuration")
        elif prompt_yes_no("Existing configuration found. Reconfigure?", "n"):
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            shutil.copy2(str(user_toml), f"{user_toml}.backup-{timestamp}")
            print_info(f"Backed up existing configuration to {user_toml}.backup-{timestamp}")
            configure_mqtt_brokers(ctx)
        else:
            print_info("Keeping existing configuration")

            # Offer owner info update for token-auth brokers
            content = user_toml.read_text()
            if 'method = "token"' in content or token_preset_brokers(ctx.config_dir):
                print()
                print_info("Token-authenticated brokers detected")

                owner_match = re.search(r'owner\s*=\s*"([^"]*)"', content)
                email_match = re.search(r'email\s*=\s*"([^"]*)"', content)
                if owner_match and owner_match.group(1):
                    print_info(f"Current owner: {owner_match.group(1)}")
                if email_match and email_match.group(1):
                    print_info(f"Current email: {email_match.group(1)}")

                # Show remote serial config
                rs_match = re.search(r'\[remote_serial\]\s*\n\s*enabled\s*=\s*(\w+)', content)
                rs_status = rs_match.group(1) if rs_match else "not configured"
                print()
                print(f"  Remote Serial: {rs_status}")

                if prompt_yes_no("Update owner information or remote serial configuration?", "n"):
                    update_owner_info(ctx.config_dir)
    else:
        configure_mqtt_brokers(ctx)

    # ---------------------------------------------------------------------------
    # Permissions and version info
    # ---------------------------------------------------------------------------
    if platform.system() != "Darwin" and ctx.svc_user:
        set_permissions(ctx.install_dir, ctx.config_dir, ctx.svc_user)

    create_version_info(ctx)

    # ---------------------------------------------------------------------------
    # Service restart
    # ---------------------------------------------------------------------------
    print_header("Service Restart")
    print_info(f"Detected existing installation type: {system_type}")

    if system_type == "docker":
        if ctx.update_mode or prompt_yes_no("Update and restart Docker container?", "y"):
            # Copy latest Dockerfile from repo archive (for local build fallback)
            dockerfile_src = os.path.join(repo_dir, "Dockerfile")
            if os.path.exists(dockerfile_src):
                shutil.copy2(dockerfile_src, f"{ctx.install_dir}/Dockerfile")

            # Pull from registry or build locally
            image = pull_or_build_docker_image(ctx)
            if image is None:
                print_error("Failed to obtain Docker image")
            else:
                # Restart container
                ps_result = run_cmd(["docker", "ps", "-a"], check=False, capture=True)
                if ps_result.returncode == 0 and "meshcore-packet-capture" in ps_result.stdout:
                    print_info("Restarting container...")
                    run_cmd(["docker", "stop", "meshcore-packet-capture"], check=False)
                    run_cmd(["docker", "rm", "meshcore-packet-capture"], check=False)

                    # Recreate container
                    serial_device = "/dev/ttyACM0"
                    if user_toml.exists():
                        match = re.search(r'^\s*ports\s*=\s*\["([^"]+)"', user_toml.read_text(), re.MULTILINE)
                        if match:
                            serial_device = match.group(1)

                    parts: list[str] = [
                        "docker", "run", "-d", "--name", "meshcore-packet-capture", "--restart", "unless-stopped",
                        "-v", f"{ctx.config_dir}:/etc/meshcore-packet-capture:ro",
                    ]
                    if Path(serial_device).exists():
                        parts.append(f"--device={serial_device}")
                    parts.append(image)

                    result = run_cmd(parts, check=False)
                    if result.returncode == 0:
                        check_service_health("docker")

    elif system_type == "systemd":
        install_systemd_service(
            ctx.install_dir, ctx.config_dir, ctx.svc_user,
            is_update=True, auto=ctx.update_mode,
        )

    elif system_type == "launchd":
        result = run_cmd(["launchctl", "list"], check=False, capture=True)
        if "com.meshcore.meshcore_packet_capture" in (result.stdout or ""):
            if ctx.update_mode or prompt_yes_no("Restart launchd service?", "y"):
                run_cmd(["launchctl", "stop", "com.meshcore.meshcore_packet_capture"], check=False)
                import time
                time.sleep(2)
                run_cmd(["launchctl", "start", "com.meshcore.meshcore_packet_capture"], check=False)
                check_service_health("launchd")
    else:
        print_info("No existing service found")
        if prompt_yes_no("Install service?", "n"):
            from .install_cmd import _install_new_service
            _install_new_service(ctx)

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------
    _print_update_summary(ctx, system_type)


def _print_update_summary(ctx: InstallerContext, system_type: str) -> None:
    """Print update completion summary."""
    print_header("Update Complete!")
    print(f"Installation directory: {ctx.install_dir}")
    print(f"Configuration directory: {ctx.config_dir}")
    print()
    print(f"Base config: {ctx.config_dir}/config.toml")
    print(f"User config: {user_config_path(ctx.config_dir)}")
    print()

    if system_type == "docker":
        print("Docker container management:")
        print("  Start:   docker start meshcore-packet-capture")
        print("  Stop:    docker stop meshcore-packet-capture")
        print("  Status:  docker ps -a | grep meshcore-packet-capture")
        print("  Logs:    docker logs -f meshcore-packet-capture")
        print("  Restart: docker restart meshcore-packet-capture")
    elif system_type == "systemd":
        print("Service management:")
        print("  Start:   sudo systemctl start meshcore-packet-capture")
        print("  Stop:    sudo systemctl stop meshcore-packet-capture")
        print("  Status:  sudo systemctl status meshcore-packet-capture")
        print("  Logs:    sudo journalctl -u meshcore-packet-capture -f")
    elif system_type == "launchd":
        print("Service management:")
        print("  Start:   sudo launchctl start com.meshcore.meshcore_packet_capture")
        print("  Stop:    sudo launchctl stop com.meshcore.meshcore_packet_capture")
        print("  Status:  launchctl list | grep meshcore-packet-capture")
        print("  Logs:    tail -f /var/log/meshcore-packet-capture.log")

    print()
    print_success("Update complete!")
