"""Entry point: python3 -m installer <subcommand> [options]"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

from . import InstallerContext
from .system import require_root, resolve_install_ref
from .ui import print_error, print_info


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meshcore-packet-capture-installer",
        description="MeshCore Packet Capture installer",
    )
    parser.add_argument("--repo", default=os.environ.get("INSTALL_REPO", "agessaman/meshcore-packet-capture"))
    # No default branch: when neither --branch nor --tag is given, the latest
    # published release is installed (falling back to 'main'). An explicit branch
    # or tag pins the install for dev/CI.
    parser.add_argument(
        "--branch",
        default=os.environ.get("INSTALL_BRANCH") or os.environ.get("PACKETCAPTURE_BRANCH") or None,
    )
    parser.add_argument(
        "--tag",
        default=os.environ.get("INSTALL_TAG") or os.environ.get("PACKETCAPTURE_TAG") or None,
    )

    sub = parser.add_subparsers(dest="command")

    install_p = sub.add_parser("install", help="Fresh installation")
    install_p.add_argument("--config", dest="config_url", default="", help="URL to download 99-user.toml from")
    install_p.add_argument("--update", action="store_true", help="Non-interactive update mode")

    sub.add_parser("update", help="Update existing installation")

    sub.add_parser("migrate", help="Migrate legacy ~/.meshcore-packet-capture installation")

    return parser


def _dispatch(args: argparse.Namespace) -> None:
    require_root()

    local_install = os.environ.get("LOCAL_INSTALL", "")
    # If the bootstrap already resolved a ref, honor it verbatim so both download
    # passes agree; otherwise resolve here (explicit branch/tag, else latest release).
    ref_env = os.environ.get("INSTALL_REF")
    if ref_env:
        ref, ref_is_tag = ref_env, os.environ.get("INSTALL_REF_KIND") == "tags"
    else:
        ref, ref_is_tag = resolve_install_ref(
            args.repo, branch=args.branch, tag=args.tag, local_install=local_install,
        )

    ctx = InstallerContext(
        repo=args.repo,
        branch=ref,
        ref_is_tag=ref_is_tag,
        local_install=local_install,
    )

    if args.command == "install":
        ctx.config_url = args.config_url
        ctx.update_mode = args.update
        from .install_cmd import run_install
        run_install(ctx)

    elif args.command == "update":
        ctx.update_mode = True
        from .update_cmd import run_update
        run_update(ctx)

    elif args.command == "migrate":
        from .migrate_cmd import run_migrate
        if not run_migrate(ctx):
            print("No legacy installation found to migrate.")
            sys.exit(0)


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        _dispatch(args)
    except KeyboardInterrupt:
        print()
        print_error("Installation cancelled.")
        sys.exit(130)
    except subprocess.CalledProcessError as exc:
        cmd = exc.cmd
        if isinstance(cmd, (list, tuple)):
            cmd = " ".join(str(c) for c in cmd)
        print_error(f"Command failed (exit {exc.returncode}): {cmd}")
        if exc.stderr:
            print_info(str(exc.stderr).strip())
        print_info("Installation did not complete. Fix the issue above and re-run the installer.")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - surface a clean message, not a traceback
        print_error(f"Unexpected error: {exc}")
        print_info("Installation did not complete. Re-run the installer; if this persists, report the message above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
