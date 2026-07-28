#!/bin/bash
# ============================================================================
# MeshCore Packet Capture - Installer bootstrap
# Runs: python3 -m installer install
# ============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${MESHCORE_PACKET_CAPTURE_REPO:-${MESHCORE_PACKETCAPTURE_REPO:-${PACKETCAPTURE_REPO:-agessaman/meshcore-packet-capture}}}"
# Branch the bootstrap fetches the installer from (default: main = latest
# installer). The install *payload* defaults to the latest published release
# unless the user pins --branch/--tag (see installer.system.resolve_install_ref).
BRANCH="${MESHCORE_PACKET_CAPTURE_BRANCH:-${PACKETCAPTURE_BRANCH:-main}}"
BRANCH_EXPLICIT=false
if [ -n "${MESHCORE_PACKET_CAPTURE_BRANCH:-}" ] || [ -n "${PACKETCAPTURE_BRANCH:-}" ]; then
    BRANCH_EXPLICIT=true
fi
TAG=""
TAG_ARGS=()
USER_SERVICE=false
SHOW_HELP=false
REPO_DIR="$SCRIPT_DIR"
EXTRA_ARGS=()

print_usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --user-service        install a per-user systemd service from the local checkout
  --repo-dir PATH       local repository checkout path for --user-service
  --repo NAME/REPO      managed install repository (default: agessaman/meshcore-packet-capture)
  --branch NAME         managed install branch for the bootstrap fetch
  --tag TAG             managed install release tag for the bootstrap fetch
  --help                show help

Notes:
  - --user-service uses the local checkout's .venv and installs a user-level service.
  - Without --user-service this script performs the managed root installation path.
EOF
}

systemd_escape_unit_value() {
    local escaped="$1"
    if [[ "$escaped" =~ [[:cntrl:]] ]]; then
        echo "Error: systemd unit values cannot contain control characters" >&2
        return 1
    fi
    escaped=${escaped//\\/\\\\}
    escaped=${escaped//\"/\\\"}
    # A single percent starts systemd specifier expansion.
    escaped=${escaped//%/%%}
    printf '%s' "$escaped"
}

systemd_quote_unit_value() {
    printf '"%s"' "$(systemd_escape_unit_value "$1")"
}

systemd_quote_exec_arg() {
    local escaped
    escaped="$(systemd_escape_unit_value "$1")"
    # ExecStart performs environment expansion; $$ produces a literal dollar.
    escaped=${escaped//\$/\$\$}
    printf '"%s"' "$escaped"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h) SHOW_HELP=true; EXTRA_ARGS+=("$1"); shift ;;
        --user-service) USER_SERVICE=true; shift ;;
        --repo-dir) REPO_DIR="$2"; shift 2 ;;
        --repo)   REPO="$2"; shift 2 ;;
        --branch) BRANCH="$2"; BRANCH_EXPLICIT=true; shift 2 ;;
        --tag)    TAG="$2"; TAG_ARGS=("--tag" "$2"); shift 2 ;;
        *)        EXTRA_ARGS+=("$1"); shift ;;
    esac
done

if [ "$USER_SERVICE" = true ] && [ "$SHOW_HELP" = true ]; then
    print_usage
    exit 0
fi

if [ "$USER_SERVICE" = true ]; then
    if [[ "$REPO_DIR" =~ [[:cntrl:]] ]]; then
        echo "Error: repository path cannot contain control characters" >&2
        exit 1
    fi
    if [ ! -d "$REPO_DIR" ]; then
        echo "Error: repository directory not found: $REPO_DIR" >&2
        exit 1
    fi
    REPO_DIR="$(cd "$REPO_DIR" >/dev/null && pwd -P)"
    if [[ "$REPO_DIR" =~ [[:cntrl:]] ]]; then
        echo "Error: repository path cannot contain control characters" >&2
        exit 1
    fi
    if [ ! -f "$REPO_DIR/pyproject.toml" ]; then
        echo "Error: pyproject.toml not found in repo path: $REPO_DIR" >&2
        exit 1
    fi
    if [ ! -d "$REPO_DIR/.venv" ]; then
        echo "Creating venv: $REPO_DIR/.venv"
        python3 -m venv "$REPO_DIR/.venv"
    fi
    CONFIG_ARGS=()
    if [ -f "$REPO_DIR/config.toml" ]; then
        CONFIG_ARGS+=("--config" "$REPO_DIR/config.toml")
    fi
    if [ -d "$REPO_DIR/config.d" ]; then
        while IFS= read -r -d '' cfg; do
            CONFIG_ARGS+=("--config" "$cfg")
        done < <(find "$REPO_DIR/config.d" -maxdepth 1 -type f -name '*.toml' -print0 | sort -z)
    fi

    # Escape each argument so systemd keeps paths with spaces intact.
    CONFIG_ARGS_ESCAPED=()
    for arg in "${CONFIG_ARGS[@]}"; do
        if [[ "$arg" =~ [[:cntrl:]] ]]; then
            echo "Error: configuration paths cannot contain control characters" >&2
            exit 1
        fi
        CONFIG_ARGS_ESCAPED+=("$(systemd_quote_exec_arg "$arg")")
    done

    echo "Installing package from local checkout"
    "$REPO_DIR/.venv/bin/python" -m pip install --upgrade pip
    "$REPO_DIR/.venv/bin/python" -m pip install -e "$REPO_DIR"

    UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    UNIT_PATH="$UNIT_DIR/meshcore-packet-capture.service"
    WORKING_DIRECTORY="$(systemd_quote_unit_value "$REPO_DIR")"
    ENV_DIRECTORY="$(systemd_quote_unit_value "MESHCORE_PACKETCAPTURE_ENV_DIR=$REPO_DIR")"
    PYTHON_EXECUTABLE="$(systemd_quote_exec_arg "$REPO_DIR/.venv/bin/python")"

    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=MeshCore Packet Capture (user)
After=network-online.target bluetooth.target
Wants=network-online.target

[Service]
Type=exec
WorkingDirectory=$WORKING_DIRECTORY
Environment=$ENV_DIRECTORY
ExecStart=$PYTHON_EXECUTABLE -m meshcore_packet_capture ${CONFIG_ARGS_ESCAPED[*]}
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
EOF

    echo "Created unit: $UNIT_PATH"
    systemctl --user daemon-reload

    if systemctl --user is-active --quiet meshcore-packet-capture; then
        systemctl --user restart meshcore-packet-capture
    else
        systemctl --user enable --now meshcore-packet-capture
    fi

    echo
    echo "Done. Useful commands:"
    echo "  systemctl --user status meshcore-packet-capture"
    echo "  journalctl --user -u meshcore-packet-capture -f"
    exit 0
fi

# Ref the bootstrap downloads its installer copy from: an explicit branch wins,
# else a pinned tag, else main. (When none is pinned the Python installer
# resolves the latest release for the payload.)
BOOT_REF="$BRANCH"; BOOT_KIND="heads"
if [ "$BRANCH_EXPLICIT" != true ] && [ -n "$TAG" ]; then
    BOOT_REF="$TAG"; BOOT_KIND="tags"
fi

_needs_root=true
for arg in "${EXTRA_ARGS[@]}"; do
    [ "$arg" = "--help" ] || [ "$arg" = "-h" ] && _needs_root=false
done
if [ "$_needs_root" = true ] && [ "$(id -u)" -ne 0 ]; then
    # Only auto-escalate when this script is a real, readable file on disk. When
    # piped (curl | bash) or run via process substitution (bash <(curl ...)),
    # $0 points at a pipe/fd that sudo's closefrom() drops, so re-execing would
    # read an empty script. In that case tell the user exactly what to run.
    if [ -f "$0" ] && [ -r "$0" ]; then
        echo "This installer requires root privileges. Re-running with sudo..."
        exec sudo bash "$0" "$@"
    else
        echo "Error: This installer requires root privileges."
        echo
        echo "Re-run it under sudo, for example:"
        echo "  sudo bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/$REPO/$BRANCH/install.sh)\""
        exit 1
    fi
fi

if [ "$_needs_root" = true ] && [ ! -t 0 ]; then
    echo "Error: interactive installs cannot be run with 'curl | sudo bash'."
    echo
    echo "That form uses stdin for the script itself, which can prevent prompts from"
    echo "receiving your answers on some systems. Download the script first so stdin"
    echo "stays attached to your terminal:"
    echo
    echo "  tmp=\$(mktemp) && curl -fsSL https://raw.githubusercontent.com/$REPO/$BRANCH/install.sh -o \"\$tmp\" && sudo bash \"\$tmp\" --repo $REPO --branch $BRANCH; rm -f \"\$tmp\""
    exit 1
fi

# --- Dependency preflight ---------------------------------------------------
# Pick an available downloader (curl preferred, wget fallback).
DOWNLOADER=""
if command -v curl >/dev/null 2>&1; then
    DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
    DOWNLOADER="wget"
fi

download() {
    # download <url> <dest>
    if [ "$DOWNLOADER" = "curl" ]; then
        curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

print_install_hint() {
    # print_install_hint <packages...>
    if command -v apt-get >/dev/null 2>&1; then
        echo "Install them with: sudo apt-get update && sudo apt-get install -y $*"
    elif command -v dnf >/dev/null 2>&1; then
        echo "Install them with: sudo dnf install -y $*"
    elif command -v pacman >/dev/null 2>&1; then
        echo "Install them with: sudo pacman -Sy --noconfirm $*"
    elif command -v apk >/dev/null 2>&1; then
        echo "Install them with: sudo apk add $*"
    fi
}

if [ -z "$LOCAL_INSTALL" ]; then
    missing=()
    [ -z "$DOWNLOADER" ] && missing+=("curl (or wget)")
    command -v tar >/dev/null 2>&1 || missing+=("tar")
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "Error: missing required tool(s): ${missing[*]}"
        print_install_hint curl tar
        exit 1
    fi
fi

py_version=$(python3 -c 'import sys; v=sys.version_info; print(f"{v.major}.{v.minor}")' 2>/dev/null || true)
if [ -z "$py_version" ] || [ "$(printf '%s\n' "3.11" "$py_version" | sort -V | head -1)" != "3.11" ]; then
    echo "Error: Python 3.11+ required (found: ${py_version:-none})"
    case "$(uname -s)" in
        Darwin) echo "Install it with: brew install python@3.12" ;;
        *)      print_install_hint python3 ;;
    esac
    exit 1
fi

TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

if [ -n "$LOCAL_INSTALL" ]; then
    cp -r "$LOCAL_INSTALL/installer" "$TMP_DIR/installer"
else
    ARCHIVE_URL="https://github.com/$REPO/archive/refs/$BOOT_KIND/$BOOT_REF.tar.gz"
    echo "Downloading repository archive..."
    download "$ARCHIVE_URL" "$TMP_DIR/repo.tar.gz" || {
        echo "Error: Failed to download repository archive"; exit 1
    }
    tar -xzf "$TMP_DIR/repo.tar.gz" -C "$TMP_DIR" || {
        echo "Error: Failed to extract repository archive"; exit 1
    }
    rm -f "$TMP_DIR/repo.tar.gz"
    # The extracted dir name varies (tags drop a leading 'v'), so locate it.
    REPO_NAME=$(echo "$REPO" | cut -d'/' -f2)
    extracted_dir=$(find "$TMP_DIR" -maxdepth 1 -type d -name "$REPO_NAME-*" | head -1)
    if [ -z "$extracted_dir" ] || [ ! -d "$extracted_dir/installer" ]; then
        echo "Error: Could not locate installer in the downloaded archive"; exit 1
    fi
    cp -r "$extracted_dir/installer" "$TMP_DIR/installer"
fi

export INSTALL_REPO="$REPO"
# Only pin a branch for the Python layer when the user explicitly chose one;
# otherwise leave it unset so the installer resolves the latest release. A
# pinned --tag is forwarded via TAG_ARGS and placed before the install
# subcommand so argparse accepts it as a global option.
if [ "$BRANCH_EXPLICIT" = true ]; then
    export INSTALL_BRANCH="$BOOT_REF"
fi
cd "$TMP_DIR"
if [ "$_needs_root" != true ]; then
    python3 -m installer "${TAG_ARGS[@]}" install "${EXTRA_ARGS[@]}"
elif [ -r /dev/tty ]; then
    python3 -m installer "${TAG_ARGS[@]}" install "${EXTRA_ARGS[@]}" < /dev/tty
else
    python3 -m installer "${TAG_ARGS[@]}" install "${EXTRA_ARGS[@]}"
fi
