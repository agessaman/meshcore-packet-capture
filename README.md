# MeshCore Packet Capture

A standalone Python script for capturing and analyzing packets from **MeshCore Companion radios only**. The script connects to MeshCore Companion devices via Bluetooth Low Energy (BLE), serial, or TCP connection, captures incoming packets, and outputs structured data to console, file, and MQTT broker.

> **⚠️ IMPORTANT: This package is for Companion radios only!**
> 
> - **For Repeaters and RoomServers**: Use [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) instead
> - **For Companion radios**: Use this package (meshcore-packet-capture)

Based on the original [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) project by [Cisien](https://github.com/Cisien) and uses the official [meshcore](https://github.com/meshcore-dev/meshcore_py) Python package.

## Device Compatibility

### ✅ **Companion Radios** - Use this package
- **meshcore-packet-capture** is designed specifically for Companion radios
- Supports BLE, serial, and TCP connections
- Captures packets from Companion devices without the need for custom firmware

### ❌ **Repeaters and RoomServers** - Use meshcoretomqtt instead
- **Repeaters**: Use [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) for repeater packet capture
- **RoomServers**: Use [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) for roomserver packet capture
- These devices have different connection requirements and packet formats

## Quick Start

### Install as a managed service (recommended)

For a turnkey install that creates a service account, installs a systemd (Linux) or
launchd (macOS) unit, and writes config under `/etc`, use the bootstrap installer.
It installs system-wide (under `/opt` and `/etc`) and so must run as root:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/agessaman/meshcore-packet-capture/main/install.sh)"
```

> **macOS + BLE:** because macOS grants Bluetooth permission per-user (not to
> root daemons), a BLE install is set up as a per-user LaunchAgent that runs in
> your login session. Serial/TCP installs use a system LaunchDaemon.

### Windows (manual / development only)

Windows has no systemd/launchd integration, so `install.ps1` is a manual/dev-only
path: it installs files and a venv for a manual run (no auto-start service) and
writes configuration as a legacy `.env.local` file rather than the TOML
`config.d` model used on Linux/macOS. `.env.local` is still honored at runtime
(TOML config overrides it where present), so this is intentional. BLE support on
Windows is limited and currently untested — serial/TCP are the expected
transports there.

```powershell
.\install.ps1
```

### Uninstall
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/agessaman/meshcore-packet-capture/main/uninstall.sh)
```

## Features

- **Companion Radio Packet Capture**: Captures incoming packets from MeshCore Companion devices
- **Connection Types**: Supports BLE, serial, and TCP connections to Companion radios
- **Packet Analysis**: Parses packet headers, routes, payloads, and metadata
- **RF Data**: Captures signal quality metrics (SNR, RSSI)
- **Status Telemetry Stats**:  MQTT status messages optionally contain battery/uptime/radio metrics
- **Multi-Broker MQTT**: Supports any number of sequentially numbered MQTT brokers
- **Auth Token Authentication**: JWT-based authentication using device private key
- **TLS/WebSocket Support**: Secure connections with TLS/SSL and WebSocket transport
- **Topic Templates**: Per-broker topic templates
- **Device Information**: Includes model, firmware version, and radio configuration in status messages

## Requirements

- Python 3.11+ (installer and recommended runtime)
- `meshcore` package (official MeshCore Python library) version 2.3.8 or later (required for multi-byte path support, stats, serialised BLE writes, and the zero-hop anonymous requests the neighbors snapshot depends on)
- `paho-mqtt` package (for MQTT functionality)

**Note**: For Docker deployment, this application is best deployed on Linux systems due to Bluetooth Low Energy (BLE) and serial device access requirements. While Docker containers can run on macOS and Windows, BLE functionality may be limited or require additional configuration.

## Installation

### From a git checkout (CLI / manual use)

```bash
git clone https://github.com/agessaman/meshcore-packet-capture.git
cd meshcore-packet-capture
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
meshcore-packet-capture --help
```

This installs the `meshcore-packet-capture` command and its dependencies into a
local virtualenv. Use it for manual runs, development, or when you manage the
process yourself. For a system service, use the bootstrap installer (see
[Quick Start](#quick-start) and
[Managed-service installer](#managed-service-installer-linux-and-macos) below).

#### User service from a wheel or uv install (Linux)

The installed CLI can generate a user systemd unit without a repository checkout:

```bash
uv tool install "git+https://github.com/agessaman/meshcore-packet-capture"
case "${XDG_CONFIG_HOME:-}" in /*) ;; *) export XDG_CONFIG_HOME="$HOME/.config" ;; esac
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
meshcore-packet-capture --print-systemd-unit --user \
  > "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/meshcore-packet-capture.service"
systemd-analyze --user verify "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/meshcore-packet-capture.service"
systemctl --user daemon-reload
systemctl --user enable --now meshcore-packet-capture
```

Generation only prints the unit to stdout. It does not read config files, connect
to a radio, install a service, or start one. The unit uses the Python executable
from the CLI's installed environment, so no path edits are needed.

Put TOML configuration in
`${XDG_CONFIG_HOME:-$HOME/.config}/meshcore-packet-capture/config.toml` and
`config.d/*.toml`. The service enables `--user-config`, which overlays user TOML
on readable system config. New, edited, or removed config files take effect after
`systemctl --user restart meshcore-packet-capture` without regenerating the unit.

To select another directory, set `PACKETCAPTURE_CONFIG_DIR` during generation.
To select specific files instead, pass repeatable `--config PATH` arguments;
their order is preserved and relative paths are saved as absolute paths.
Capture options such as `--no-mqtt`, `--debug`, and `--output PATH` are also
saved in the generated command. Shell settings for `PACKETCAPTURE_CONFIG_DIR`,
`XDG_CONFIG_HOME`, and `MESHCORE_PACKETCAPTURE_ENV_DIR` are saved when explicitly
set; other `PACKETCAPTURE_*` settings should go in TOML or the service environment.
`--neighbors-now` and `--neighbors-exit` are manual actions and are rejected during
unit generation, because a restarting service would repeat their on-air work.

Without a selected checkout, runtime state defaults to
`${XDG_STATE_HOME:-$HOME/.local/state}/meshcore-packet-capture/`. The unit supplies
`PACKETCAPTURE_DEFAULT_DATA_DIR` as a fallback; `[capture] data_dir` in TOML takes
precedence. An explicitly set `PACKETCAPTURE_DATA_DIR` is saved in the unit and
overrides TOML. The capture process creates the state directory when saving state.
The working directory is the user's home, or the selected checkout when
`MESHCORE_PACKETCAPTURE_ENV_DIR` is set. Relative XDG directory values are ignored.
Generated services without a checkout pass `--no-env-files`, so unrelated
`~/.env` and `~/.env.local` cannot redirect their config or supply runtime settings.
To use legacy env files, explicitly select their directory with
`MESHCORE_PACKETCAPTURE_ENV_DIR` during generation.

Regenerate the unit and run `systemctl --user daemon-reload` followed by a restart
if the installed Python path or saved directory selections change. For startup
without logging in, enable lingering with `loginctl enable-linger "$USER"`
(this may require administrator authorization). Radio access still requires the
user's normal serial-device or Bluetooth permissions.

Only `--print-systemd-unit --user` is supported. System services use the managed
installer, which sets up the service account and permissions.

#### User service from a local checkout (Linux)

For a local checkout on Linux, `./install.sh --user-service` will create a per-user
systemd service that runs from the repo's `.venv`. Pass `--repo-dir PATH` if the checkout
is not the current script directory.

To remove that user service, run `./uninstall.sh --user-service` from the same checkout.
Add `--remove-venv` if you also want the local `.venv` deleted.

When using `--user-service`, keep your config files in the repo itself:

```text
meshcore-packet-capture/
  .env
  .env.local
  config.toml
  config.d/
    10-base.toml
    99-user.toml
```

The user-service path loads `.env` and `.env.local` from the repo root. It discovers
`config.toml` and every `config.d/*.toml` file in sorted order at each startup, so
new files take effect after `systemctl --user restart meshcore-packet-capture`.
The checkout remains the selected TOML tree even when it is empty. It never
falls through to system or XDG TOML when files are added or removed; a missing
checkout directory fails startup. Legacy env files are confined to the repo root.

To select a different TOML tree, set `PACKETCAPTURE_CONFIG_DIR` when installing
the user service; the installer saves it in the generated unit:

```bash
mkdir -p "$HOME/.config/meshcore-packet-capture/config.d"
PACKETCAPTURE_CONFIG_DIR="$HOME/.config/meshcore-packet-capture" ./install.sh --user-service
```

The installer also saves an explicitly set `XDG_CONFIG_HOME`. Changing these
variables in your shell later does not change an installed unit; rerun the
installer or edit its service environment and run `systemctl --user daemon-reload`.

The checkout installer uses the CLI renderer above. Without an explicit data
directory in TOML, legacy env files, or the unit environment, checkout services
retain the legacy state location beside the package (its `data/` subdirectory
when present). This preserves existing advert and neighbor schedule timestamps.

**Existing user services:** rerun `./install.sh --user-service` once after
upgrading to replace the old fixed `--config` file list with startup discovery.
The selected tree now loads every future `config.d/*.toml` file, so only put
finished, trusted configuration there. Use explicit `--config` arguments with
the CLI generator if you need a fixed file list. If you previously generated a
unit that set the XDG state directory, retain that location with `[capture]
`data_dir` or `PACKETCAPTURE_DATA_DIR` before regenerating, or copy its
`advert_state.json` to your chosen directory while the service is stopped.
Moving state without preserving that file resets advert and neighbor timers.

### Docker Installation

The project includes Docker support for easy deployment:

```bash
# Build the Docker image
docker build -t meshcore-capture .

# Run with Docker Compose (recommended)
docker-compose up -d

# Or run directly with Docker
docker run --privileged --device=/dev/ttyUSB0 \
  -v $(pwd)/data:/app/data \
  -e PACKETCAPTURE_CONNECTION_TYPE=serial \
  meshcore-capture
```

See the [Docker Deployment](#docker-deployment) section below for detailed instructions.

## Configuration

**TOML under `/etc/meshcore-packet-capture/` is the primary configuration source**, matching [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt). Configuration is resolved with this precedence (highest first):

1. **Process environment** — `PACKETCAPTURE_*` variables already set in the environment (e.g. from a systemd unit, Docker `-e`, or your shell) always win.
2. **TOML**: `/etc/meshcore-packet-capture/config.toml` plus every `*.toml` in `/etc/meshcore-packet-capture/config.d/` (sorted). Broker entries use the same `[[broker]]` shape as meshcoretomqtt. See `config.toml.example` and bundled `presets/letsmesh.toml` (LetsMesh Packet Analyzer defaults). With **`--config PATH`** (repeatable) only those files are merged, in order, and the automatic `/etc` scan is skipped.
3. **Legacy `.env` / `.env.local`** (see below) — a development/manual-install convenience. An explicit `MESHCORE_PACKETCAPTURE_ENV_DIR` selects only that directory; otherwise the first directory with env files among the working directory, repo root, and package directory is used. `--no-env-files` skips them. These are overridden by TOML, so they only take effect for keys the TOML config does not set.

Values are applied as `PACKETCAPTURE_*` environment variables. See `config.toml.example` for every TOML key, or `.env` for the equivalent flat variable names.

### Selecting a TOML configuration tree

TOML sources are selected in this order:

1. Repeatable `--config PATH` loads only the listed files, in order, regardless
   of directory variables or user discovery.
2. A non-empty `PACKETCAPTURE_CONFIG_DIR` loads only that directory's
   `config.toml` and sorted `config.d/*.toml`. It does not merge `/etc` or XDG
   config. `~` is expanded; relative paths resolve against the working directory
   (the user-service installer saves them as absolute paths). A missing directory
   or a path pointing to a file fails startup. An existing empty directory is
   allowed; it supplies no TOML settings. Empty or whitespace-only values leave
   default discovery enabled.
3. With `--user-config`, a non-empty `MESHCORE_PACKETCAPTURE_ENV_DIR` selects
   only that checkout tree, even when it contains no TOML. Surrounding whitespace
   is stripped. A missing or non-directory checkout fails startup.
   Without that selector, `/etc/meshcore-packet-capture/`
   is loaded first and the user tree is overlaid. The user tree is
   `$XDG_CONFIG_HOME/meshcore-packet-capture/` when `XDG_CONFIG_HOME` is absolute;
   otherwise it is `~/.config/meshcore-packet-capture/`.
4. Without `--user-config`, default discovery uses only `/etc/meshcore-packet-capture/`.

The checkout user-service installer enables `--user-config`. Manual CLI users
can opt in with `meshcore-packet-capture --user-config`. Managed Linux/macOS
services keep their existing system-only discovery. The managed installer, BLE
cleanup helper, and uninstaller continue using `/etc`; the new variable selects
runtime TOML sources rather than relocating managed installation files.

User overlays merge brokers by name: unmatched system brokers remain configured.
In user-discovery mode with readable user TOML present, a permission error reading
any system file or listing its directory discards the entire system config layer
with a warning. Only user TOML is used, so a skipped disabling override cannot
leave an earlier system broker enabled. Ensure your user TOML supplies all the
settings it needs. Without user TOML, system permission failures stop startup.
Unreadable explicit files, selected-tree files, and user-tree files still fail
startup. Malformed TOML is never skipped when read, and a `config.d` path that is
a file fails startup in every mode.
Use `enabled = false` on a matching broker to disable it, or select an isolated
tree with `PACKETCAPTURE_CONFIG_DIR` to exclude system TOML entirely.
Process-environment precedence still applies in all modes; legacy env loading
applies unless `--no-env-files` is set.
Matching TOML files are read at startup, so malformed new files prevent startup;
the error log identifies the file. Keep unfinished files outside `config.d` or
use a suffix other than `.toml` until they are ready.

### Managed-service installer (Linux and macOS)

Use the bootstrap installer when you want a systemwide managed background service
rather than just the CLI: it installs under `/opt/meshcore-packet-capture`, writes
configuration under `/etc/meshcore-packet-capture`, creates a Linux service
account, and installs a systemd (Linux) or launchd (macOS) unit. During setup it
also configures the Companion connection (BLE, serial, or TCP) and offers bundled
broker presets (default selection: LetsMesh).

From a repo checkout (requires root):

```bash
export LOCAL_INSTALL=/path/to/meshcore-packet-capture
sudo bash install.sh
```

Or bootstrap via curl (downloads the installer and runs `python3 -m installer install`).

#### Choosing what to install (version pinning)

By default the installer installs the **latest published GitHub Release**, so you
get a stable, tagged version rather than the moving branch tip. (If the project
has no releases yet, it falls back to the `main` branch.) You can override this:

```bash
sudo bash install.sh --tag v2.2.1      # pin to a specific release
sudo bash install.sh --branch main     # track a branch (development)
```

`update` resolves the latest release the same way and reports the
installed-versus-target version before applying it.

The same choices can be made with environment variables. See
[Installer environment variables](#installer-environment-variables). `install.sh`
re-execs under `sudo` when it is not already root, which drops the environment,
so the flags above are the reliable form.

#### Installer environment variables

These variables are read by the installer. They do not affect a capture process
that is already running.

`install.sh` re-execs with `sudo` when it is not already root, and that drops
the environment. `--repo`, `--branch`, and `--tag` survive because they are
arguments. To use the variables, start the installer in an environment that
still has them, for example `sudo env PACKETCAPTURE_BRANCH=dev bash install.sh`,
or run `python3 -m installer` as root.

`install.sh` selects the installer code it runs. `python3 -m installer` selects
the files that get installed. `--branch`, `MESHCORE_PACKET_CAPTURE_BRANCH`, and
`PACKETCAPTURE_BRANCH` apply to both layers. `INSTALL_BRANCH`, `INSTALL_TAG`,
and `PACKETCAPTURE_TAG` are read only by the Python installer. Through
`install.sh`, pin a release with `--tag`. Without that flag, the bootstrap still
downloads its installer from `main`, or from an explicit branch.

Bootstrap (`install.sh`):

- `MESHCORE_PACKET_CAPTURE_REPO`, otherwise `MESHCORE_PACKETCAPTURE_REPO`, otherwise `PACKETCAPTURE_REPO`: GitHub repository as `owner/name`. Default: `agessaman/meshcore-packet-capture`. `--repo` overrides this.
- `MESHCORE_PACKET_CAPTURE_BRANCH`, otherwise `PACKETCAPTURE_BRANCH`: branch the bootstrap downloads. Default: `main`. Setting either variable, or passing `--branch`, also exports `INSTALL_BRANCH`, so the installed files are that branch rather than the latest release.
- `LOCAL_INSTALL`: path to a checkout. The bootstrap copies `installer/` from that directory instead of downloading an archive. The Python installer then installs that same directory. See the checkout example above.

Python installer (`python3 -m installer`):

- `INSTALL_REPO`: default for `--repo`. `install.sh` always exports the repository it resolved.
- `INSTALL_BRANCH`, or `PACKETCAPTURE_BRANCH` when `INSTALL_BRANCH` is unset: default for `--branch`.
- `INSTALL_TAG`, or `PACKETCAPTURE_TAG` when `INSTALL_TAG` is unset: default for `--tag`.
- `INSTALL_REF`: when set and non-empty, this git ref is used and the latest-release lookup is skipped.
- `INSTALL_REF_KIND`: the exact value `tags` means `INSTALL_REF` is a release tag. Any other value, including unset, fetches it as a branch.
- `LOCAL_INSTALL`: install this directory and skip the release lookup. A branch or tag set at the same time does not replace that tree.
- `INSTALL_REBUILD_VENV`: any non-empty value deletes the install virtualenv and creates it again. `0` and `false` still rebuild. When the variable is unset or empty, an existing virtualenv is kept if `meshcore`, `paho.mqtt.client`, and `bleak` import.

When `INSTALL_REF` is unset and `LOCAL_INSTALL` is unset, the installed ref is
chosen in this order: an explicit branch, an explicit tag, the latest published
GitHub release, then `main`. An explicit branch wins over an explicit tag,
including a branch left in the environment while `--tag` is passed.

`install.sh` does not set `INSTALL_REF` or `INSTALL_REF_KIND`. Those two are for
a direct `python3 -m installer` run that has already chosen the ref.

#### Upgrading legacy service installs

Older installers placed the app and `.env.local` configuration under
`~/.meshcore-packet-capture` and created a `meshcore-capture.service` unit. Run the
managed-service installer to upgrade that layout. It detects the legacy directory,
converts `.env` / `.env.local` into
`/etc/meshcore-packet-capture/config.d/99-user.toml`, stops and removes the old
service unit after the TOML file is written, then continues with the new
systemwide `/opt` install.

The old `~/.meshcore-packet-capture` directory is left in place for rollback or
manual cleanup. Standalone `python3 -m installer migrate` only migrates
configuration and service units; use the full installer when you want the new
application files and service installed too.

### Legacy environment files (local development)

For development and manual installs, two flat key/value files are still read from the
working directory (repo root, `/opt/meshcore-packet-capture`, or `/app` in Docker):

1. `.env` - Default configuration (committed to repository)
2. `.env.local` - Local overrides (not committed, for your specific setup; `.env.local` wins over `.env`)

Capture settings use the `PACKETCAPTURE_` prefix. `AUTH_TOKEN_METHOD`,
`AUTH_TOKEN_DEVICE_ONLY`, and `DEBUG_DEVICE_SIGNING` are copied through under
those names. See [Authentication Methods](#authentication-methods). The files
are **legacy**: TOML config under `/etc/meshcore-packet-capture/` takes
precedence over them. For service installs, configure via TOML
(`config.d/99-user.toml`) instead.

### Configuration Variables

For systemd installs, prefer editing `/etc/meshcore-packet-capture/config.d/99-user.toml`. Legacy `~/.meshcore-packet-capture` installs can be migrated with `sudo python3 -m installer migrate` from a checkout.

### Unit tests

```bash
pip install -r requirements-dev.txt
pytest
```

Tests live under `tests/`. Legacy experiments belong in `old/` (gitignored). Optional developer scripts are in `devtools/`.


### Environment Variables

#### Connection Settings
- `PACKETCAPTURE_CONNECTION_TYPE`: `ble`, `serial`, or `tcp`
- `PACKETCAPTURE_BLE_ADDRESS`: Specific BLE device address (optional)
- `PACKETCAPTURE_BLE_DEVICE_NAME`: BLE device name to scan for (optional)
- `PACKETCAPTURE_BLE_PIN`: Six-digit PIN used for BLE connection authentication (optional)
- `PACKETCAPTURE_SERIAL_PORTS`: Comma-separated list of serial ports to try
- `PACKETCAPTURE_TCP_HOST`: TCP host address (default: localhost)
- `PACKETCAPTURE_TCP_PORT`: TCP port number (default: 5000)
- `PACKETCAPTURE_TIMEOUT`: Connection timeout in seconds
- `PACKETCAPTURE_MAX_CONNECTION_RETRIES`: Maximum MeshCore connection retry attempts (0 = infinite)
- `PACKETCAPTURE_CONNECTION_RETRY_DELAY`: Delay between MeshCore reconnection attempts (seconds)
- `PACKETCAPTURE_HEALTH_CHECK_INTERVAL`: How often to check connection health (seconds)
- `PACKETCAPTURE_DRAIN_MESSAGES`: When `true` (default), run meshcore auto message fetch so the device message queue is drained; set to `false` for RF packet capture only without pulling stored messages

#### Logging Settings
- `PACKETCAPTURE_LOG_LEVEL`: Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) - default: `INFO`
  - Command line arguments (`--debug`, `--verbose`) override this setting

#### Status Telemetry / Stats
- `PACKETCAPTURE_STATS_IN_STATUS_ENABLED`: Toggle stat collection in status payloads (default: `true`)
- `PACKETCAPTURE_STATS_REFRESH_INTERVAL`: Seconds between stat refreshes/status republishes (default: `300`, i.e. 5 minutes)

When enabled, status messages published to MQTT include a `stats` object with battery, uptime, queue depth, and radio runtime metrics refreshed at the configured cadence.

#### MQTT Settings
Brokers are discovered sequentially starting at `MQTT1` and continue until `PACKETCAPTURE_MQTT<n>_ENABLED` is no longer defined — there is no fixed upper limit. (Via TOML, add as many `[[broker]]` blocks as you need; they are flattened to these `MQTT<n>_*` variables.) Each broker can be configured independently:

**Broker 1 (Primary):**
- `PACKETCAPTURE_MQTT1_ENABLED`: Enable/disable MQTT broker 1
- `PACKETCAPTURE_MQTT1_NAME`: Optional human-readable broker label for logs (TOML `[[broker]]` `name` is exported automatically; when unset, logs use `SERVER`)
- `PACKETCAPTURE_MQTT1_SERVER`: MQTT broker address
- `PACKETCAPTURE_MQTT1_PORT`: MQTT broker port
- `PACKETCAPTURE_MQTT1_USERNAME`/`PACKETCAPTURE_MQTT1_PASSWORD`: Authentication credentials
- `PACKETCAPTURE_MQTT1_TRANSPORT`: Transport type (`tcp` or `websockets`)
- `PACKETCAPTURE_MQTT1_WEBSOCKET_PATH`: WebSocket endpoint path (default: `/`)
- `PACKETCAPTURE_MQTT1_USE_TLS`: Enable TLS/SSL encryption
- `PACKETCAPTURE_MQTT1_TLS_VERIFY`: Verify TLS certificates (default: true)
- `PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN`: Use auth token authentication
- `PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE`: Token audience for auth token
- `PACKETCAPTURE_MQTT1_CLIENT_ID_PREFIX`: Client ID prefix
- `PACKETCAPTURE_MQTT1_QOS`: Quality of Service level
- `PACKETCAPTURE_MQTT1_RETAIN`: Retain messages
- `PACKETCAPTURE_MQTT1_KEEPALIVE`: Keep-alive interval

**Additional brokers:** Use the same pattern with `MQTT2_`, `MQTT3_`, and higher sequential prefixes as needed

**Global MQTT Settings:**
- `PACKETCAPTURE_MAX_MQTT_RETRIES`: Maximum MQTT connection retry attempts (0 = infinite)
- `PACKETCAPTURE_MQTT_RETRY_DELAY`: Delay between MQTT reconnection attempts (seconds)
- `PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL`: Exit when reconnection attempts fail (default: true)

**Private Key Settings:**
- `PACKETCAPTURE_PRIVATE_KEY`: Device private key for auth token authentication (hex string)
- `PACKETCAPTURE_PRIVATE_KEY_FILE`: Path to file containing device private key
- `AUTH_TOKEN_METHOD`: `device` (default), `python`, or `meshcore-decoder`. No `PACKETCAPTURE_` prefix. See [Authentication Methods](#authentication-methods).
- `AUTH_TOKEN_DEVICE_ONLY`: set to `true` to disable the private-key fallback. No `PACKETCAPTURE_` prefix.
- `DEBUG_DEVICE_SIGNING`: set to `true` to use the manual on-device signing sequence. Troubleshooting only.

**Note**: Private keys can be provided via environment variable, file path, or `.env.local` file.

#### Topic Templates
Topics support template variables:
- `{IATA}`: Replaced with your IATA code in uppercase (e.g., "SEA")
- `{IATA_lower}`: Replaced with your IATA code in lowercase (e.g., "sea")
- `{PUBLIC_KEY}`: Replaced with device public key

Examples:
- `meshcore/{IATA}/packets` becomes `meshcore/SEA/packets`
- `meshcore/{IATA_lower}/packets` becomes `meshcore/sea/packets`

#### Per-Broker Topic Overrides
Topics can be set globally (under `[topics]`) or overridden per broker. A broker's own
topic takes precedence over the global value; brokers without an override fall back to
the global topic. The same template variables apply.

In TOML, set them under the broker's `[broker.topics]` table:
```toml
[[broker]]
name = "analyzer"
enabled = true
server = "mqtt.example.com"

[broker.topics]
# This broker's packets go to a custom topic; status/raw fall back to [topics].
packets = "custom/{IATA}/{PUBLIC_KEY}/packets"

[topics]
packets = "meshcore/{IATA}/{PUBLIC_KEY}/packets"
status  = "meshcore/{IATA}/{PUBLIC_KEY}/status"
```
These flatten to `PACKETCAPTURE_MQTT<n>_TOPIC_<NAME>` (per broker) and
`PACKETCAPTURE_TOPIC_<NAME>` (global fallback) — supported names: `STATUS`,
`PACKETS`, `DECODED`, `DEBUG`, `RAW`, `NEIGHBORS`.

#### Authentication Methods

**Username/Password Authentication:**
```bash
PACKETCAPTURE_MQTT1_USERNAME=your_username
PACKETCAPTURE_MQTT1_PASSWORD=your_password
```

**Auth Token Authentication (JWT):**
```bash
PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE=mqtt.example.com
PACKETCAPTURE_PRIVATE_KEY=your_private_key_here
# OR
PACKETCAPTURE_PRIVATE_KEY_FILE=/path/to/private_key_file
```

With a connected radio, the token is signed on the device and the private key
is not required. The private key is the fallback when on-device signing is
unavailable or fails, and it is required for the `python` and
`meshcore-decoder` methods below.

`AUTH_TOKEN_METHOD` and `AUTH_TOKEN_DEVICE_ONLY` have no `PACKETCAPTURE_`
prefix. TOML export only writes `PACKETCAPTURE_*` keys, so it cannot set them,
and `--print-systemd-unit` does not copy them into the unit. Set them in the
process environment (a systemd `Environment=` line, Docker `-e`, or the shell)
or in `.env` / `.env.local`. A value already in the environment wins over those
files. Generated user units pass `--no-env-files` unless
`MESHCORE_PACKETCAPTURE_ENV_DIR` was set when the unit was generated, so a wheel
or uv install needs these variables on the unit itself.

`AUTH_TOKEN_METHOD` is compared after lowercasing, and surrounding whitespace is
ignored:

- Unset, empty, or `device`: sign on the connected radio. This is the default.
- `python`: sign with PyNaCl using the device private key. The radio is not asked.
- `meshcore-decoder`: sign with the `meshcore-decoder` command, or with the `@michaelhart/meshcore-decoder` Node module when that command is not on `PATH`. This requires the private key, and the key is passed to that tool. The radio is not asked.

Any other value is treated as `device`.

If on-device signing fails and `AUTH_TOKEN_METHOD` is unset, capture loads
`PACKETCAPTURE_PRIVATE_KEY` or `PACKETCAPTURE_PRIVATE_KEY_FILE`. If those are
unset it tries to export the key from the radio, then signs with PyNaCl.
`AUTH_TOKEN_DEVICE_ONLY=true` turns that fallback off, and token creation fails
instead of using a private key. Only the word `true` enables it (any case,
surrounding whitespace ignored). `1` and `yes` leave the fallback on.

Leave `AUTH_TOKEN_DEVICE_ONLY` unset when `AUTH_TOKEN_METHOD` is `python` or
`meshcore-decoder`. Those methods never sign on the radio, so device-only mode
rejects the token before the private key is used.

`DEBUG_DEVICE_SIGNING=true` is for signing failures, not normal configuration.
The value must be `true` ignoring case, with no extra whitespace (unlike
`AUTH_TOKEN_DEVICE_ONLY`, surrounding spaces are not stripped). It applies only
while signing on the radio: the library `sign()` call is replaced by
`sign_start`, `sign_data`, and `sign_finish`, and that sequence is logged at
DEBUG, including the bytes sent to the radio and the signature that comes back.
The replacement happens even when the log level hides those lines. Use `--debug`
or `PACKETCAPTURE_LOG_LEVEL=DEBUG` to see them. Leave the variable unset
otherwise.

Optional owner identification links your observer to your MeshCore account in
broker dashboards. Set a global default under `[capture]` or override per broker:

```toml
[capture]
owner_public_key = "64_hex_char_public_key"
owner_email = "you@example.com"

[[broker]]
name = "meshmapper"

[broker.auth]
method = "token"
email = "meshmapper-alias@example.com"   # overrides capture.owner_email for this broker
```

Environment equivalents: `PACKETCAPTURE_OWNER_EMAIL` (global fallback) and
`PACKETCAPTURE_MQTT<n>_TOKEN_EMAIL` / `PACKETCAPTURE_MQTT<n>_TOKEN_OWNER`
(per-broker overrides).

**Transport Options:**
- `tcp`: Standard TCP connection
- `websockets`: WebSocket connection (useful for web applications)

**TLS/SSL Security:**
```bash
PACKETCAPTURE_MQTT1_USE_TLS=true
PACKETCAPTURE_MQTT1_TLS_VERIFY=true  # Verify certificates
```

#### Exit Behavior

The script handles MQTT disconnections by continuing to run and attempting reconnection. On reconnection failure, it exits after maximum retry attempts (configurable).

For BLE connections where disconnections may be transient:

```bash
# Exit when reconnection attempts fail (recommended for BLE)
PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL=true

# Never exit, keep trying indefinitely
PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL=false
PACKETCAPTURE_MAX_MQTT_RETRIES=0
```

#### Advert Settings
- `PACKETCAPTURE_ADVERT_INTERVAL_HOURS`: Send flood adverts at this interval (0 = disabled, default = 47 hours)

#### Packet Type Filtering
- `PACKETCAPTURE_UPLOAD_PACKET_TYPES`: Comma-separated list of packet type numbers to upload to MQTT (default: upload all types)

This setting allows you to filter which packet types are uploaded to MQTT brokers. Packets are still captured and written to files/console, but only specified packet types will be uploaded to MQTT.

**Available Packet Types:**
- `0` = REQ (Request)
- `1` = RESPONSE
- `2` = TXT_MSG (Text Message)
- `3` = ACK (Acknowledgment)
- `4` = ADVERT (Advertisement)
- `5` = GRP_TXT (Group Text)
- `6` = GRP_DATA (Group Data)
- `7` = ANON_REQ (Anonymous Request)
- `8` = PATH
- `9` = TRACE
- `10` = MULTIPART
- `11` = CONTROL
- `12-14` = Reserved
- `15` = RAW_CUSTOM

**Examples:**
```bash
# Upload only text messages and advertisements
PACKETCAPTURE_UPLOAD_PACKET_TYPES=2,4

# Upload only requests, responses, and text messages
PACKETCAPTURE_UPLOAD_PACKET_TYPES=0,1,2

# Upload all types (default behavior - leave unset or empty)
# PACKETCAPTURE_UPLOAD_PACKET_TYPES=
```

**Note:** If this setting is not configured or is empty, all packet types will be uploaded.

#### Passive Payload Decoding

Payload decoding operates on captured RF packets; it does not fetch or drain the
companion's message queue. When enabled it adds a nested `decoded` object to packet
output:

- `GRP_TXT` channel messages are authenticated and decrypted when a matching
  16-byte channel key is configured.
- `ADVERT` packets expose structured public-key, role, location, feature, and name
  fields when present.
- Direct `TXT_MSG` packets remain encrypted because a passive observer does not
  have the sender/recipient ECDH session key.

Decoding and MQTT disclosure are separate controls. Decoded data is always present
in local/console packet output when `decode_payloads` is enabled, but is removed from
MQTT packet payloads by default. Opt in globally with `include_decoded`, or only for
specific trusted brokers:

```toml
[capture]
decode_payloads = true
include_decoded = false
decode_hashtag_channels = ["bot", "weather"]
decode_channel_keys = "private=00112233445566778899aabbccddeeff"
decode_include_public = true

[[broker]]
name = "trusted"
include_decoded = true
```

Custom channel keys may be 32-character hex or base64. Treat them as secrets and
protect the containing TOML or environment file accordingly. See
`config.toml.example` for TOML settings and `.env` for environment-variable
equivalents.

#### Packet Log Rotation

`--output PATH` normally truncates `PATH` when the process starts, matching the
original behavior. Optional size- or time-based rotation retains previous logs:

```toml
[capture]
log_rotation = "size"       # off | size | time
log_max_bytes = "50MB"      # size mode
log_rotation_when = "midnight" # time mode: midnight, H, D, W0-W6
log_backup_count = 5
```

## Usage

### Local Usage

```bash
# Basic usage (after: pip install -e .  or  PYTHONPATH=src)
python -m meshcore_packet_capture

# From repo root without install:
python packet_capture.py

# Save output to file
python -m meshcore_packet_capture --output packets.json

# Disable MQTT publishing
python -m meshcore_packet_capture --no-mqtt

# Verbose / debug
python -m meshcore_packet_capture --verbose
python -m meshcore_packet_capture --debug
```

## Docker Deployment

The project includes Docker support for deployment.

### Prerequisites

- Docker and Docker Compose installed
- Linux host system (recommended for BLE support)

### Quick Start with Docker Compose

1. **Clone and configure**:
   ```bash
   git clone <repository-url>
   cd meshcore-packet-capture
   ```

2. **Configure** (optional): edit the `environment:` block in `docker-compose.yml`
   (the recommended approach — `PACKETCAPTURE_*` variables), or bind-mount a TOML
   config directory at `/etc/meshcore-packet-capture` (uncomment the
   `./meshcore-etc:/etc/meshcore-packet-capture:ro` volume). A legacy `.env.local`
   bind-mount is also supported — copy the committed `.env` as a starting point:
   ```bash
   cp .env .env.local
   # Edit .env.local with your configuration
   ```

3. **Start the service**:
   ```bash
   docker-compose up -d
   ```

4. **View logs**:
   ```bash
   docker-compose logs -f meshcore-capture
   ```

### Docker Compose Configuration

The `docker-compose.yml` file includes privileged mode for device access, volume mounts for data storage, and environment variable configuration.

### Manual Docker Commands

```bash
# Build the image
docker build -t meshcore-capture .

# Run with BLE connection
docker run --privileged \
  -v $(pwd)/data:/app/data \
  -e PACKETCAPTURE_CONNECTION_TYPE=ble \
  -e PACKETCAPTURE_MQTT1_SERVER=your-mqtt-broker \
  meshcore-capture

# Run with serial connection
docker run --privileged \
  --device=/dev/ttyUSB0:/dev/ttyUSB0 \
  -v $(pwd)/data:/app/data \
  -e PACKETCAPTURE_CONNECTION_TYPE=serial \
  -e PACKETCAPTURE_SERIAL_PORTS=/dev/ttyUSB0 \
  meshcore-capture

# Run with TCP connection
docker run \
  -v $(pwd)/data:/app/data \
  -e PACKETCAPTURE_CONNECTION_TYPE=tcp \
  -e PACKETCAPTURE_TCP_HOST=your-tcp-server \
  -e PACKETCAPTURE_TCP_PORT=5000 \
  meshcore-capture
```

### Configuration in Docker

Configuration can be provided three ways, in precedence order: `PACKETCAPTURE_*`
environment variables (`-e` / the compose `environment:` block) win, then a
volume-mounted TOML config at `/etc/meshcore-packet-capture` (recommended for
non-trivial setups), then a legacy volume-mounted `.env.local`.

### Platform Considerations

- **Linux**: Full BLE and serial support
- **macOS**: Full BLE and serial support, limited BLE support in containers
- **Windows**: Limited BLE support (currently untested), serial connections work with proper device mounting

### Troubleshooting Docker Deployment

**BLE Connection Issues**:
```bash
# Try host networking for BLE discovery
docker run --privileged --network=host meshcore-capture
```

**Serial Device Access**:
```bash
# Ensure device permissions
sudo chmod 666 /dev/ttyUSB0
# Or add user to dialout group
sudo usermod -a -G dialout $USER
```

**MQTT Connection Issues**:
```bash
# Check network connectivity
docker exec -it meshcore-capture ping mqtt-broker
# View container logs
docker logs meshcore-capture
```

## Output Levels

The script supports three output levels:

- **Normal (default)**: Shows minimal packet info line only
- **--verbose**: Adds JSON packet data output  
- **--debug**: Adds all detailed debugging information

## Output Format

Captured packets are output in JSON format with the following structure:

```json
{
  "origin": "Device Name",
  "origin_id": "device_public_key",
  "timestamp": "2024-01-01T12:00:00.000000",
  "type": "PACKET",
  "direction": "rx",
  "time": "12:00:00",
  "date": "01/01/2024",
  "len": "45",
  "packet_type": "4",
  "route": "F",
  "payload_len": "32",
  "raw": "F5930103807E5F1EDE680070B9F3FCF238AA6B64BDEA8B4FDC4E2A",
  "SNR": "12.5",
  "RSSI": "-65",
  "hash": "A1B2C3D4E5F67890"
}
```

## MQTT Topics

Default topic templates (from the shipped `config.toml`):

- `meshcore/{IATA}/{PUBLIC_KEY}/status`: Device online/offline status (plus optional stats)
- `meshcore/{IATA}/{PUBLIC_KEY}/packets`: Full packet data
- `meshcore/{IATA}/{PUBLIC_KEY}/raw`: Raw packet data (commented out by default; enable it for e.g. map.w0z.is)
- `meshcore/{IATA}/{PUBLIC_KEY}/neighbors`: Periodic neighbor snapshot (off by default; see [Neighbors Publishing](#neighbors-publishing))

These are configurable globally or per broker — see [Topic Templates](#topic-templates)
and [Per-Broker Topic Overrides](#per-broker-topic-overrides). The classic flat form
(`meshcore/status`, `meshcore/packets`, `meshcore/raw`) still works if you set the
topics explicitly.

## Neighbors Publishing

A port of the observer firmware's neighbors feature. On a long interval the tool asks
which repeaters it can hear directly, then asks each one for its region scopes, and
publishes the result to the `neighbors` topic. **Off by default.**

Enable it per broker, since not every broker accepts this topic:

```toml
[[broker]]
name = "analyzer"
enabled = true
server = "mqtt.example.com"
neighbors = true          # opt this broker in

[capture]
neighbors_interval_hours = 24   # clamped to 12-336
```

The topic needs an IATA code (or an explicit `[broker.topics] neighbors` template) —
there is no flat `meshcore/neighbors` fallback, matching the firmware, which only routes
this topic in MeshCore form. Payloads are published non-retained.

Each cycle runs two stages: a zero-hop node-discover collecting responses for
`neighbors_discover_window` seconds, then one scope request per neighbor. Those requests
go out **one at a time** — issuing them together makes the replies collide on air. Each
wait defaults to the device's own airtime estimate (`neighbors_scope_timeout = 0`), with
`neighbors_scope_gap` seconds between requests and `neighbors_cycle_timeout` bounding the
whole pass. Neighbors are queried most-recently-heard first, so a truncated cycle still
covers the most useful ones. See `config.toml.example` for every knob.

```json
{
  "timestamp": "2024-01-01T12:00:00.000000+00:00",
  "origin": "MeshCore-HOWL",
  "origin_id": "A1B2C3D4E5F67890...",
  "total_neighbors": 6,
  "queried_neighbors": 6,
  "truncated": false,
  "self": { "scopes": "DEN,APRS" },
  "neighbors": [
    {
      "pubkey": "0011223344556677...",
      "snr": 9.75,
      "heard_secs_ago": 42,
      "scopes": "DEN,APRS",
      "status": "responded"
    }
  ]
}
```

### Triggering a cycle manually

The minimum interval is 12 hours, so for testing use the one-shot trigger — the
equivalent of the firmware's `discover.neighbors` / scope pass:

```bash
# Run one cycle now, then keep capturing normally
python -m meshcore_packet_capture --neighbors-now --verbose

# Run one cycle and exit
python -m meshcore_packet_capture --neighbors-now --neighbors-exit --verbose
```

It runs after the device and brokers connect, before the scheduler starts, and takes
roughly `neighbors_discover_window` seconds plus a few seconds per neighbor. Add `--debug`
to see each discover response and scope reply. A cycle also runs automatically on first
start, since no previous publish is recorded.

`total_neighbors` is how many were discovered, `queried_neighbors` how many were
actually asked for scopes, and `truncated` is true when either the `neighbors_max`
cap or the payload budget dropped some.

`status` is `responded`, `timeout`, or `send_failed` per neighbor. Entries are ordered
most- to least-useful (most recently heard, then stronger SNR) and the tail is dropped if
the payload would exceed 10 KB, matching the firmware's buffer.

Two differences from the firmware worth knowing: `heard_secs_ago` is measured within the
current cycle (this tool keeps no long-lived neighbor table), and `self.scopes` comes from
the radio's default flood scope name, since a companion radio has no region map — set
`neighbors_self_scopes` to declare it explicitly.

## Troubleshooting

### Connection Issues

**Script stops receiving packets but doesn't reconnect:**
- The script now includes automatic reconnection logic
- Check the logs for connection health check messages
- Adjust `health_check_interval` in config to check more frequently
- Increase `max_connection_retries` if you want more retry attempts

**BLE connection keeps dropping:**
- Ensure the MeshCore device is within range
- Check for interference from other Bluetooth devices
- Try increasing `connection_retry_delay` to give the device more time to recover
- Set `max_connection_retries = 0` for infinite retry attempts

**MQTT connection issues:**
- Verify MQTT broker settings in config
- Check network connectivity to MQTT broker
- The script will automatically retry MQTT connections on failure
- Adjust `mqtt_retry_delay` if reconnection attempts are too frequent

### Debugging

Enable debug mode for detailed logging:
```bash
python -m meshcore_packet_capture --debug
```

This will show:
- Connection health check results
- Reconnection attempts and results
- Detailed packet parsing information
- MQTT connection status

## Layout

- `src/meshcore_packet_capture/`: Installable Python package (run with `python -m meshcore_packet_capture`)
- `packet_capture.py`: Repo-root launcher (adds `src` to `PYTHONPATH` for quick runs)
- `pyproject.toml`: Package metadata and dependencies
- `packaging/`: systemd and launchd unit templates
- `devtools/`: Optional BLE/network debugging helpers (not installed to `/opt` by default)
- `config.toml.example`: Annotated reference for the TOML config under `/etc`
- `presets/`: Bundled `[[broker]]` presets installed to `config.d/10-*.toml`
- `install.sh` / `install.ps1` / `uninstall.sh`: Installation scripts
- `.env`: Legacy default configuration template (TOML takes precedence)
- `.env.local`: Legacy local configuration (for dev or Docker bind-mount)

## Contributing

Contributions are welcome! Please open GitHub issues for bug reports and feature requests, or submit pull requests for improvements.

## Credits

This project is based on the original [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) project by [Cisien](https://github.com/Cisien), which provides a foundation for MeshCore packet capture and MQTT integration. The project uses the official [meshcore](https://github.com/meshcore-dev/meshcore_py) Python package for device communication.
