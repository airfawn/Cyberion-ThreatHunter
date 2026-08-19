# Cyberion Universal Installer

## Overview

The Cyberion installer framework provides one command surface for install, upgrade, repair, uninstall, service control, and diagnostics across Windows, Linux, and macOS.

Primary CLI:

- `python -m installer.cli install`
- `python -m installer.cli upgrade`
- `python -m installer.cli repair`
- `python -m installer.cli uninstall`
- `python -m installer.cli start`
- `python -m installer.cli stop`
- `python -m installer.cli restart`
- `python -m installer.cli status`
- `python -m installer.cli version`
- `python -m installer.cli diagnostics`

Server CLI:

- `./cyberion-server install`
- `./cyberion-server upgrade`
- `./cyberion-server repair`
- `./cyberion-server uninstall`
- `./cyberion-server start`
- `./cyberion-server stop`
- `./cyberion-server restart`
- `./cyberion-server status`
- `./cyberion-server diagnostics`

The server installer deploys a headless runtime based on `python -m src.server_runner` for service mode.

## Silent install

```bash
python -m installer.cli install --silent \
  --server https://server.example.com \
  --token XXXXX \
  --name HOST-001 \
  --log-level INFO
```

## Interactive install

```bash
python -m installer.cli install
```

The installer prompts for server URL, enrollment token, and agent name if they are not provided.

## Paths used

### Windows

- Binary/application root: `C:\Program Files\Cyberion\Agent\` (admin)
- Mutable state/config/logs: `C:\ProgramData\Cyberion\Agent\`

### Linux

- App: `/opt/cyberion/agent/`
- Config: `/etc/cyberion/`
- State: `/var/lib/cyberion/`
- Logs: `/var/log/cyberion/`

### macOS

- App support: `/Library/Application Support/Cyberion/Agent/`
- Config: `/Library/Application Support/Cyberion/Config/`
- Logs: `/Library/Logs/Cyberion/`
- Service plist: `/Library/LaunchDaemons/`

## Service management

- Windows: `sc` service (`CyberionAgent`)
- Linux: `systemd` (`cyberion-agent.service`)
- macOS: `launchd` (`com.cyberion.agent`)

Each service definition uses restart-on-failure behavior.

## Security notes

- Installer logs redact tokens and secrets.
- TLS verification remains enabled by default.
- Enrollment token is never printed to terminal or installer log.
- Configuration and identity files are written with restricted permissions when supported.

## Packaging scripts

- Linux/macOS shell bundle script: `scripts/build_installer_packages.sh`
- Windows bundle script: `scripts/build_installer_packages.ps1`

These scripts create distributable bootstrap payloads and include integration points for MSI/PKG/DEB/RPM build pipelines.
