# Cyberion Uninstallation

## Standard uninstall

```bash
python -m installer.cli uninstall
```

Standard uninstall:

1. Stops the service.
2. Disables/removes service registration.
3. Removes application binaries.
4. Preserves diagnostic config/state/logs by default.

## Purge uninstall

```bash
python -m installer.cli uninstall --purge
```

Purge uninstall also removes:

- Configuration files
- Agent identity/state
- Runtime cache and logs

## Preserve config behavior

Use `--preserve-config` (default true) to keep config when not purging.

## Identity behavior

- Upgrade and repair preserve identity.
- Clean uninstall followed by reinstall generates a new identity.
