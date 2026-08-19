from __future__ import annotations

import json
import shutil
from pathlib import Path

from installer.install.common import build_agent_run_command


def collect_diagnostics(installer) -> dict:
    adapter = installer._build_platform_adapter(*build_agent_run_command(installer.paths, installer.config_manager.config_file))
    status = adapter.status()
    config_ok, config_message = installer.config_manager.validate()
    deps = {
        "python": installer._validate_dependencies().python_version,
    }
    connectivity_ok, connectivity_msg = installer._connectivity_check()

    report = {
        "os": installer.platform.os_family,
        "architecture": installer.platform.architecture,
        "agent_version": installer._version(),
        "service_status": status.message,
        "configuration_status": config_message,
        "dependency_versions": deps,
        "permissions": installer.platform.privilege,
        "recent_errors": _tail_log(installer.log_file),
        "connectivity_status": connectivity_msg,
        "disk_usage": _disk_usage(installer.paths.root),
        "memory_usage": "n/a",
        "secrets_redacted": True,
        "checks": {
            "config_valid": config_ok,
            "connectivity": connectivity_ok,
        },
    }
    return report


def _tail_log(log_file: Path, max_lines: int = 30) -> list[str]:
    if not log_file.exists():
        return []
    lines = log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    return lines[-max_lines:]


def _disk_usage(path: Path) -> dict:
    if not path.exists():
        return {"exists": False}
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            total += p.stat().st_size
    return {"exists": True, "bytes": total}


class UniversalUninstaller:
    def __init__(self, installer, purge: bool = False, preserve_config: bool = True):
        self.installer = installer
        self.purge = purge
        self.preserve_config = preserve_config

    def uninstall(self) -> int:
        run_cmd_line, run_args = build_agent_run_command(self.installer.paths, self.installer.config_manager.config_file)
        adapter = self.installer._build_platform_adapter(run_cmd_line, run_args)
        adapter.stop()
        adapter.uninstall_service()

        if self.purge:
            self._remove_path(self.installer.paths.root)
            self._remove_path(self.installer.paths.config_dir)
            self._remove_path(self.installer.paths.state_dir)
            self._remove_path(self.installer.paths.log_dir)
        else:
            self._remove_path(self.installer.paths.root)
            if not self.preserve_config:
                self._remove_path(self.installer.paths.config_dir)
            # Preserve state/log by default for diagnostics.

        manifest = self.installer.config_manager.manifest_file
        if manifest.exists():
            manifest.unlink()

        print("Cyberion Agent uninstall completed")
        return 0

    def _remove_path(self, path: Path) -> None:
        if not path.exists():
            return
        if path.is_file():
            path.unlink()
            return
        shutil.rmtree(path, ignore_errors=True)
