from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from installer.models import InstallPaths, PlatformInfo


def resolve_install_paths(platform_info: PlatformInfo) -> InstallPaths:
    override_root = os.getenv("CYBERION_INSTALLER_ROOT")
    if override_root:
        root = Path(override_root)
        return InstallPaths(
            root=root,
            bin_dir=root / "bin",
            config_dir=root / "config",
            log_dir=root / "logs",
            state_dir=root / "state",
            certs_dir=root / "certs",
            runtime_dir=root / "runtime",
            service_dir=root / "service",
        )

    if platform_info.os_family == "windows":
        if platform_info.privilege == "admin":
            root = Path(os.environ.get("ProgramFiles", r"C:\\Program Files")) / "Cyberion" / "Agent"
            data_root = Path(os.environ.get("ProgramData", r"C:\\ProgramData")) / "Cyberion" / "Agent"
        else:
            root = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Cyberion" / "Agent"
            data_root = root / "data"
        return InstallPaths(
            root=root,
            bin_dir=root / "bin",
            config_dir=data_root / "config",
            log_dir=data_root / "logs",
            state_dir=data_root / "state",
            certs_dir=data_root / "certs",
            runtime_dir=data_root / "runtime",
            service_dir=None,
        )

    if platform_info.os_family == "linux":
        if platform_info.privilege == "admin":
            return InstallPaths(
                root=Path("/opt/cyberion/agent"),
                bin_dir=Path("/opt/cyberion/agent/bin"),
                config_dir=Path("/etc/cyberion"),
                log_dir=Path("/var/log/cyberion"),
                state_dir=Path("/var/lib/cyberion"),
                certs_dir=Path("/var/lib/cyberion/certs"),
                runtime_dir=Path("/var/lib/cyberion/runtime"),
                service_dir=Path("/etc/systemd/system"),
            )
        root = Path.home() / ".local" / "share" / "cyberion" / "agent"
        return InstallPaths(
            root=root,
            bin_dir=root / "bin",
            config_dir=Path.home() / ".config" / "cyberion",
            log_dir=Path.home() / ".local" / "state" / "cyberion" / "logs",
            state_dir=Path.home() / ".local" / "state" / "cyberion",
            certs_dir=Path.home() / ".local" / "state" / "cyberion" / "certs",
            runtime_dir=root / "runtime",
            service_dir=Path.home() / ".config" / "systemd" / "user",
        )

    if platform_info.privilege == "admin":
        root = Path("/Library/Application Support/Cyberion/Agent")
        log_dir = Path("/Library/Logs/Cyberion")
        state_dir = Path("/Library/Application Support/Cyberion/State")
        config_dir = Path("/Library/Application Support/Cyberion/Config")
        service_dir = Path("/Library/LaunchDaemons")
    else:
        root = Path.home() / "Library" / "Application Support" / "Cyberion" / "Agent"
        log_dir = Path.home() / "Library" / "Logs" / "Cyberion"
        state_dir = Path.home() / "Library" / "Application Support" / "Cyberion" / "State"
        config_dir = Path.home() / "Library" / "Application Support" / "Cyberion" / "Config"
        service_dir = Path.home() / "Library" / "LaunchAgents"

    return InstallPaths(
        root=root,
        bin_dir=root / "bin",
        config_dir=config_dir,
        log_dir=log_dir,
        state_dir=state_dir,
        certs_dir=state_dir / "certs",
        runtime_dir=state_dir / "runtime",
        service_dir=service_dir,
    )


def ensure_layout(paths: InstallPaths) -> None:
    for path in [
        paths.root,
        paths.bin_dir,
        paths.config_dir,
        paths.log_dir,
        paths.state_dir,
        paths.certs_dir,
        paths.runtime_dir,
    ]:
        path.mkdir(parents=True, exist_ok=True)


def deploy_agent_files(repo_root: Path, paths: InstallPaths) -> Path:
    app_dir = paths.root / "app"
    if app_dir.exists():
        shutil.rmtree(app_dir)
    app_dir.mkdir(parents=True, exist_ok=True)

    shutil.copytree(repo_root / "Agent", app_dir / "Agent", dirs_exist_ok=True)

    for file_name in ["requirements.txt", "agent.yaml", "config_reference.yaml"]:
        src = repo_root / file_name
        if src.exists():
            shutil.copy2(src, app_dir / file_name)

    return app_dir


def build_agent_run_command(paths: InstallPaths, config_file: Path) -> tuple[str, list[str]]:
    venv_python = paths.runtime_dir / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    py_exec = str(venv_python if venv_python.exists() else sys.executable)

    connector_script = paths.root / "app" / "Agent" / "connector.py"
    args = [py_exec, str(connector_script), "--config", str(config_file)]
    cmd_line = subprocess.list2cmdline(args) if os.name == "nt" else " ".join(args)
    return cmd_line, args
