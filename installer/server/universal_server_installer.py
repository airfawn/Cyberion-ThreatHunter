from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict

import yaml

from installer.detection.dependency_detection import create_venv_and_install, detect_dependencies
from installer.detection.platform_detection import detect_platform
from installer.logs.installer_logging import get_logger
from installer.models import InstallOptions, InstallPaths, SUPPORTED_ARCHES, SUPPORTED_OSES
from installer.service.launchd_service import LaunchdServiceManager
from installer.service.launchd_service import launchd_domain_for_user_mode
from installer.service.systemd_service import SystemdServiceManager
from installer.service.windows_service import WindowsServiceManager


class UniversalServerInstaller:
    def __init__(self, repo_root: Path, options: InstallOptions):
        self.repo_root = repo_root
        self.options = options
        self.platform = detect_platform()
        self.paths = self._resolve_paths()
        self.log_file = self.paths.log_dir / "server_installer.log"
        self.logger = get_logger(self.log_file, level=options.log_level)
        self.config_file = self.paths.config_dir / "server.yaml"
        self.manifest_file = self.paths.state_dir / "server_install_manifest.json"

    def install(self) -> int:
        self._validate_platform()
        if self.manifest_file.exists() and not self.options.force and self.options.mode == "install":
            if self._installed_payload_exists():
                if self.options.silent:
                    self.logger.info("Existing server installation detected. Switching to repair mode.")
                    return self.repair()
                print("Existing Cyberion server installation detected. Use upgrade/repair.")
                return 1

            self.logger.info("Stale server manifest found without installed payload; clearing manifest and continuing.")
            self.manifest_file.unlink()

        self._ensure_layout()
        deps = detect_dependencies(self.repo_root)
        if deps.message:
            raise RuntimeError(deps.message)

        app_dir = self._deploy_files()
        config = self._build_config()
        self._save_config(config)

        if not deps.standalone_binary_found:
            self._prepare_runtime()

        cmd_line, run_args = self._build_run_command()
        adapter = self._adapter(cmd_line, run_args)
        adapter.install()
        adapter.start()

        health = self._health(adapter)
        self._write_manifest({
            "version": self._version(),
            "platform": self.platform.os_family,
            "architecture": self.platform.architecture,
            "app_dir": str(app_dir),
            "config": str(self.config_file),
        })
        self._print_health(health)
        if not health["errors"]:
            print(f"Access the service at {self._service_access_url()}")
            if self.options.launch_gui:
                self._launch_gui_if_requested()
        return 0 if not health["errors"] else 1

    def upgrade(self) -> int:
        backup = self._backup_current()
        self.stop()
        prev_mode = self.options.mode
        prev_force = self.options.force
        self.options.mode = "upgrade"
        self.options.force = True
        try:
            code = self.install()
            if code != 0:
                raise RuntimeError("upgrade failed")
            return 0
        except Exception as exc:
            print(f"Upgrade failed: {exc}. Rolling back...")
            self._rollback(backup)
            self.start()
            return 1
        finally:
            self.options.mode = prev_mode
            self.options.force = prev_force

    def repair(self) -> int:
        self._validate_platform()
        self._ensure_layout()
        if not self.config_file.exists():
            self._save_config(self._build_config())

        self._prepare_runtime(allow_failure=True)
        cmd_line, run_args = self._build_run_command()
        adapter = self._adapter(cmd_line, run_args)
        adapter.install()
        adapter.start()
        health = self._health(adapter)
        self._print_health(health)
        if not health["errors"]:
            print(f"Access the service at {self._service_access_url()}")
            if self.options.launch_gui:
                self._launch_gui_if_requested()
        return 0 if not health["errors"] else 1

    def uninstall(self, purge: bool = False) -> int:
        cmd_line, run_args = self._build_run_command()
        adapter = self._adapter(cmd_line, run_args)
        adapter.stop()
        removed = adapter.uninstall()
        if not removed.ok:
            print(f"Server service removal warning: {removed.message}")

        shutil.rmtree(self.paths.root, ignore_errors=True)
        if self.manifest_file.exists():
            self.manifest_file.unlink()
        if purge:
            shutil.rmtree(self.paths.config_dir, ignore_errors=True)
            shutil.rmtree(self.paths.state_dir, ignore_errors=True)
            shutil.rmtree(self.paths.log_dir, ignore_errors=True)
        print("Cyberion Server uninstall completed")
        return 0

    def start(self) -> int:
        cmd_line, run_args = self._build_run_command()
        result = self._adapter(cmd_line, run_args).start()
        print(result.message)
        if result.ok:
            print(f"Access the service at {self._service_access_url()}")
            if self.options.launch_gui:
                self._launch_gui_if_requested()
        return 0 if result.ok else 1

    def stop(self) -> int:
        cmd_line, run_args = self._build_run_command()
        result = self._adapter(cmd_line, run_args).stop()
        print(result.message)
        return 0 if result.ok else 1

    def restart(self) -> int:
        cmd_line, run_args = self._build_run_command()
        adapter = self._adapter(cmd_line, run_args)
        adapter.stop()
        result = adapter.start()
        print(result.message)
        if result.ok:
            print(f"Access the service at {self._service_access_url()}")
            if self.options.launch_gui:
                self._launch_gui_if_requested()
        return 0 if result.ok else 1

    def launch_gui(self) -> int:
        return self._launch_gui_if_requested()

    def status(self) -> int:
        cmd_line, run_args = self._build_run_command()
        result = self._adapter(cmd_line, run_args).status()
        print(result.message)
        return 0 if result.ok else 1

    def diagnostics(self) -> int:
        cmd_line, run_args = self._build_run_command()
        adapter = self._adapter(cmd_line, run_args)
        service = adapter.status()
        report = {
            "os": self.platform.os_family,
            "architecture": self.platform.architecture,
            "version": self._version(),
            "service_status": service.message,
            "config_exists": self.config_file.exists(),
            "config_valid": self._config_valid(),
            "connectivity": self._connectivity(),
            "log_writable": self._dir_writable(self.paths.log_dir),
        }
        out = self.paths.log_dir / "server_diagnostics.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0

    def _resolve_paths(self) -> InstallPaths:
        override_root = os.getenv("CYBERION_SERVER_INSTALLER_ROOT")
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

        if self.platform.os_family == "windows":
            if self.platform.privilege == "admin":
                root = Path(os.environ.get("ProgramFiles", r"C:\\Program Files")) / "Cyberion" / "Server"
                data = Path(os.environ.get("ProgramData", r"C:\\ProgramData")) / "Cyberion" / "Server"
            else:
                root = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Cyberion" / "Server"
                data = root / "data"
            return InstallPaths(
                root=root,
                bin_dir=root / "bin",
                config_dir=data / "config",
                log_dir=data / "logs",
                state_dir=data / "state",
                certs_dir=data / "certs",
                runtime_dir=data / "runtime",
                service_dir=None,
            )

        if self.platform.os_family == "linux":
            if self.platform.privilege == "admin":
                return InstallPaths(
                    root=Path("/opt/cyberion/server"),
                    bin_dir=Path("/opt/cyberion/server/bin"),
                    config_dir=Path("/etc/cyberion"),
                    log_dir=Path("/var/log/cyberion"),
                    state_dir=Path("/var/lib/cyberion/server"),
                    certs_dir=Path("/var/lib/cyberion/server/certs"),
                    runtime_dir=Path("/var/lib/cyberion/server/runtime"),
                    service_dir=Path("/etc/systemd/system"),
                )
            root = Path.home() / ".local" / "share" / "cyberion" / "server"
            return InstallPaths(
                root=root,
                bin_dir=root / "bin",
                config_dir=Path.home() / ".config" / "cyberion",
                log_dir=Path.home() / ".local" / "state" / "cyberion" / "logs",
                state_dir=Path.home() / ".local" / "state" / "cyberion" / "server",
                certs_dir=Path.home() / ".local" / "state" / "cyberion" / "server" / "certs",
                runtime_dir=root / "runtime",
                service_dir=Path.home() / ".config" / "systemd" / "user",
            )

        if self.platform.privilege == "admin":
            root = Path("/Library/Application Support/Cyberion/Server")
            config = Path("/Library/Application Support/Cyberion/Config")
            state = Path("/Library/Application Support/Cyberion/ServerState")
            log = Path("/Library/Logs/Cyberion")
            service = Path("/Library/LaunchDaemons")
        else:
            root = Path.home() / "Library/Application Support/Cyberion/Server"
            config = Path.home() / "Library/Application Support/Cyberion/Config"
            state = Path.home() / "Library/Application Support/Cyberion/ServerState"
            log = Path.home() / "Library/Logs/Cyberion"
            service = Path.home() / "Library/LaunchAgents"

        return InstallPaths(
            root=root,
            bin_dir=root / "bin",
            config_dir=config,
            log_dir=log,
            state_dir=state,
            certs_dir=state / "certs",
            runtime_dir=state / "runtime",
            service_dir=service,
        )

    def _ensure_layout(self) -> None:
        for p in [
            self.paths.root,
            self.paths.bin_dir,
            self.paths.config_dir,
            self.paths.log_dir,
            self.paths.state_dir,
            self.paths.runtime_dir,
        ]:
            p.mkdir(parents=True, exist_ok=True)

    def _deploy_files(self) -> Path:
        app_dir = self.paths.root / "app"
        if app_dir.exists():
            shutil.rmtree(app_dir)
        app_dir.mkdir(parents=True, exist_ok=True)

        shutil.copytree(self.repo_root / "src", app_dir / "src", dirs_exist_ok=True)
        if (self.repo_root / "config").exists():
            shutil.copytree(self.repo_root / "config", app_dir / "config", dirs_exist_ok=True)
        for f in ["requirements.txt", "cyberion_settings.json"]:
            src = self.repo_root / f
            if src.exists():
                shutil.copy2(src, app_dir / f)
        return app_dir

    def _build_config(self) -> dict:
        bind = os.getenv("THREATHUNTER_BIND_HOST", "0.0.0.0")
        port = int(os.getenv("THREATHUNTER_PORT", "9090"))

        if not self.options.silent:
            raw_bind = input(f"Server bind host [{bind}]: ").strip()
            raw_port = input(f"Server port [{port}]: ").strip()
            if raw_bind:
                bind = raw_bind
            if raw_port:
                try:
                    port = int(raw_port)
                except ValueError:
                    pass

        return {
            "server": {
                "bind_host": bind,
                "port": port,
            },
            "logging": {
                "level": self.options.log_level.upper(),
                "directory": str(self.paths.log_dir),
            },
            "version": self._version(),
        }

    def _save_config(self, config: dict) -> None:
        self.paths.config_dir.mkdir(parents=True, exist_ok=True)
        with self.config_file.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(config, handle, sort_keys=False)

    def _prepare_runtime(self, allow_failure: bool = False) -> None:
        req = self.repo_root / "requirements.txt"
        if not req.exists():
            req = self.repo_root / "src" / "requirements.txt"
        if not req.exists():
            return

        venv = self.paths.runtime_dir / "venv"
        try:
            create_venv_and_install(self.repo_root, venv, req)
        except Exception:
            if allow_failure:
                return
            raise

    def _build_run_command(self) -> tuple[str, list[str]]:
        py = self.paths.runtime_dir / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        py_exec = str(py if py.exists() else sys.executable)
        runner_script = self.paths.root / "app" / "src" / "server_runner.py"
        args = [py_exec, str(runner_script)]
        cmd_line = subprocess.list2cmdline(args) if os.name == "nt" else " ".join(args)
        return cmd_line, args

    def _installed_payload_exists(self) -> bool:
        runner_script = self.paths.root / "app" / "src" / "server_runner.py"
        return runner_script.exists()

    def _adapter(self, cmd_line: str, run_args: list[str]):
        if self.platform.os_family == "windows":
            return _WindowsServerAdapter(cmd_line)
        if self.platform.os_family == "linux":
            return _LinuxServerAdapter(self.paths.service_dir, cmd_line, user_mode=self.platform.privilege != "admin")
        return _MacServerAdapter(
            self.paths.service_dir,
            run_args,
            self.paths.log_dir,
            user_mode=self.platform.privilege != "admin",
        )

    def _validate_platform(self) -> None:
        if self.platform.os_family not in SUPPORTED_OSES:
            raise RuntimeError(f"Unsupported operating system: {self.platform.os_family}")
        if self.platform.architecture not in SUPPORTED_ARCHES:
            raise RuntimeError(f"Unsupported architecture: {self.platform.architecture}")

    def _health(self, adapter) -> Dict[str, Any]:
        checks = {
            "OS detected": self.platform.os_family in SUPPORTED_OSES,
            "Architecture supported": self.platform.architecture in SUPPORTED_ARCHES,
            "Configuration created": self.config_file.exists(),
            "Service installed": True,
            "Service running": adapter.status().ok,
            "Log directory writable": self._dir_writable(self.paths.log_dir),
            "Configuration valid": self._config_valid(),
            "Server connectivity": self._connectivity()[0],
        }
        warnings = []
        errors = []
        if not checks["Service running"]:
            errors.append("Service is not running")
        if not checks["Configuration valid"]:
            errors.append("Server configuration invalid")
        if not checks["Server connectivity"]:
            warnings.append("Server TCP connectivity check failed")
        return {"checks": checks, "warnings": warnings, "errors": errors}

    def _connectivity(self) -> tuple[bool, str]:
        if not self.config_file.exists():
            return False, "missing config"
        data = yaml.safe_load(self.config_file.read_text(encoding="utf-8")) or {}
        host = data.get("server", {}).get("bind_host", "127.0.0.1")
        port = int(data.get("server", {}).get("port", 9090))
        test_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
        last_error = "unknown"
        for _ in range(10):
            try:
                with socket.create_connection((test_host, port), timeout=2):
                    return True, "OK"
            except Exception as exc:
                last_error = str(exc)
                time.sleep(1)
        return False, last_error

    def _config_valid(self) -> bool:
        if not self.config_file.exists():
            return False
        try:
            data = yaml.safe_load(self.config_file.read_text(encoding="utf-8")) or {}
            return bool(data.get("server", {}).get("port"))
        except Exception:
            return False

    def _dir_writable(self, path: Path) -> bool:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".server_write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True
        except Exception:
            return False

    def _backup_current(self) -> Path:
        backup_root = self.paths.state_dir / "rollback"
        backup_root.mkdir(parents=True, exist_ok=True)
        backup = backup_root / "server_app_backup"
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
        if self.paths.root.exists():
            shutil.copytree(self.paths.root, backup, dirs_exist_ok=True)
        return backup

    def _rollback(self, backup: Path) -> None:
        if not backup.exists():
            return
        if self.paths.root.exists():
            shutil.rmtree(self.paths.root, ignore_errors=True)
        shutil.copytree(backup, self.paths.root, dirs_exist_ok=True)

    def _write_manifest(self, data: Dict[str, Any]) -> None:
        self.paths.state_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _version(self) -> str:
        return os.getenv("CYBERION_SERVER_VERSION", os.getenv("CYBERION_AGENT_VERSION", "1.0.0"))

    def _print_health(self, health: Dict[str, Any]) -> None:
        print("Running server health checks...")
        for key, value in health["checks"].items():
            status = "[OK]" if value else "[FAIL]"
            print(f"  {status} {key}")
        for warn in health["warnings"]:
            print(f"  [WARN] {warn}")
        for err in health["errors"]:
            print(f"  [ERROR] {err}")

    def _service_access_url(self) -> str:
        host = "127.0.0.1"
        port = 9090
        if self.config_file.exists():
            try:
                data = yaml.safe_load(self.config_file.read_text(encoding="utf-8")) or {}
                cfg_host = str(data.get("server", {}).get("bind_host", host) or host)
                host = "127.0.0.1" if cfg_host in {"0.0.0.0", "::"} else cfg_host
                port = int(data.get("server", {}).get("port", port))
            except Exception:
                pass
        return f"http://{host}:{port}"

    def _build_gui_command(self) -> tuple[str, list[str]]:
        py = self.paths.runtime_dir / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        py_exec = str(py if py.exists() else sys.executable)
        main_script = self.paths.root / "app" / "src" / "main.py"
        args = [py_exec, str(main_script)]
        cmd_line = subprocess.list2cmdline(args) if os.name == "nt" else " ".join(args)
        return cmd_line, args

    def _launch_gui_if_requested(self) -> int:
        _, gui_args = self._build_gui_command()
        app_dir = self.paths.root / "app"
        if not Path(gui_args[1]).exists():
            print("GUI launch skipped: UI files not found in installation path")
            return 1

        env = os.environ.copy()
        env["THREATHUNTER_GUI_ATTACH_MODE"] = "1"
        self.paths.log_dir.mkdir(parents=True, exist_ok=True)
        gui_out = self.paths.log_dir / "gui.out.log"
        gui_err = self.paths.log_dir / "gui.err.log"

        try:
            with gui_out.open("ab") as out_handle, gui_err.open("ab") as err_handle:
                proc = subprocess.Popen(
                    gui_args,
                    cwd=str(app_dir),
                    env=env,
                    stdout=out_handle,
                    stderr=err_handle,
                    start_new_session=True,
                )
            if self.platform.os_family == "macos":
                self._focus_gui_window(proc.pid)
            print("Cyberion GUI launched in attach mode")
            print(f"GUI logs: {gui_out} | {gui_err}")
            return 0
        except Exception as exc:
            print(f"GUI launch failed: {exc}")
            return 1

    def _focus_gui_window(self, pid: int) -> None:
        script = (
            'tell application "System Events"\n'
            f'  set frontmost of first process whose unix id is {pid} to true\n'
            "end tell"
        )
        try:
            subprocess.run(["osascript", "-e", script], check=False, capture_output=True, text=True)
        except Exception:
            pass


class _LinuxServerAdapter:
    def __init__(self, service_dir: Path, cmd_line: str, user_mode: bool):
        self.manager = SystemdServiceManager(
            service_dir,
            cmd_line,
            user_mode,
            service_name="cyberion-server.service",
            description="Cyberion Security Server",
        )

    def install(self):
        return self.manager.install()

    def start(self):
        return self.manager.start()

    def stop(self):
        return self.manager.stop()

    def status(self):
        return self.manager.status()

    def uninstall(self):
        return self.manager.uninstall()


class _WindowsServerAdapter:
    def __init__(self, cmd_line: str):
        self.manager = WindowsServiceManager(
            cmd_line,
            service_name="CyberionServer",
            display_name="Cyberion Security Server",
        )

    def install(self):
        return self.manager.install()

    def start(self):
        return self.manager.start()

    def stop(self):
        return self.manager.stop()

    def status(self):
        return self.manager.status()

    def uninstall(self):
        return self.manager.uninstall()


class _MacServerAdapter:
    def __init__(self, service_dir: Path, run_args: list[str], log_dir: Path, user_mode: bool):
        plist = service_dir / "com.cyberion.server.plist"
        domain = launchd_domain_for_user_mode(user_mode)
        self.manager = LaunchdServiceManager(
            plist,
            run_args,
            log_dir,
            label="com.cyberion.server",
            log_prefix="server",
            domain=domain,
        )

    def install(self):
        return self.manager.install()

    def start(self):
        return self.manager.start()

    def stop(self):
        return self.manager.stop()

    def status(self):
        return self.manager.status()

    def uninstall(self):
        return self.manager.uninstall()
