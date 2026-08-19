from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict
from urllib.error import URLError
from urllib.request import Request, urlopen

from installer.config.config_manager import ConfigManager
from installer.detection.dependency_detection import create_venv_and_install, detect_dependencies
from installer.detection.platform_detection import detect_platform
from installer.install.common import (
    build_agent_run_command,
    deploy_agent_files,
    ensure_layout,
    resolve_install_paths,
)
from installer.install.linux_installer import LinuxInstaller
from installer.install.macos_installer import MacOSInstaller
from installer.install.windows_installer import WindowsInstaller
from installer.logs.installer_logging import get_logger
from installer.models import InstallOptions, SUPPORTED_ARCHES, SUPPORTED_OSES


class UniversalInstaller:
    def __init__(self, repo_root: Path, options: InstallOptions):
        self.repo_root = repo_root
        self.options = options

        self.platform = detect_platform()
        self.paths = resolve_install_paths(self.platform)
        self.log_file = self.paths.log_dir / "installer.log"
        self.logger = get_logger(self.log_file, level=options.log_level)
        self.config_manager = ConfigManager(self.paths)

    def install(self) -> int:
        self._print_banner("Installation")
        self._validate_platform()
        ensure_layout(self.paths)
        deps = self._validate_dependencies()

        existing = self.config_manager.read_manifest()
        if existing and not self.options.force and self.options.mode == "install":
            if self.options.silent:
                self.logger.info("Existing installation detected. Switching to repair mode.")
                return self.repair()
            choice = self._prompt_existing_install_choice(existing)
            if choice == "upgrade":
                from installer.upgrade.upgrade_manager import UpgradeManager

                return UpgradeManager(self).upgrade()
            if choice == "repair":
                return self.repair()
            self.logger.info("Installation cancelled by user")
            return 0

        app_dir = deploy_agent_files(self.repo_root, self.paths)
        config = self._build_config()
        self.config_manager.save_config(config)

        if not deps.standalone_binary_found:
            self._prepare_runtime()

        run_cmd_line, run_args = build_agent_run_command(self.paths, self.config_manager.config_file)
        adapter = self._build_platform_adapter(run_cmd_line, run_args)
        adapter.install_service()
        adapter.start()

        health = self._health_check(adapter)
        self.config_manager.write_manifest(
            {
                "version": self._version(),
                "platform": self.platform.os_family,
                "architecture": self.platform.architecture,
                "paths": {
                    "root": str(self.paths.root),
                    "config": str(self.paths.config_dir),
                    "state": str(self.paths.state_dir),
                    "log": str(self.paths.log_dir),
                },
            }
        )

        self._render_health(health)
        return 0 if not health["errors"] else 1

    def repair(self) -> int:
        self._print_banner("Repair")
        self._validate_platform()
        ensure_layout(self.paths)

        config_valid, message = self.config_manager.validate()
        if not config_valid:
            self.logger.warning("Config invalid: %s", message)
            cfg = self._build_config()
            self.config_manager.save_config(cfg)

        self._prepare_runtime(allow_failure=True)

        run_cmd_line, run_args = build_agent_run_command(self.paths, self.config_manager.config_file)
        adapter = self._build_platform_adapter(run_cmd_line, run_args)
        adapter.install_service()
        adapter.start()

        health = self._health_check(adapter)
        self._render_health(health)
        return 0 if not health["errors"] else 1

    def start(self) -> int:
        run_cmd_line, run_args = build_agent_run_command(self.paths, self.config_manager.config_file)
        adapter = self._build_platform_adapter(run_cmd_line, run_args)
        result = adapter.start()
        self.logger.info("Service start: %s", result.message)
        return 0 if result.ok else 1

    def stop(self) -> int:
        run_cmd_line, run_args = build_agent_run_command(self.paths, self.config_manager.config_file)
        adapter = self._build_platform_adapter(run_cmd_line, run_args)
        result = adapter.stop()
        self.logger.info("Service stop: %s", result.message)
        return 0 if result.ok else 1

    def restart(self) -> int:
        run_cmd_line, run_args = build_agent_run_command(self.paths, self.config_manager.config_file)
        adapter = self._build_platform_adapter(run_cmd_line, run_args)
        result = adapter.restart()
        self.logger.info("Service restart: %s", result.message)
        return 0 if result.ok else 1

    def status(self) -> int:
        run_cmd_line, run_args = build_agent_run_command(self.paths, self.config_manager.config_file)
        adapter = self._build_platform_adapter(run_cmd_line, run_args)
        result = adapter.status()
        self.logger.info("Service status: %s", result.message)
        print(result.message)
        return 0 if result.ok else 1

    def diagnostics(self) -> int:
        from installer.uninstall.universal_uninstaller import collect_diagnostics

        report = collect_diagnostics(self)
        out = self.paths.log_dir / "diagnostics.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        self.logger.info("Diagnostics written to %s", out)
        print(json.dumps(report, indent=2))
        return 0

    def _validate_platform(self) -> None:
        if self.platform.os_family not in SUPPORTED_OSES:
            raise RuntimeError(f"Unsupported operating system: {self.platform.os_family}")
        if self.platform.architecture not in SUPPORTED_ARCHES:
            raise RuntimeError(
                "Unsupported architecture: "
                f"{self.platform.architecture}\n\nSupported architectures:\nx86_64\nARM64"
            )

    def _validate_dependencies(self):
        deps = detect_dependencies(self.repo_root)
        if deps.message:
            raise RuntimeError(deps.message)
        if not deps.openssl_ok:
            raise RuntimeError("OpenSSL runtime not available")
        self.logger.info("Dependency check complete. Python=%s OpenSSL=%s", deps.python_version, deps.openssl_ok)
        return deps

    def _prepare_runtime(self, allow_failure: bool = False) -> None:
        requirements_file = self.repo_root / "requirements.txt"
        if not requirements_file.exists():
            requirements_file = self.repo_root / "src" / "requirements.txt"
        if not requirements_file.exists():
            self.logger.warning("No requirements file found; skipping venv package installation")
            return

        venv_dir = self.paths.runtime_dir / "venv"
        try:
            create_venv_and_install(self.repo_root, venv_dir, requirements_file)
            self.logger.info("Runtime environment ready at %s", venv_dir)
        except Exception as exc:
            if allow_failure:
                self.logger.warning("Runtime setup warning: %s", exc)
                return
            raise

    def _build_config(self) -> dict:
        opts = self.options
        if not opts.silent:
            if not opts.server:
                opts.server = input("Server URL: ").strip()
            if not opts.token:
                opts.token = input("Enrollment Token: ").strip()
            if not opts.name:
                opts.name = input("Agent Name: ").strip()

        config = self.config_manager.load_or_initialize(
            hostname=self.platform.hostname,
            version=self._version(),
            opts=opts,
        )
        return config

    def _build_platform_adapter(self, run_cmd_line: str, run_args: list[str]):
        if self.platform.os_family == "windows":
            return WindowsInstaller(self.paths, run_cmd_line)
        if self.platform.os_family == "linux":
            return LinuxInstaller(self.paths, run_cmd_line, user_mode=self.platform.privilege != "admin")
        return MacOSInstaller(self.paths, run_args, user_mode=self.platform.privilege != "admin")

    def _health_check(self, adapter) -> Dict[str, Any]:
        checks: Dict[str, bool] = {}
        warnings: list[str] = []
        errors: list[str] = []

        checks["OS detected"] = self.platform.os_family in SUPPORTED_OSES
        checks["Architecture supported"] = self.platform.architecture in SUPPORTED_ARCHES
        checks["Configuration created"] = self.config_manager.config_file.exists()
        checks["Agent identity generated"] = self.config_manager.identity_file.exists()
        checks["Log directory writable"] = self._dir_writable(self.paths.log_dir)

        service_status = adapter.status()
        checks["Service installed"] = True
        checks["Service running"] = service_status.ok
        if not service_status.ok:
            errors.append(f"Service status check failed: {service_status.message}")

        conf_ok, conf_message = self.config_manager.validate()
        checks["Configuration valid"] = conf_ok
        if not conf_ok:
            errors.append(conf_message)

        connectivity_ok, connectivity_msg = self._connectivity_check()
        checks["Server connectivity"] = connectivity_ok
        if not connectivity_ok:
            warnings.append(connectivity_msg)

        enroll_ok, enroll_msg = self._enrollment_check()
        checks["Enrollment successful"] = enroll_ok
        if not enroll_ok:
            warnings.append(enroll_msg)

        return {"checks": checks, "warnings": warnings, "errors": errors}

    def _connectivity_check(self) -> tuple[bool, str]:
        config = self._read_config()
        host = config.get("server", {}).get("host")
        port = int(config.get("server", {}).get("port", 9090))
        if not host:
            return False, "Server host is empty"
        try:
            with socket.create_connection((host, port), timeout=3):
                return True, "OK"
        except Exception as exc:
            return False, f"TCP connection to {host}:{port} failed: {exc}"

    def _enrollment_check(self) -> tuple[bool, str]:
        config = self._read_config()
        server_url = config.get("server", {}).get("url", "")
        token = config.get("server", {}).get("enrollment_token", "")
        agent_id = config.get("agent", {}).get("id", "")
        if not server_url or not token:
            return False, "Enrollment skipped (missing server URL or token)"
        endpoint = server_url.rstrip("/") + "/api/agents/enroll"
        payload = json.dumps({"agent_id": agent_id, "name": config.get("agent", {}).get("name", "")}).encode("utf-8")
        req = Request(endpoint, data=payload, method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/json")

        try:
            context = ssl.create_default_context()
            with urlopen(req, context=context, timeout=5) as response:
                if 200 <= response.status < 300:
                    return True, "OK"
                return False, f"Enrollment endpoint returned HTTP {response.status}"
        except URLError as exc:
            return False, f"TLS connection to {server_url} failed: {exc.reason}"
        except Exception as exc:
            return False, f"Enrollment failed: {exc}"

    def _read_config(self) -> dict:
        if not self.config_manager.config_file.exists():
            return {}
        import yaml

        return yaml.safe_load(self.config_manager.config_file.read_text(encoding="utf-8")) or {}

    def _prompt_existing_install_choice(self, manifest: dict) -> str:
        print("Existing Cyberion installation detected.\n")
        print(f"Version: {manifest.get('version', 'unknown')}")
        print(f"Installed: {manifest.get('paths', {}).get('root', str(self.paths.root))}\n")
        print("Options:\n[U] Upgrade\n[R] Repair\n[C] Cancel")
        raw = input("Choose option: ").strip().lower()
        if raw.startswith("u"):
            return "upgrade"
        if raw.startswith("r"):
            return "repair"
        return "cancel"

    def _dir_writable(self, path: Path) -> bool:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".cyberion_write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True
        except Exception:
            return False

    def _version(self) -> str:
        return os.getenv("CYBERION_AGENT_VERSION", "1.0.0")

    def _print_banner(self, mode: str) -> None:
        print("=" * 54)
        print("CYBERION SECURITY AGENT")
        print(mode)
        print("=" * 54)

        self.logger.info("Cyberion installer started")
        self.logger.info("OS: %s", self.platform.os_family)
        self.logger.info("Architecture: %s", self.platform.architecture)
        self.logger.info("Privilege: %s", self.platform.privilege)
        self.logger.info("Distribution: %s", self.platform.linux_distribution or "n/a")

    def _render_health(self, health: Dict[str, Any]) -> None:
        print("Running health checks...")
        for key, value in health["checks"].items():
            status = "[OK]" if value else "[FAIL]"
            print(f"  {status} {key}")
        if health["warnings"]:
            print("Warnings:")
            for item in health["warnings"]:
                print(f"  - {item}")
        if health["errors"]:
            print("Errors:")
            for item in health["errors"]:
                print(f"  - {item}")
