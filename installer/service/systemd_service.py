from __future__ import annotations

from pathlib import Path

from installer.service.base import ServiceResult, ensure_file, run_command


SERVICE_NAME = "cyberion-agent.service"


class SystemdServiceManager:
    def __init__(
        self,
        service_dir: Path,
        run_command_line: str,
        user_mode: bool,
        service_name: str = SERVICE_NAME,
        description: str = "Cyberion Security Agent",
    ):
        self.service_dir = service_dir
        self.run_command_line = run_command_line
        self.user_mode = user_mode
        self.service_name = service_name
        self.description = description
        self.service_file = self.service_dir / self.service_name

    def install(self) -> ServiceResult:
        unit = f"""[Unit]
Description={self.description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={self.run_command_line}
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=300
StartLimitBurst=10

[Install]
WantedBy=multi-user.target
"""
        ensure_file(self.service_file, unit, 0o644)
        scope = ["--user"] if self.user_mode else []
        run_command(["systemctl", *scope, "daemon-reload"])
        run_command(["systemctl", *scope, "enable", self.service_name])
        return ServiceResult(True, f"Installed {self.service_file}")

    def start(self) -> ServiceResult:
        scope = ["--user"] if self.user_mode else []
        code, _, err = run_command(["systemctl", *scope, "start", self.service_name])
        return ServiceResult(code == 0, err or "started")

    def stop(self) -> ServiceResult:
        scope = ["--user"] if self.user_mode else []
        code, _, err = run_command(["systemctl", *scope, "stop", self.service_name])
        return ServiceResult(code == 0, err or "stopped")

    def status(self) -> ServiceResult:
        scope = ["--user"] if self.user_mode else []
        code, out, err = run_command(["systemctl", *scope, "is-active", self.service_name])
        return ServiceResult(code == 0 and out.strip() == "active", out or err)

    def uninstall(self) -> ServiceResult:
        scope = ["--user"] if self.user_mode else []
        run_command(["systemctl", *scope, "disable", self.service_name])
        run_command(["systemctl", *scope, "stop", self.service_name])
        if self.service_file.exists():
            self.service_file.unlink()
        run_command(["systemctl", *scope, "daemon-reload"])
        return ServiceResult(True, "removed")
