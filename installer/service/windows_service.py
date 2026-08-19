from __future__ import annotations

from installer.service.base import ServiceResult, run_command


SERVICE_NAME = "CyberionAgent"
DISPLAY_NAME = "Cyberion Security Agent"


class WindowsServiceManager:
    def __init__(
        self,
        run_command_line: str,
        service_name: str = SERVICE_NAME,
        display_name: str = DISPLAY_NAME,
    ):
        self.run_command_line = run_command_line
        self.service_name = service_name
        self.display_name = display_name

    def install(self) -> ServiceResult:
        # sc requires spaces around '=' values.
        create_cmd = [
            "sc",
            "create",
            self.service_name,
            "binPath=",
            self.run_command_line,
            "start=",
            "auto",
            "DisplayName=",
            self.display_name,
        ]
        run_command(create_cmd)
        run_command(["sc", "failure", self.service_name, "reset=", "60", "actions=", "restart/5000/restart/15000/restart/30000"])
        return ServiceResult(True, "service installed")

    def start(self) -> ServiceResult:
        code, _, err = run_command(["sc", "start", self.service_name])
        return ServiceResult(code == 0, err or "started")

    def stop(self) -> ServiceResult:
        code, _, err = run_command(["sc", "stop", self.service_name])
        return ServiceResult(code == 0, err or "stopped")

    def status(self) -> ServiceResult:
        code, out, err = run_command(["sc", "query", self.service_name])
        running = "RUNNING" in out
        return ServiceResult(code == 0 and running, out or err)

    def uninstall(self) -> ServiceResult:
        run_command(["sc", "stop", self.service_name])
        code, _, err = run_command(["sc", "delete", self.service_name])
        return ServiceResult(code == 0, err or "removed")
