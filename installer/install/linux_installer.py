from __future__ import annotations

from installer.models import InstallPaths
from installer.service.systemd_service import SystemdServiceManager


class LinuxInstaller:
    def __init__(self, paths: InstallPaths, run_command_line: str, user_mode: bool):
        self.paths = paths
        self.service = SystemdServiceManager(paths.service_dir, run_command_line, user_mode=user_mode)

    def install_service(self):
        result = self.service.install()
        if not result.ok:
            raise RuntimeError(result.message)
        self.service.start()

    def start(self):
        return self.service.start()

    def stop(self):
        return self.service.stop()

    def restart(self):
        self.stop()
        return self.start()

    def status(self):
        return self.service.status()

    def uninstall_service(self):
        return self.service.uninstall()
