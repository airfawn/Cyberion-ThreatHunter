from __future__ import annotations

from pathlib import Path

from installer.models import InstallPaths
from installer.service.windows_service import WindowsServiceManager


class WindowsInstaller:
    def __init__(self, paths: InstallPaths, run_command_line: str):
        self.paths = paths
        self.service = WindowsServiceManager(run_command_line)

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
