from __future__ import annotations

from pathlib import Path

from installer.models import InstallPaths
from installer.service.launchd_service import LABEL, LaunchdServiceManager, launchd_domain_for_user_mode


class MacOSInstaller:
    def __init__(self, paths: InstallPaths, run_args: list[str], user_mode: bool):
        plist_name = f"{LABEL}.plist"
        plist_path = (paths.service_dir / plist_name) if paths.service_dir else (paths.root / plist_name)
        domain = launchd_domain_for_user_mode(user_mode)
        self.service = LaunchdServiceManager(
            plist_path=plist_path,
            run_args=run_args,
            log_dir=paths.log_dir,
            domain=domain,
        )

    def install_service(self):
        result = self.service.install()
        if not result.ok:
            raise RuntimeError(result.message)

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
