from __future__ import annotations

import shutil
from pathlib import Path


class UpgradeManager:
    def __init__(self, installer):
        self.installer = installer

    def upgrade(self) -> int:
        self.installer._print_banner("Upgrade")
        backup = self._backup_current()
        self.installer.stop()
        previous_mode = self.installer.options.mode
        previous_force = self.installer.options.force
        self.installer.options.mode = "upgrade"
        self.installer.options.force = True

        try:
            code = self.installer.install()
            if code != 0:
                raise RuntimeError("upgrade failed")
            return code
        except Exception as exc:
            print(f"Upgrade failed: {exc}. Attempting rollback...")
            self._rollback(backup)
            self.installer.start()
            return 1
        finally:
            self.installer.options.mode = previous_mode
            self.installer.options.force = previous_force

    def repair(self) -> int:
        return self.installer.repair()

    def _backup_current(self) -> Path:
        backup_root = self.installer.paths.state_dir / "rollback"
        backup_root.mkdir(parents=True, exist_ok=True)
        backup = backup_root / "app_backup"
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
        if self.installer.paths.root.exists():
            shutil.copytree(self.installer.paths.root, backup, dirs_exist_ok=True)
        return backup

    def _rollback(self, backup: Path) -> None:
        if not backup.exists():
            return
        if self.installer.paths.root.exists():
            shutil.rmtree(self.installer.paths.root, ignore_errors=True)
        shutil.copytree(backup, self.installer.paths.root, dirs_exist_ok=True)
