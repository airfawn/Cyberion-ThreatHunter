from __future__ import annotations

import ctypes
import os
import platform


def is_admin_or_root() -> bool:
    if platform.system().lower().startswith("win"):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def privilege_level() -> str:
    return "admin" if is_admin_or_root() else "user"
