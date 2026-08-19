from __future__ import annotations

import platform
from pathlib import Path


def detect_os_family() -> str:
    raw = platform.system().lower()
    if raw.startswith("win"):
        return "windows"
    if raw == "darwin":
        return "macos"
    if raw == "linux":
        return "linux"
    return "unknown"


def detect_linux_distribution() -> str:
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return "other"

    data = {}
    for line in os_release.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').lower()

    candidate = data.get("id", "other")
    if candidate in {"ubuntu", "debian", "fedora", "rhel", "centos", "arch"}:
        return candidate
    if candidate in {"rocky", "almalinux", "ol"}:
        return "rhel"
    return "other"
