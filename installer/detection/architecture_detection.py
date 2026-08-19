from __future__ import annotations

import platform


def detect_architecture() -> str:
    machine = platform.machine().strip().lower()
    if machine in {"x86_64", "amd64"}:
        return "x86_64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    return "unsupported"
