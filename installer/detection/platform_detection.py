from __future__ import annotations

import socket
import platform

from installer.detection.architecture_detection import detect_architecture
from installer.detection.os_detection import detect_linux_distribution, detect_os_family
from installer.detection.privilege_detection import privilege_level
from installer.models import PlatformInfo


def detect_platform() -> PlatformInfo:
    os_family = detect_os_family()
    distro = detect_linux_distribution() if os_family == "linux" else None
    return PlatformInfo(
        os_family=os_family,
        architecture=detect_architecture(),
        privilege=privilege_level(),
        linux_distribution=distro,
        os_version=platform.version(),
        hostname=socket.gethostname(),
    )
