from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


SUPPORTED_OSES = {"windows", "linux", "macos"}
SUPPORTED_ARCHES = {"x86_64", "arm64"}
SUPPORTED_LINUX_DISTROS = {
    "ubuntu",
    "debian",
    "fedora",
    "rhel",
    "centos",
    "arch",
    "other",
}


@dataclass
class PlatformInfo:
    os_family: str
    architecture: str
    privilege: str
    linux_distribution: Optional[str] = None
    os_version: str = ""
    hostname: str = ""


@dataclass
class InstallPaths:
    root: Path
    bin_dir: Path
    config_dir: Path
    log_dir: Path
    state_dir: Path
    certs_dir: Path
    runtime_dir: Path
    service_dir: Optional[Path] = None


@dataclass
class DependencyStatus:
    python_ok: bool
    python_version: str
    python_required: str
    openssl_ok: bool
    missing_imports: List[str] = field(default_factory=list)
    standalone_binary_found: bool = False
    message: str = ""


@dataclass
class InstallOptions:
    silent: bool = False
    server: str = ""
    token: str = ""
    name: str = ""
    config_path: str = ""
    log_level: str = "INFO"
    preserve_config: bool = True
    purge: bool = False
    force: bool = False
    preserve_identity: bool = True
    mode: str = "install"
    launch_gui: bool = False


@dataclass
class HealthCheckResult:
    checks: Dict[str, bool] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def ok(self) -> bool:
        return all(self.checks.values()) and not self.errors
