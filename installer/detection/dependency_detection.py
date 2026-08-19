from __future__ import annotations

import importlib.metadata
import ssl
import subprocess
import sys
from pathlib import Path
from typing import List

from installer.models import DependencyStatus


def _parse_requirements(req_path: Path) -> List[str]:
    if not req_path.exists():
        return []
    names = []
    for line in req_path.read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        for splitter in ("==", ">=", "<=", "~=", ">", "<"):
            if splitter in item:
                item = item.split(splitter, 1)[0].strip()
                break
        if item:
            names.append(item)
    return names


def detect_dependencies(repo_root: Path, python_required: str = "3.10") -> DependencyStatus:
    standalone = (repo_root / "bin" / "cyberion-agent").exists() or (repo_root / "dist" / "cyberion-agent").exists()

    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = (sys.version_info.major, sys.version_info.minor) >= tuple(int(v) for v in python_required.split(".")[:2])

    openssl_ok = bool(getattr(ssl, "OPENSSL_VERSION", ""))

    missing_imports: List[str] = []
    requirements = _parse_requirements(repo_root / "requirements.txt")
    if not requirements:
        requirements = _parse_requirements(repo_root / "src" / "requirements.txt")

    for pkg in requirements:
        try:
            importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            missing_imports.append(pkg)

    message = ""
    if not py_ok:
        message = (
            "Cyberion Agent installation failed.\n\n"
            "Missing dependency:\n"
            f"Python >= {python_required}\n\n"
            f"Detected:\nPython {py_version}\n\n"
            f"Required:\nPython {python_required}+"
        )

    return DependencyStatus(
        python_ok=py_ok,
        python_version=py_version,
        python_required=python_required,
        openssl_ok=openssl_ok,
        missing_imports=missing_imports,
        standalone_binary_found=standalone,
        message=message,
    )


def create_venv_and_install(repo_root: Path, venv_dir: Path, requirements_file: Path) -> None:
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    if platform_is_windows():
        pip_cmd = venv_dir / "Scripts" / "pip.exe"
        py_cmd = venv_dir / "Scripts" / "python.exe"
    else:
        pip_cmd = venv_dir / "bin" / "pip"
        py_cmd = venv_dir / "bin" / "python"

    subprocess.run([str(pip_cmd), "install", "--upgrade", "pip"], check=True)
    subprocess.run([str(pip_cmd), "install", "-r", str(requirements_file)], check=True)

    # Verify core imports after installation.
    subprocess.run([str(py_cmd), "-c", "import yaml, PyQt5"], check=True)


def platform_is_windows() -> bool:
    import platform

    return platform.system().lower().startswith("win")
