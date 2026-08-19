from __future__ import annotations

import json
from pathlib import Path

import pytest

from installer.config.config_manager import ConfigManager
from installer.detection.architecture_detection import detect_architecture
from installer.detection.os_detection import detect_os_family
from installer.install.common import resolve_install_paths
from installer.install.universal_installer import UniversalInstaller
from installer.logs.installer_logging import redact
from installer.models import InstallOptions, PlatformInfo
from installer.uninstall.universal_uninstaller import UniversalUninstaller


class DummyServiceAdapter:
    def __init__(self):
        self.started = False

    def install_service(self):
        return None

    def start(self):
        self.started = True
        return type("R", (), {"ok": True, "message": "running"})()

    def stop(self):
        self.started = False
        return type("R", (), {"ok": True, "message": "stopped"})()

    def restart(self):
        self.started = True
        return type("R", (), {"ok": True, "message": "running"})()

    def status(self):
        return type("R", (), {"ok": True, "message": "active"})()

    def uninstall_service(self):
        return type("R", (), {"ok": True, "message": "removed"})()


@pytest.fixture
def installer_tmp(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERION_INSTALLER_ROOT", str(tmp_path / "install-root"))
    opts = InstallOptions(silent=True, server="https://example.local", token="SECRET_TOKEN", name="HOST-001", force=True)
    installer = UniversalInstaller(repo_root=Path(__file__).resolve().parent.parent, options=opts)

    monkeypatch.setattr(installer, "_prepare_runtime", lambda allow_failure=False: None)
    monkeypatch.setattr(installer, "_validate_dependencies", lambda: type("D", (), {
        "standalone_binary_found": True,
        "python_version": "3.11.0",
        "openss_ok": True,
    })())
    monkeypatch.setattr(installer, "_connectivity_check", lambda: (True, "OK"))
    monkeypatch.setattr(installer, "_enrollment_check", lambda: (True, "OK"))

    adapter = DummyServiceAdapter()
    monkeypatch.setattr(installer, "_build_platform_adapter", lambda *_args, **_kwargs: adapter)
    return installer


def test_os_detection_known_values(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Windows")
    assert detect_os_family() == "windows"

    monkeypatch.setattr("platform.system", lambda: "Linux")
    assert detect_os_family() == "linux"

    monkeypatch.setattr("platform.system", lambda: "Darwin")
    assert detect_os_family() == "macos"


def test_arch_detection_known_values(monkeypatch):
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    assert detect_architecture() == "x86_64"

    monkeypatch.setattr("platform.machine", lambda: "AMD64")
    assert detect_architecture() == "x86_64"

    monkeypatch.setattr("platform.machine", lambda: "arm64")
    assert detect_architecture() == "arm64"

    monkeypatch.setattr("platform.machine", lambda: "aarch64")
    assert detect_architecture() == "arm64"


def test_install_paths_override(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERION_INSTALLER_ROOT", str(tmp_path / "custom"))
    info = PlatformInfo(os_family="linux", architecture="x86_64", privilege="admin")
    paths = resolve_install_paths(info)
    assert paths.root == tmp_path / "custom"
    assert paths.config_dir.name == "config"


def test_fresh_install_flow(installer_tmp):
    code = installer_tmp.install()
    assert code == 0
    assert installer_tmp.config_manager.config_file.exists()
    manifest = installer_tmp.config_manager.read_manifest()
    assert manifest.get("version")


def test_repair_flow(installer_tmp):
    installer_tmp.install()
    installer_tmp.config_manager.config_file.unlink()
    code = installer_tmp.repair()
    assert code == 0
    assert installer_tmp.config_manager.config_file.exists()


def test_uninstall_preserve_default(installer_tmp):
    installer_tmp.install()
    code = UniversalUninstaller(installer_tmp, purge=False, preserve_config=True).uninstall()
    assert code == 0
    assert installer_tmp.paths.root.exists() is False


def test_uninstall_purge(installer_tmp):
    installer_tmp.install()
    code = UniversalUninstaller(installer_tmp, purge=True, preserve_config=False).uninstall()
    assert code == 0
    assert not installer_tmp.paths.config_dir.exists()
    assert not installer_tmp.paths.state_dir.exists()


def test_identity_persisted_across_upgrade_style_reinstall(installer_tmp):
    installer_tmp.install()
    initial = json.loads(installer_tmp.config_manager.identity_file.read_text(encoding="utf-8"))["agent_id"]

    installer_tmp.install()
    second = json.loads(installer_tmp.config_manager.identity_file.read_text(encoding="utf-8"))["agent_id"]
    assert initial == second


def test_redaction_never_exposes_token():
    raw = "server=https://example token=ABC123 enrollment_token=XYZ987"
    out = redact(raw)
    assert "ABC123" not in out
    assert "XYZ987" not in out


def test_config_validation_detects_missing_host(monkeypatch, tmp_path):
    paths = resolve_install_paths(PlatformInfo(os_family="linux", architecture="x86_64", privilege="admin"))
    paths = paths.__class__(
        root=tmp_path / "r",
        bin_dir=tmp_path / "r/bin",
        config_dir=tmp_path / "cfg",
        log_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
        certs_dir=tmp_path / "state/certs",
        runtime_dir=tmp_path / "state/runtime",
        service_dir=tmp_path / "svc",
    )
    mgr = ConfigManager(paths)
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    mgr.config_file.write_text("agent:\n  id: abc\nserver: {}\n", encoding="utf-8")
    ok, message = mgr.validate()
    assert not ok
    assert "server.host" in message
