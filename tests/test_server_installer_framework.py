from __future__ import annotations

from pathlib import Path

import pytest

from installer.models import InstallOptions
from installer.server.universal_server_installer import UniversalServerInstaller
from installer.server_cli import build_parser


class DummyAdapter:
    def install(self):
        return type("R", (), {"ok": True, "message": "installed"})()

    def start(self):
        return type("R", (), {"ok": True, "message": "running"})()

    def stop(self):
        return type("R", (), {"ok": True, "message": "stopped"})()

    def status(self):
        return type("R", (), {"ok": True, "message": "active"})()

    def uninstall(self):
        return type("R", (), {"ok": True, "message": "removed"})()


@pytest.fixture
def server_installer(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERION_SERVER_INSTALLER_ROOT", str(tmp_path / "server-root"))
    opts = InstallOptions(silent=True, force=True, mode="install")
    installer = UniversalServerInstaller(Path(__file__).resolve().parent.parent, opts)

    class _Deps:
        message = ""
        standalone_binary_found = True

    monkeypatch.setattr("installer.server.universal_server_installer.detect_dependencies", lambda _repo_root: _Deps())
    monkeypatch.setattr(installer, "_adapter", lambda *_args, **_kwargs: DummyAdapter())
    monkeypatch.setattr(installer, "_connectivity", lambda: (True, "OK"))
    return installer


def test_server_cli_parser_commands():
    parser = build_parser()
    args = parser.parse_args(["install", "--silent"])
    assert args.command == "install"
    assert args.silent is True


def test_server_install_flow(server_installer):
    code = server_installer.install()
    assert code == 0
    assert server_installer.config_file.exists()


def test_server_repair_flow(server_installer):
    server_installer.install()
    server_installer.config_file.unlink()
    code = server_installer.repair()
    assert code == 0
    assert server_installer.config_file.exists()


def test_server_uninstall_purge(server_installer):
    server_installer.install()
    code = server_installer.uninstall(purge=True)
    assert code == 0
    assert not server_installer.paths.root.exists()
