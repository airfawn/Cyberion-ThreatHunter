from __future__ import annotations

import argparse
from pathlib import Path

from installer.install.universal_installer import UniversalInstaller
from installer.models import InstallOptions
from installer.uninstall.universal_uninstaller import UniversalUninstaller
from installer.upgrade.upgrade_manager import UpgradeManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberion-agent", description="Cyberion Agent universal installer and service manager")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ["install", "upgrade", "repair", "uninstall", "start", "stop", "restart", "status", "version", "diagnostics"]:
        cmd = sub.add_parser(name)
        _add_common_flags(cmd)

    return parser


def _add_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--silent", action="store_true", help="Run without interactive prompts")
    parser.add_argument("--server", default="", help="Cyberion server URL")
    parser.add_argument("--token", default="", help="Enrollment token")
    parser.add_argument("--name", default="", help="Agent display name")
    parser.add_argument("--config", default="", help="Path to existing config file")
    parser.add_argument("--log-level", default="INFO", help="Installer log level")
    parser.add_argument("--preserve-config", action="store_true", default=True, help="Preserve config on uninstall")
    parser.add_argument("--purge", action="store_true", help="Purge config/state/logs during uninstall")
    parser.add_argument("--force", action="store_true", help="Force operation")


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    opts = InstallOptions(
        silent=args.silent,
        server=args.server,
        token=args.token,
        name=args.name,
        config_path=args.config,
        log_level=args.log_level,
        preserve_config=args.preserve_config,
        purge=args.purge,
        force=args.force,
        mode=args.command,
    )

    repo_root = Path(__file__).resolve().parent.parent
    installer = UniversalInstaller(repo_root=repo_root, options=opts)

    if args.command == "install":
        return installer.install()
    if args.command == "upgrade":
        return UpgradeManager(installer).upgrade()
    if args.command == "repair":
        return installer.repair()
    if args.command == "uninstall":
        return UniversalUninstaller(installer, purge=args.purge, preserve_config=args.preserve_config).uninstall()
    if args.command == "start":
        return installer.start()
    if args.command == "stop":
        return installer.stop()
    if args.command == "restart":
        return installer.restart()
    if args.command == "status":
        return installer.status()
    if args.command == "version":
        print(installer._version())
        return 0
    if args.command == "diagnostics":
        return installer.diagnostics()

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(run())
