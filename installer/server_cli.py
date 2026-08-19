from __future__ import annotations

import argparse
from pathlib import Path

from installer.models import InstallOptions
from installer.server.universal_server_installer import UniversalServerInstaller


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberion-server", description="Cyberion Server universal installer and service manager")
    sub = parser.add_subparsers(dest="command", required=True)

    launch_gui_commands = {"install", "upgrade", "repair", "start", "restart"}

    for name in ["install", "upgrade", "repair", "uninstall", "start", "stop", "restart", "status", "version", "diagnostics", "gui"]:
        cmd = sub.add_parser(name)
        cmd.add_argument("--silent", action="store_true")
        cmd.add_argument("--log-level", default="INFO")
        cmd.add_argument("--force", action="store_true")
        cmd.add_argument("--purge", action="store_true")
        if name in launch_gui_commands:
            cmd.add_argument("--launch-gui", dest="launch_gui", action="store_true", default=True)
            cmd.add_argument("--no-launch-gui", dest="launch_gui", action="store_false")

    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    opts = InstallOptions(
        silent=args.silent,
        log_level=args.log_level,
        force=args.force,
        purge=args.purge,
        mode=args.command,
        launch_gui=getattr(args, "launch_gui", False),
    )
    repo_root = Path(__file__).resolve().parent.parent
    installer = UniversalServerInstaller(repo_root, opts)

    if args.command == "install":
        return installer.install()
    if args.command == "upgrade":
        return installer.upgrade()
    if args.command == "repair":
        return installer.repair()
    if args.command == "uninstall":
        return installer.uninstall(purge=args.purge)
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
    if args.command == "gui":
        return installer.launch_gui()

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(run())
