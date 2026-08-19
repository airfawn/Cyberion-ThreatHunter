from __future__ import annotations

import os
from pathlib import Path

from installer.service.base import ServiceResult, ensure_file, run_command


LABEL = "com.cyberion.agent"


class LaunchdServiceManager:
    def __init__(
        self,
        plist_path: Path,
        run_args: list[str],
        log_dir: Path,
        label: str = LABEL,
        log_prefix: str = "agent",
        domain: str = "system",
    ):
        self.plist_path = plist_path
        self.run_args = run_args
        self.log_dir = log_dir
        self.label = label
        self.log_prefix = log_prefix
        self.domain = domain

    def install(self) -> ServiceResult:
        program_xml = "\n".join([f"        <string>{arg}</string>" for arg in self.run_args])
        self.log_dir.mkdir(parents=True, exist_ok=True)
        content = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>{self.label}</string>
    <key>ProgramArguments</key>
    <array>
{program_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>StandardOutPath</key>
    <string>{self.log_dir / f'{self.log_prefix}.out.log'}</string>
    <key>StandardErrorPath</key>
    <string>{self.log_dir / f'{self.log_prefix}.err.log'}</string>
</dict>
</plist>
"""
        ensure_file(self.plist_path, content, 0o644)
        run_command(["launchctl", "bootout", self.domain, str(self.plist_path)])
        code, _, err = run_command(["launchctl", "bootstrap", self.domain, str(self.plist_path)])
        return ServiceResult(code == 0, err or "loaded")

    def start(self) -> ServiceResult:
        code, _, err = run_command(["launchctl", "kickstart", "-k", f"{self.domain}/{self.label}"])
        return ServiceResult(code == 0, err or "started")

    def stop(self) -> ServiceResult:
        code, _, err = run_command(["launchctl", "bootout", self.domain, str(self.plist_path)])
        if self._is_not_found_message(err):
            return ServiceResult(True, "service already stopped")
        return ServiceResult(code == 0, err or "stopped")

    def status(self) -> ServiceResult:
        code, out, err = run_command(["launchctl", "print", f"{self.domain}/{self.label}"])
        if self._is_not_found_message(err) or self._is_not_found_message(out):
            return ServiceResult(False, "service not installed")
        running = code == 0 and "state = running" in out
        if running:
            return ServiceResult(True, "running")
        return ServiceResult(False, out or err or "service not running")

    def uninstall(self) -> ServiceResult:
        _, _, err = run_command(["launchctl", "bootout", self.domain, str(self.plist_path)])
        if err and not self._is_not_found_message(err):
            return ServiceResult(False, err)
        if self.plist_path.exists():
            self.plist_path.unlink()
        return ServiceResult(True, "removed")

    def _is_not_found_message(self, text: str) -> bool:
        normalized = (text or "").lower()
        return (
            "could not find service" in normalized
            or "service not found" in normalized
            or "boot-out failed: 5" in normalized
            or "input/output error" in normalized
        )


def launchd_domain_for_user_mode(user_mode: bool) -> str:
    if user_mode:
        return f"gui/{os.getuid()}"
    return "system"
