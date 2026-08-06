import json
import os
import platform
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


class Collector:
    """Collects Linux system logs from various sources."""

    def __init__(self, send_callback, interval=10):
        self.send_callback = send_callback
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = None
        self._last_positions = {}
        self._journalctl_available = self._check_journalctl()
        self._log_files = self._discover_log_files()

    def _check_journalctl(self) -> bool:
        return Path("/usr/bin/journalctl").exists() or Path("/bin/journalctl").exists()

    def _discover_log_files(self) -> dict[str, Path]:
        candidates = {
            "syslog": Path("/var/log/syslog"),
            "auth": Path("/var/log/auth.log"),
            "kern": Path("/var/log/kern.log"),
            "audit": Path("/var/log/audit/audit.log"),
            "messages": Path("/var/log/messages"),
            "secure": Path("/var/log/secure"),
        }
        return {name: path for name, path in candidates.items() if path.exists()}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._collect_all()
            except Exception as e:
                print(f"[Collector] Error during collection: {e}")
            self._stop_event.wait(self.interval)

    def _collect_all(self):
        if self._journalctl_available:
            self._collect_journald()
        self._collect_log_files()

    def _collect_journald(self):
        self._collect_journal_unit("ssh", "ssh.service")
        self._collect_journal_unit("sshd", "sshd.service")
        self._collect_journal_unit("sudo", "sudo")
        self._collect_journal_unit("systemd", "systemd")
        self._collect_journal_kernel()
        self._collect_journal_audit()

    def _collect_journal_unit(self, source_name: str, unit: str):
        cursor_file = Path(f"/tmp/cyberion_journal_cursor_{source_name}")
        cursor = cursor_file.read_text().strip() if cursor_file.exists() else None

        cmd = ["journalctl", "-u", unit, "-o", "json", "--no-pager"]
        if cursor:
            cmd.extend(["--after-cursor", cursor])
        else:
            cmd.extend(["--since", "1 minute ago"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return
        except Exception as e:
            print(f"[Collector] journalctl error for {unit}: {e}")
            return

        lines = result.stdout.strip().split("\n")
        new_cursor = None
        for line in lines:
            if not line:
                continue
            try:
                entry = json.loads(line)
                cursor = entry.get("__CURSOR")
                if cursor:
                    new_cursor = cursor
                message = entry.get("MESSAGE", "")
                if message:
                    self._send_event(
                        source=f"journald:{source_name}",
                        raw_event=message,
                        event_type="journald_log",
                    )
            except json.JSONDecodeError:
                continue

        if new_cursor:
            try:
                cursor_file.write_text(new_cursor)
            except Exception:
                pass

    def _collect_journal_kernel(self):
        cursor_file = Path("/tmp/cyberion_journal_cursor_kernel")
        cursor = cursor_file.read_text().strip() if cursor_file.exists() else None

        cmd = ["journalctl", "-k", "-o", "json", "--no-pager"]
        if cursor:
            cmd.extend(["--after-cursor", cursor])
        else:
            cmd.extend(["--since", "1 minute ago"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return
        except Exception as e:
            print(f"[Collector] journalctl kernel error: {e}")
            return

        lines = result.stdout.strip().split("\n")
        new_cursor = None
        for line in lines:
            if not line:
                continue
            try:
                entry = json.loads(line)
                cursor = entry.get("__CURSOR")
                if cursor:
                    new_cursor = cursor
                message = entry.get("MESSAGE", "")
                if message:
                    self._send_event(
                        source="journald:kernel",
                        raw_event=message,
                        event_type="journald_log",
                    )
            except json.JSONDecodeError:
                continue

        if new_cursor:
            try:
                cursor_file.write_text(new_cursor)
            except Exception:
                pass

    def _collect_journal_audit(self):
        cursor_file = Path("/tmp/cyberion_journal_cursor_audit")
        cursor = cursor_file.read_text().strip() if cursor_file.exists() else None

        cmd = ["journalctl", "-u", "auditd", "-o", "json", "--no-pager"]
        if cursor:
            cmd.extend(["--after-cursor", cursor])
        else:
            cmd.extend(["--since", "1 minute ago"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return
        except Exception as e:
            print(f"[Collector] journalctl audit error: {e}")
            return

        lines = result.stdout.strip().split("\n")
        new_cursor = None
        for line in lines:
            if not line:
                continue
            try:
                entry = json.loads(line)
                cursor = entry.get("__CURSOR")
                if cursor:
                    new_cursor = cursor
                message = entry.get("MESSAGE", "")
                if message:
                    self._send_event(
                        source="journald:audit",
                        raw_event=message,
                        event_type="journald_log",
                    )
            except json.JSONDecodeError:
                continue

        if new_cursor:
            try:
                cursor_file.write_text(new_cursor)
            except Exception:
                pass

    def _collect_log_files(self):
        for name, path in self._log_files.items():
            try:
                self._collect_log_file(name, path)
            except Exception as e:
                print(f"[Collector] Failed to collect {name}: {e}")

    def _collect_log_file(self, name: str, path: Path):
        last_pos = self._last_positions.get(str(path), 0)
        try:
            current_size = path.stat().st_size
        except Exception:
            return

        if current_size < last_pos:
            last_pos = 0

        if current_size == last_pos:
            return

        try:
            with path.open("r") as f:
                f.seek(last_pos)
                new_lines = f.readlines()
                self._last_positions[str(path)] = f.tell()
        except PermissionError:
            print(f"[Collector] Permission denied reading {path}")
            return
        except Exception as e:
            print(f"[Collector] Error reading {path}: {e}")
            return

        for line in new_lines:
            line = line.rstrip("\n")
            if line:
                self._send_event(
                    source=f"log:{name}",
                    raw_event=line,
                    event_type="syslog",
                )

    def _send_event(self, source: str, raw_event: str, event_type: str):
        event = {
            "source": source,
            "raw_event": raw_event,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "event_type": event_type,
        }
        try:
            self.send_callback(event)
        except Exception as e:
            print(f"[Collector] Send callback error: {e}")


def gather_initial_data() -> dict:
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "unknown"

    try:
        with open("/etc/os-release") as f:
            os_release = {}
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    os_release[k] = v.strip('"')
    except Exception:
        os_release = {}

    return {
        "agent_id": str(uuid.getnode()),
        "hostname": hostname,
        "ip_address": ip_address,
        "os_name": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "kernel_version": platform.release(),
        "architecture": platform.machine(),
        "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
        "platform": platform.platform(),
        "processor": platform.processor(),
        "os_distribution": os_release.get("PRETTY_NAME", ""),
        "os_id": os_release.get("ID", ""),
        "os_version_id": os_release.get("VERSION_ID", ""),
    }