import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_SOURCES_BY_OS = {
    "windows": [
        "windows_security",
        "sysmon",
        "powershell",
        "defender",
        "firewall",
    ],
    "macos": [
        "endpointsecurity_process",
        "endpointsecurity_file",
        "endpointsecurity_network",
        "unifiedlog_auth",
        "unifiedlog_system",
        "unifiedlog_app",
    ],
    "linux": [
        "journald",
        "syslog",
        "auth",
        "kern",
        "audit",
    ],
}


def detect_runtime_platform() -> dict:
    os_name = platform.system().strip().lower()
    if os_name == "darwin":
        os_family = "macos"
    elif os_name.startswith("win"):
        os_family = "windows"
    else:
        os_family = "linux"

    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "unknown"

    return {
        "os_family": os_family,
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": hostname,
        "ip_address": ip_address,
        "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
        "platform": platform.platform(),
        "processor": platform.processor(),
    }


class Collector:
    """Collects system logs from OS-specific sources and normalizes events."""

    def __init__(
        self,
        send_callback,
        interval=10,
        selected_sources=None,
        os_sources=None,
        runtime_info=None,
    ):
        self.send_callback = send_callback
        self.interval = interval
        self.selected_sources = selected_sources or []
        self.os_sources = os_sources or {}
        self.runtime_info = runtime_info or detect_runtime_platform()
        self.os_family = self.runtime_info.get("os_family", "linux")

        self._stop_event = threading.Event()
        self._thread = None
        self._last_positions = {}
        self._source_cursors = {}
        self._recent_signatures = deque(maxlen=4000)

        self._journalctl_available = self._check_journalctl()
        self._log_files = self._discover_log_files()
        self._active_sources = self._resolve_active_sources()

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

    def _resolve_active_sources(self) -> list[str]:
        if self.selected_sources:
            return [str(item).strip() for item in self.selected_sources if str(item).strip()]

        configured = self.os_sources.get(self.os_family, [])
        if isinstance(configured, str):
            configured = [configured]
        if isinstance(configured, list) and configured:
            return [str(item).strip() for item in configured if str(item).strip()]

        return list(DEFAULT_SOURCES_BY_OS.get(self.os_family, []))

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
        if self.os_family == "windows":
            self._collect_windows_sources()
            return
        if self.os_family == "macos":
            self._collect_macos_sources()
            return
        self._collect_linux_sources()

    # ------------------------------------------------------------------
    # Linux collection
    # ------------------------------------------------------------------

    def _collect_linux_sources(self):
        if "journald" in self._active_sources and self._journalctl_available:
            self._collect_journald()
        if any(source in self._active_sources for source in self._log_files):
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
                        parsed=self._parse_journald_entry(entry),
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
                        parsed=self._parse_journald_entry(entry),
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
                        parsed=self._parse_journald_entry(entry),
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
            if name not in self._active_sources:
                continue
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
                    parsed=self._parse_text_event(line),
                )

    # ------------------------------------------------------------------
    # Windows collection
    # ------------------------------------------------------------------

    def _collect_windows_sources(self):
        mapping = {
            "windows_security": ("Security", "windows_security_event"),
            "sysmon": ("Microsoft-Windows-Sysmon/Operational", "sysmon_event"),
            "powershell": ("Windows PowerShell", "powershell_event"),
            "defender": ("Microsoft-Windows-Windows Defender/Operational", "defender_event"),
            "firewall": ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "firewall_event"),
        }
        for source in self._active_sources:
            if source not in mapping:
                continue
            channel, event_type = mapping[source]
            self._collect_windows_channel(source, channel, event_type)

    def _collect_windows_channel(self, source: str, channel: str, event_type: str):
        last_record = int(self._source_cursors.get(source, 0))
        cmd = ["wevtutil", "qe", channel, "/rd:true", "/c:40", "/f:text"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        except Exception:
            return

        if result.returncode != 0:
            return

        blocks = [chunk.strip() for chunk in result.stdout.split("\n\n") if chunk.strip()]
        max_record = last_record
        for block in reversed(blocks):
            record = self._extract_windows_record_id(block)
            if record <= last_record:
                continue
            max_record = max(max_record, record)
            if self._is_duplicate(source, str(record)):
                continue
            self._send_event(
                source=source,
                raw_event=block,
                event_type=event_type,
                parsed=self._parse_text_event(block),
            )
        self._source_cursors[source] = max_record

    def _extract_windows_record_id(self, text: str) -> int:
        m = re.search(r"Record\s+ID:\s*(\d+)", text, re.IGNORECASE)
        if not m:
            return 0
        try:
            return int(m.group(1))
        except ValueError:
            return 0

    # ------------------------------------------------------------------
    # macOS collection
    # ------------------------------------------------------------------

    def _collect_macos_sources(self):
        predicates = {
            "endpointsecurity_process": 'eventMessage CONTAINS[c] "exec" OR eventMessage CONTAINS[c] "process"',
            "endpointsecurity_file": 'eventMessage CONTAINS[c] "file" OR eventMessage CONTAINS[c] "open" OR eventMessage CONTAINS[c] "write"',
            "endpointsecurity_network": 'eventMessage CONTAINS[c] "network" OR eventMessage CONTAINS[c] "connection"',
            "unifiedlog_auth": 'eventMessage CONTAINS[c] "authentication" OR eventMessage CONTAINS[c] "login"',
            "unifiedlog_system": 'subsystem CONTAINS[c] "system"',
            "unifiedlog_app": 'processImagePath != ""',
        }
        for source in self._active_sources:
            predicate = predicates.get(source)
            if not predicate:
                continue
            self._collect_macos_unified_log(source, predicate)

    def _collect_macos_unified_log(self, source: str, predicate: str):
        cmd = [
            "log",
            "show",
            "--last",
            "1m",
            "--style",
            "json",
            "--predicate",
            predicate,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception:
            return

        if result.returncode != 0:
            return

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            signature = f"{source}:{hash(line)}"
            if self._is_duplicate(source, signature):
                continue
            try:
                entry = json.loads(line)
                raw_text = entry.get("eventMessage") or line
            except json.JSONDecodeError:
                entry = {}
                raw_text = line
            self._send_event(
                source=source,
                raw_event=raw_text,
                event_type="unified_log_event",
                parsed=self._parse_macos_log_entry(entry, raw_text),
            )

    def _is_duplicate(self, source: str, signature: str) -> bool:
        key = f"{source}:{signature}"
        if key in self._recent_signatures:
            return True
        self._recent_signatures.append(key)
        return False

    # ------------------------------------------------------------------
    # Normalization and parsing
    # ------------------------------------------------------------------

    def _send_event(self, source: str, raw_event: str, event_type: str, parsed: dict | None = None):
        normalized = self._normalize_event(source, raw_event, event_type, parsed=parsed)
        event = {
            "source": source,
            "raw_event": json.dumps(normalized, ensure_ascii=False),
            "timestamp": normalized["timestamp"],
            "event_type": normalized["event_type"],
        }
        try:
            self.send_callback(event)
        except Exception as e:
            print(f"[Collector] Send callback error: {e}")

    def _normalize_event(self, source: str, raw_event: str, event_type: str, parsed: dict | None = None) -> dict:
        parsed = parsed or {}
        ts = parsed.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        host = parsed.get("host") or self.runtime_info.get("hostname", "unknown")
        user = parsed.get("user") or self.runtime_info.get("username", "unknown")
        command_line = str(parsed.get("command_line") or "")
        process_name = str(parsed.get("process_name") or "")
        if not process_name and command_line:
            first_token = command_line.strip().split(" ", 1)[0].strip('"').strip("'")
            if first_token:
                process_name = Path(first_token).name

        normalized = {
            "timestamp": str(ts),
            "host": str(host),
            "os": str(self.os_family),
            "architecture": str(self.runtime_info.get("architecture", "unknown")),
            "event_type": str(parsed.get("event_type") or event_type),
            "process_name": process_name,
            "pid": self._to_int(parsed.get("pid")),
            "ppid": self._to_int(parsed.get("ppid")),
            "user": str(user),
            "command_line": command_line,
            "source_ip": str(parsed.get("source_ip") or ""),
            "destination_ip": str(parsed.get("destination_ip") or ""),
            "source": source,
            "message": raw_event,
        }
        return normalized

    def _to_int(self, value):
        try:
            if value in (None, ""):
                return None
            return int(value)
        except (ValueError, TypeError):
            return None

    def _parse_journald_entry(self, entry: dict) -> dict:
        message = str(entry.get("MESSAGE") or "")
        parsed = self._parse_text_event(message)
        parsed["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        parsed["process_name"] = parsed.get("process_name") or str(entry.get("SYSLOG_IDENTIFIER") or "")
        parsed["user"] = parsed.get("user") or str(entry.get("_UID") or "")
        return parsed

    def _parse_macos_log_entry(self, entry: dict, raw_text: str) -> dict:
        parsed = self._parse_text_event(raw_text)
        parsed["timestamp"] = entry.get("timestamp") or parsed.get("timestamp")
        parsed["process_name"] = parsed.get("process_name") or entry.get("processImagePath") or entry.get("process") or ""
        parsed["user"] = parsed.get("user") or entry.get("senderImageUUID") or ""
        return parsed

    def _parse_text_event(self, text: str) -> dict:
        parsed: dict = {}

        explicit_proc = re.search(r"\bprocess(?:_name)?[=: ]+([A-Za-z0-9_.\\-]+)\b", text, re.IGNORECASE)
        if explicit_proc:
            parsed["process_name"] = explicit_proc.group(1)

        proc = re.search(r"([A-Za-z0-9_.-]+)(?:\[(\d+)\])?:", text)
        if proc and "process_name" not in parsed:
            if proc.group(1).lower() not in {"record", "id"}:
                parsed["process_name"] = proc.group(1)
        if proc:
            if proc.group(2):
                parsed["pid"] = proc.group(2)

        if parsed.get("process_name", "").lower() in {"record", "id"}:
            parsed.pop("process_name", None)

        pid = re.search(r"\bpid[=: ]+(\d+)\b", text, re.IGNORECASE)
        if pid:
            parsed["pid"] = pid.group(1)

        ppid = re.search(r"\bppid[=: ]+(\d+)\b", text, re.IGNORECASE)
        if ppid:
            parsed["ppid"] = ppid.group(1)

        user = re.search(r"\buser(?:name)?[=: ]+([A-Za-z0-9_.\\-]+)\b", text, re.IGNORECASE)
        if user:
            parsed["user"] = user.group(1)

        src_ip = re.search(r"\b(?:src|source)(?:_ip| ip|=|:)?\s*(\d{1,3}(?:\.\d{1,3}){3})\b", text, re.IGNORECASE)
        if src_ip:
            parsed["source_ip"] = src_ip.group(1)

        dst_ip = re.search(r"\b(?:dst|dest|destination)(?:_ip| ip|=|:)?\s*(\d{1,3}(?:\.\d{1,3}){3})\b", text, re.IGNORECASE)
        if dst_ip:
            parsed["destination_ip"] = dst_ip.group(1)

        cmd = re.search(r"(?:cmd|command(?:_line)?)[:= ]+(.+)$", text, re.IGNORECASE)
        if cmd:
            parsed["command_line"] = cmd.group(1).strip()

        return parsed


def gather_initial_data() -> dict:
    runtime = detect_runtime_platform()

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
        "hostname": runtime["hostname"],
        "ip_address": runtime["ip_address"],
        "os_name": runtime["os_name"],
        "os_family": runtime["os_family"],
        "os_version": runtime["os_version"],
        "os_release": runtime["os_release"],
        "kernel_version": runtime["os_release"],
        "architecture": runtime["architecture"],
        "username": runtime["username"],
        "platform": runtime["platform"],
        "processor": runtime["processor"],
        "os_distribution": os_release.get("PRETTY_NAME", ""),
        "os_id": os_release.get("ID", ""),
        "os_version_id": os_release.get("VERSION_ID", ""),
    }