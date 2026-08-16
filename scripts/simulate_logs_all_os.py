"""Simulate representative logs from Linux, Windows, and macOS.

The script feeds sample raw log lines through the agent collector normalization
path and prints normalized events for each OS family.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from Agent.collector import Collector


def _runtime(os_family: str, architecture: str, host: str, username: str) -> dict:
    return {
        "os_family": os_family,
        "os_name": os_family,
        "os_release": "simulated",
        "os_version": "simulated",
        "architecture": architecture,
        "hostname": host,
        "ip_address": "10.10.10.10",
        "username": username,
        "platform": f"{os_family}-simulated",
        "processor": architecture,
    }


def _simulate_for_os(os_family: str, samples: list[tuple[str, str, str]]) -> list[dict]:
    queued: list[dict] = []

    collector = Collector(
        send_callback=queued.append,
        interval=10,
        selected_sources=[],
        os_sources={os_family: []},
        runtime_info=_runtime(
            os_family=os_family,
            architecture="arm64" if os_family == "macos" else "x86_64",
            host=f"{os_family}-host",
            username="admin",
        ),
    )

    for source, event_type, raw_line in samples:
        parsed = collector._parse_text_event(raw_line)
        parsed.setdefault("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        collector._send_event(source=source, raw_event=raw_line, event_type=event_type, parsed=parsed)

    normalized: list[dict] = []
    for item in queued:
        raw_event = item.get("raw_event", "{}")
        try:
            normalized.append(json.loads(raw_event))
        except Exception:
            normalized.append({"parse_error": raw_event})
    return normalized


def main() -> None:
    linux_samples = [
        (
            "journald:sshd",
            "auth_event",
            "sshd[3920]: user=admin src=10.0.0.22 dst=10.0.0.10 command=ssh login",
        ),
        (
            "log:syslog",
            "process_create",
            "sudo[4812]: user=admin pid=4812 ppid=3920 command=/usr/bin/apt update",
        ),
    ]

    windows_samples = [
        (
            "windows_security",
            "windows_security_event",
            "Record ID: 15012 user=admin pid=4812 ppid=3920 src=10.0.0.22 dst=8.8.8.8 command=powershell.exe -enc AAA",
        ),
        (
            "sysmon",
            "sysmon_event",
            "Record ID: 22411 process_name=powershell.exe pid=4812 ppid=3920 src=10.0.0.22 dst=1.1.1.1 command=powershell.exe -nop",
        ),
    ]

    macos_samples = [
        (
            "endpointsecurity_process",
            "process_create",
            "launchd[204]: user=admin pid=742 ppid=1 command=/bin/zsh -c whoami",
        ),
        (
            "unifiedlog_auth",
            "auth_event",
            "loginwindow[117]: user=admin src=172.16.0.20 command=interactive login",
        ),
    ]

    output = {
        "linux": _simulate_for_os("linux", linux_samples),
        "windows": _simulate_for_os("windows", windows_samples),
        "macos": _simulate_for_os("macos", macos_samples),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
