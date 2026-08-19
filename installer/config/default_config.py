from __future__ import annotations

from uuid import uuid4


def default_agent_config(hostname: str, version: str, log_dir: str) -> dict:
    return {
        "agent": {
            "id": str(uuid4()),
            "name": hostname,
            "version": version,
        },
        "server": {
            "url": "",
            "enrollment_token": "",
            "host": "127.0.0.1",
            "port": 9090,
            "connect_timeout": 8,
        },
        "logging": {
            "level": "INFO",
            "directory": log_dir,
        },
        "collection": {
            "process_events": True,
            "file_events": True,
            "network_events": True,
            "authentication_events": True,
            "system_events": True,
        },
        "security": {
            "verify_tls": True,
        },
        "collector": {
            "interval": 10,
            "sources": {
                "default": ["journald", "syslog", "auth", "kern", "audit"],
                "windows": ["windows_security", "sysmon", "powershell", "defender", "firewall"],
                "macos": [
                    "endpointsecurity_process",
                    "endpointsecurity_file",
                    "endpointsecurity_network",
                    "unifiedlog_auth",
                    "unifiedlog_system",
                    "unifiedlog_app",
                ],
                "linux": ["journald", "syslog", "auth", "kern", "audit"],
            },
        },
    }
