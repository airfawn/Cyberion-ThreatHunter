from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Dict
from urllib.parse import urlparse

import yaml

from installer.config.default_config import default_agent_config
from installer.models import InstallOptions, InstallPaths


class ConfigManager:
    def __init__(self, paths: InstallPaths):
        self.paths = paths
        self.config_file = self.paths.config_dir / "agent.yaml"
        self.identity_file = self.paths.state_dir / "agent_identity.json"
        self.manifest_file = self.paths.state_dir / "install_manifest.json"

    def load_or_initialize(self, hostname: str, version: str, opts: InstallOptions) -> dict:
        if self.config_file.exists():
            with self.config_file.open("r", encoding="utf-8") as handle:
                config = yaml.safe_load(handle) or {}
        else:
            config = default_agent_config(hostname=hostname, version=version, log_dir=str(self.paths.log_dir))

        config.setdefault("agent", {})
        config.setdefault("server", {})
        config.setdefault("logging", {})
        config.setdefault("security", {"verify_tls": True})

        config["agent"]["id"] = self._ensure_identity(preserve=True)
        config["agent"]["name"] = opts.name or config["agent"].get("name") or hostname
        config["agent"]["version"] = version

        if opts.server:
            config["server"]["url"] = opts.server
            host, port = self._parse_server(opts.server)
            config["server"]["host"] = host
            config["server"]["port"] = port
        if opts.token:
            config["server"]["enrollment_token"] = opts.token

        config["logging"]["level"] = opts.log_level.upper()
        config["logging"]["directory"] = str(self.paths.log_dir)

        return config

    def save_config(self, config: dict) -> None:
        self.paths.config_dir.mkdir(parents=True, exist_ok=True)
        with self.config_file.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(config, handle, sort_keys=False)

        if os.name != "nt":
            os.chmod(self.config_file, 0o600)

    def _ensure_identity(self, preserve: bool = True) -> str:
        if preserve and self.identity_file.exists():
            try:
                data = json.loads(self.identity_file.read_text(encoding="utf-8"))
                if data.get("agent_id"):
                    return str(data["agent_id"])
            except Exception:
                pass

        from uuid import uuid4

        agent_id = str(uuid4())
        self.paths.state_dir.mkdir(parents=True, exist_ok=True)
        self.identity_file.write_text(json.dumps({"agent_id": agent_id}, indent=2), encoding="utf-8")
        if os.name != "nt":
            os.chmod(self.identity_file, 0o600)
        return agent_id

    def regenerate_identity(self) -> str:
        return self._ensure_identity(preserve=False)

    def write_manifest(self, manifest: Dict) -> None:
        self.paths.state_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    def read_manifest(self) -> Dict:
        if not self.manifest_file.exists():
            return {}
        try:
            return json.loads(self.manifest_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def validate(self) -> tuple[bool, str]:
        if not self.config_file.exists():
            return False, "Configuration file missing"
        try:
            data = yaml.safe_load(self.config_file.read_text(encoding="utf-8")) or {}
            if not data.get("agent", {}).get("id"):
                return False, "Missing agent.id"
            if not data.get("server", {}).get("host"):
                return False, "Missing server.host"
            return True, "Configuration valid"
        except Exception as exc:
            return False, f"Configuration parse error: {exc}"

    def _parse_server(self, server: str) -> tuple[str, int]:
        parsed = urlparse(server)
        if parsed.scheme and parsed.hostname:
            return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        if ":" in server:
            host, port = server.rsplit(":", 1)
            try:
                return host.strip(), int(port)
            except ValueError:
                return host.strip(), 9090
        return server.strip(), 9090
