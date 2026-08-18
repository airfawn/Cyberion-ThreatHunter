"""Centralized Sigma -> Cyberion field mapping."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


DEFAULT_FIELD_MAP: Dict[str, str] = {
    "Image": "process_name",
    "CommandLine": "command",
    "ParentImage": "parent_process",
    "ParentCommandLine": "command",
    "User": "user",
    "ProcessId": "pid",
    "ParentProcessId": "ppid",
    "TargetFilename": "filepath",
    "FileName": "filepath",
    "FilePath": "filepath",
    "ComputerName": "hostname",
    "HostName": "hostname",
    "EventID": "event_id",
    "SourceIp": "ip_address",
    "DestinationIp": "ip_address",
    "IpAddress": "ip_address",
    "Protocol": "message",
    "EventType": "event_type",
    "Message": "message",
    "Product": "os",
}


class SigmaFieldMapper:
    def __init__(self, mapping_file: str | None = None):
        self.mapping = dict(DEFAULT_FIELD_MAP)
        if mapping_file:
            self._load_external_map(mapping_file)
        else:
            default_path = (
                Path(__file__).resolve().parent.parent.parent / "config" / "sigma_field_map.yaml"
            )
            if default_path.exists():
                self._load_external_map(str(default_path))

    def map_field(self, sigma_field: str) -> str | None:
        # Direct map first.
        if sigma_field in self.mapping:
            return self.mapping[sigma_field]

        # Case-insensitive fallback.
        sigma_field_l = sigma_field.lower()
        for key, value in self.mapping.items():
            if key.lower() == sigma_field_l:
                return value

        return None

    def _load_external_map(self, mapping_file: str) -> None:
        if yaml is None:
            return
        try:
            with Path(mapping_file).open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except Exception:
            return
        if not isinstance(data, dict):
            return

        file_map = data.get("field_map", data)
        if not isinstance(file_map, dict):
            return

        for key, value in file_map.items():
            if not key or not value:
                continue
            self.mapping[str(key)] = str(value)
