"""Indicator extraction from log events for threat hunting."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Set


FIELD_CANDIDATES = {
    "source_ip": ["source_ip", "src_ip", "ip_address", "sourceAddress"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "destinationAddress"],
    "pid": ["pid", "process_id"],
    "ppid": ["ppid", "parent_pid"],
    "process_name": ["process_name", "process", "image"],
    "username": ["user", "username", "account_name"],
    "host": ["hostname", "host", "computer_name"],
    "file_path": ["filepath", "file_path", "path"],
    "command_line": ["command", "command_line", "cmdline"],
    "timestamp": ["timestamp", "received_at", "time"],
    "hash": ["hash", "sha256", "sha1", "md5"],
    "session_id": ["session_id", "logon_id"],
    "connection_id": ["connection_id", "flow_id"],
}


class IndicatorExtractor:
    """Extract and normalize indicator values from events."""

    def extract_from_event(self, event: Dict[str, Any]) -> Dict[str, List[str]]:
        indicators: Dict[str, Set[str]] = {key: set() for key in FIELD_CANDIDATES}

        for key, candidates in FIELD_CANDIDATES.items():
            for candidate in candidates:
                value = event.get(candidate)
                normalized = self._normalize_value(value)
                if normalized:
                    indicators[key].add(normalized)

        # Also inspect free-form extras for typical hash keys.
        for extra_key in ("sha256", "sha1", "md5", "imphash"):
            extra_val = self._normalize_value(event.get(extra_key))
            if extra_val:
                indicators["hash"].add(extra_val)

        return {key: sorted(values) for key, values in indicators.items() if values}

    def merge(self, events: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
        merged: Dict[str, Set[str]] = {}
        for event in events:
            extracted = self.extract_from_event(event)
            for key, values in extracted.items():
                merged.setdefault(key, set()).update(values)
        return {key: sorted(values) for key, values in merged.items()}

    def public_ips(self, indicators: Dict[str, List[str]]) -> List[str]:
        ips: Set[str] = set()
        for key in ("source_ip", "destination_ip"):
            for value in indicators.get(key, []):
                if self._is_public_ip(value):
                    ips.add(value)
        return sorted(ips)

    def _normalize_value(self, value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip()
        if not text:
            return ""
        if text.lower() in {"none", "null", "nan"}:
            return ""
        return text

    def _is_public_ip(self, value: str) -> bool:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not (
            addr.is_loopback
            or addr.is_private
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_link_local
        )
