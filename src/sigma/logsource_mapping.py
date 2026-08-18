"""Sigma logsource mapping to Cyberion platform/event hints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from .models import SigmaLogsource


SUPPORTED_PRODUCTS = {"windows", "linux", "macos", "darwin"}

CATEGORY_MAP = {
    ("windows", "process_creation"): ("windows", "process_start"),
    ("windows", "file_event"): ("windows", "file_write"),
    ("windows", "network_connection"): ("windows", "network_connect"),
    ("windows", "authentication"): ("windows", "auth_event"),
    ("linux", "process_creation"): ("linux", "process_start"),
    ("linux", "file_event"): ("linux", "file_write"),
    ("linux", "network_connection"): ("linux", "network_connect"),
    ("linux", "authentication"): ("linux", "auth_event"),
    ("macos", "process_creation"): ("macos", "process_start"),
    ("macos", "file_event"): ("macos", "file_write"),
    ("macos", "network_connection"): ("macos", "network_connect"),
    ("macos", "authentication"): ("macos", "auth_event"),
}

SERVICE_MAP = {
    ("windows", "sysmon"): ("windows", "process_start"),
    ("windows", "security"): ("windows", "auth_event"),
}


class SigmaLogsourceMapper:
    def map_logsource(self, logsource: SigmaLogsource) -> tuple[bool, str, str, list[str]]:
        warnings: list[str] = []

        product = (logsource.product or "").strip().lower()
        category = (logsource.category or "").strip().lower()
        service = (logsource.service or "").strip().lower()

        if product == "darwin":
            product = "macos"

        if product and product not in SUPPORTED_PRODUCTS:
            return False, "", "", [f"Unsupported logsource product: {product}"]

        if product and category:
            mapped = CATEGORY_MAP.get((product, category))
            if mapped:
                platform, event_hint = mapped
                return True, platform, event_hint, warnings
            return False, "", "", [f"Unsupported logsource category for {product}: {category}"]

        if product and service:
            mapped = SERVICE_MAP.get((product, service))
            if mapped:
                platform, event_hint = mapped
                return True, platform, event_hint, warnings
            warnings.append(f"Unknown service mapping for {product}/{service}; proceeding without event_type hint")
            return True, product, "", warnings

        if product:
            warnings.append("Sigma logsource category/service missing; applying platform-only mapping")
            return True, product, "", warnings

        return False, "", "", ["Missing Sigma logsource product"]
