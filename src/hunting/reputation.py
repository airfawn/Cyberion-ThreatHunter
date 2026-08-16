"""IP reputation/enrichment adapter.

This module only performs lookups when a reputation API endpoint is configured.
No credentials are hard-coded.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class ReputationLookupService:
    """Thin HTTP adapter for optional reputation lookups."""

    def __init__(self):
        self.api_url = os.getenv("THREATHUNTER_IPREP_API_URL", "").strip()
        self.api_key = os.getenv("THREATHUNTER_IPREP_API_KEY", "").strip()
        self.api_source = os.getenv("THREATHUNTER_IPREP_SOURCE", "Configured Reputation API").strip()
        timeout_raw = os.getenv("THREATHUNTER_IPREP_TIMEOUT", "4")
        try:
            self.timeout_seconds = max(1.0, min(float(timeout_raw), 15.0))
        except ValueError:
            self.timeout_seconds = 4.0

    def is_configured(self) -> bool:
        return bool(self.api_url)

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        checked_at = datetime.now(timezone.utc).isoformat()
        if not self.is_configured():
            return {
                "ip": ip,
                "available": False,
                "reason": "Reputation service not configured",
                "source": "none",
                "last_checked": checked_at,
            }

        url = self._format_url(ip)
        headers = {
            "Accept": "application/json",
            "User-Agent": "Cyberion-ThreatHunter/1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = Request(url=url, headers=headers, method="GET")

        try:
            with urlopen(req, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8", errors="replace")
                payload = json.loads(body) if body else {}
        except HTTPError as exc:
            return {
                "ip": ip,
                "available": False,
                "reason": f"HTTP {exc.code}",
                "source": self.api_source,
                "last_checked": checked_at,
            }
        except URLError as exc:
            return {
                "ip": ip,
                "available": False,
                "reason": f"Network failure: {exc.reason}",
                "source": self.api_source,
                "last_checked": checked_at,
            }
        except json.JSONDecodeError:
            return {
                "ip": ip,
                "available": False,
                "reason": "Malformed JSON from reputation API",
                "source": self.api_source,
                "last_checked": checked_at,
            }
        except Exception as exc:
            return {
                "ip": ip,
                "available": False,
                "reason": f"Lookup failed: {exc}",
                "source": self.api_source,
                "last_checked": checked_at,
            }

        return {
            "ip": ip,
            "available": True,
            "status": payload.get("status") or payload.get("reputation") or "unknown",
            "confidence": payload.get("confidence"),
            "country": payload.get("country"),
            "asn": payload.get("asn"),
            "organization": payload.get("organization") or payload.get("provider"),
            "malicious_reports": payload.get("malicious_reports") or payload.get("reports"),
            "source": self.api_source,
            "raw": payload,
            "last_checked": checked_at,
        }

    def _format_url(self, ip: str) -> str:
        template = self.api_url
        if "{ip}" in template:
            return template.format(ip=quote(ip))
        separator = "&" if "?" in template else "?"
        return f"{template}{separator}ip={quote(ip)}"
