"""Correlation logic for related events around a suspicious seed event."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from .indicator_extractor import IndicatorExtractor


class CorrelationEngine:
    """Find related events around a seed event with confidence labels."""

    def __init__(self, db, extractor: IndicatorExtractor | None = None):
        self.db = db
        self.extractor = extractor or IndicatorExtractor()

    def correlate(
        self,
        seed_event: Dict[str, Any],
        window_minutes: int = 30,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        if not seed_event:
            return []

        seed_ts = self._parse_time(seed_event)
        if seed_ts is None:
            # If timestamp is malformed, fallback to latest events and rely on indicator matching.
            candidates = self.db.get_events(limit=max(100, limit), offset=0)
        else:
            start = (seed_ts - timedelta(minutes=window_minutes)).isoformat()
            end = (seed_ts + timedelta(minutes=window_minutes)).isoformat()
            candidates = self.db.execute_query(
                "WHERE COALESCE(timestamp, received_at) >= ? AND COALESCE(timestamp, received_at) <= ?",
                params=[start, end],
                limit=limit,
                offset=0,
            )

        seed_id = seed_event.get("id")
        seed_indicators = self.extractor.extract_from_event(seed_event)
        related: List[Dict[str, Any]] = []

        for candidate in candidates:
            if seed_id is not None and candidate.get("id") == seed_id:
                continue

            score, reasons = self._score_match(seed_event, candidate, seed_indicators)
            if score <= 0:
                continue

            enriched = dict(candidate)
            enriched["_correlation_score"] = score
            enriched["_correlation_reasons"] = reasons
            enriched["_correlation_uncertain"] = score < 3
            related.append(enriched)

        related.sort(
            key=lambda item: (
                float(item.get("_correlation_score", 0)),
                str(item.get("timestamp") or item.get("received_at") or ""),
            ),
            reverse=True,
        )
        return related[:limit]

    def _score_match(
        self,
        seed_event: Dict[str, Any],
        candidate: Dict[str, Any],
        seed_indicators: Dict[str, List[str]],
    ) -> Tuple[int, List[str]]:
        reasons: List[str] = []
        score = 0

        if self._matches(candidate, seed_indicators, "pid"):
            score += 4
            reasons.append("shared process id")

        if self._matches(candidate, seed_indicators, "ppid"):
            score += 4
            reasons.append("shared parent process id")

        if self._bidirectional_pid_ppid(seed_event, candidate):
            score += 5
            reasons.append("parent-child process linkage")

        if self._matches(candidate, seed_indicators, "process_name"):
            score += 2
            reasons.append("shared process name")

        if self._matches(candidate, seed_indicators, "username"):
            score += 2
            reasons.append("shared user")

        if self._matches(candidate, seed_indicators, "host"):
            score += 2
            reasons.append("shared host")

        if self._matches(candidate, seed_indicators, "file_path"):
            score += 2
            reasons.append("shared file path")

        if self._matches(candidate, seed_indicators, "hash"):
            score += 4
            reasons.append("shared hash")

        ip_hits = 0
        if self._matches(candidate, seed_indicators, "source_ip"):
            ip_hits += 1
        if self._matches(candidate, seed_indicators, "destination_ip"):
            ip_hits += 1
        if ip_hits:
            score += ip_hits * 2
            reasons.append("shared network endpoint")

        if self._matches(candidate, seed_indicators, "session_id"):
            score += 3
            reasons.append("shared session id")

        if self._matches(candidate, seed_indicators, "connection_id"):
            score += 3
            reasons.append("shared connection id")

        return score, reasons

    def _matches(
        self,
        candidate: Dict[str, Any],
        seed_indicators: Dict[str, List[str]],
        indicator_key: str,
    ) -> bool:
        candidate_indicators = self.extractor.extract_from_event(candidate)
        candidate_values = set(candidate_indicators.get(indicator_key, []))
        seed_values = set(seed_indicators.get(indicator_key, []))
        return bool(seed_values and candidate_values.intersection(seed_values))

    def _bidirectional_pid_ppid(self, seed_event: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
        seed_pid = str(seed_event.get("pid") or "")
        seed_ppid = str(seed_event.get("ppid") or "")
        cand_pid = str(candidate.get("pid") or "")
        cand_ppid = str(candidate.get("ppid") or "")

        if seed_pid and cand_ppid and seed_pid == cand_ppid:
            return True
        if seed_ppid and cand_pid and seed_ppid == cand_pid:
            return True
        return False

    def _parse_time(self, event: Dict[str, Any]) -> datetime | None:
        raw = str(event.get("timestamp") or event.get("received_at") or "").strip()
        if not raw:
            return None
        try:
            # Support both Z suffix and explicit offsets.
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            parsed = datetime.fromisoformat(raw)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed
        except Exception:
            return None
