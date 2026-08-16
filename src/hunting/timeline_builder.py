"""Timeline assembly for threat hunting investigations."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .models import EvidenceType, TimelineEvent


class TimelineBuilder:
    """Convert observed/correlated events into analyst-readable timeline rows."""

    def build(
        self,
        initial_event: Dict[str, Any],
        related_events: Iterable[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        items: List[TimelineEvent] = []

        if initial_event:
            items.append(self._to_timeline_event(initial_event, EvidenceType.OBSERVED, "seed event", False))

        for event in related_events:
            reasons = event.get("_correlation_reasons") or []
            reason = ", ".join(reasons) if reasons else "time-window association"
            uncertain = bool(event.get("_correlation_uncertain", True))
            items.append(self._to_timeline_event(event, EvidenceType.CORRELATED, reason, uncertain))

        items.sort(key=lambda item: item.timestamp or "")
        return [item.to_dict() for item in items]

    def _to_timeline_event(
        self,
        event: Dict[str, Any],
        evidence_type: EvidenceType,
        correlation_reason: str,
        uncertain: bool,
    ) -> TimelineEvent:
        return TimelineEvent(
            timestamp=str(event.get("timestamp") or event.get("received_at") or ""),
            event_type=str(event.get("event_type") or ""),
            process=str(event.get("process_name") or event.get("process") or ""),
            user=str(event.get("user") or ""),
            host=str(event.get("hostname") or event.get("host") or ""),
            source_ip=str(event.get("source_ip") or event.get("ip_address") or ""),
            destination_ip=str(event.get("destination_ip") or ""),
            command_line=str(event.get("command") or ""),
            file_path=str(event.get("filepath") or event.get("file_path") or ""),
            severity=str(event.get("_severity") or event.get("severity") or ""),
            correlation_reason=correlation_reason,
            evidence_type=evidence_type.value,
            uncertain=uncertain,
            raw_event=event,
        )
