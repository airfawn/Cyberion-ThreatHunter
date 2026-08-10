"""Detection engine and detection persistence models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class DetectionStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass
class Detection:
    """A persisted detection created when a rule matches an event."""

    detection_id: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: str = ""
    rule_source: str = "cyberion"
    trigger_event_id: Optional[int] = None
    severity: str = "medium"
    status: str = DetectionStatus.NEW.value
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        return {
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_source": self.rule_source,
            "trigger_event_id": self.trigger_event_id,
            "severity": self.severity,
            "status": self.status,
            "detected_at": self.detected_at,
            "metadata": self.metadata or {},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Detection":
        return cls(
            detection_id=data.get("detection_id"),
            rule_id=data.get("rule_id"),
            rule_name=data.get("rule_name", ""),
            rule_source=data.get("rule_source", "cyberion"),
            trigger_event_id=data.get("trigger_event_id"),
            severity=data.get("severity", "medium"),
            status=data.get("status", DetectionStatus.NEW.value),
            detected_at=data.get("detected_at", datetime.utcnow().isoformat()),
            metadata=data.get("metadata") or {},
        )


__all__ = ["Detection", "DetectionStatus"]
