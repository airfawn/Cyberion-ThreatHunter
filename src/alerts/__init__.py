"""Alert management models and persistence layer.

Alert rules are queries that trigger actions when matched.
Statistics track rule firing and action execution.
History records every trigger event.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import json

from ..query.query_model import QueryDefinition


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(Enum):
    """Supported alert action types."""
    LOG_ALERT = "log_alert"              # Write to application log
    CREATE_EVENT = "create_event"        # Create an alert event in database
    DESKTOP_NOTIFICATION = "notification"  # Show desktop notification


class ActionStatus(Enum):
    """Status of action execution."""
    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"


class DetectionType(Enum):
    """Supported detection evaluation modes."""
    SINGLE_EVENT = "single_event"
    THRESHOLD = "threshold"


class TimeUnit(Enum):
    """Time units used by threshold and cooldown windows."""
    SECONDS = "seconds"
    MINUTES = "minutes"
    HOURS = "hours"


@dataclass
class ThresholdConfig:
    """Configuration for threshold-based detections."""
    count: int = 1
    window: int = 60
    unit: TimeUnit = TimeUnit.SECONDS
    group_by: List[str] = field(default_factory=list)
    cooldown: int = 0
    cooldown_unit: TimeUnit = TimeUnit.MINUTES

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "window": self.window,
            "unit": self.unit.value,
            "group_by": list(self.group_by or []),
            "cooldown": self.cooldown,
            "cooldown_unit": self.cooldown_unit.value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ThresholdConfig":
        return cls(
            count=int(data.get("count", 1)),
            window=int(data.get("window", 60)),
            unit=TimeUnit(data.get("unit", "seconds")),
            group_by=list(data.get("group_by", []) or []),
            cooldown=int(data.get("cooldown", 0)),
            cooldown_unit=TimeUnit(data.get("cooldown_unit", "minutes")),
        )


@dataclass
class ActionConfig:
    """Configuration for an alert action."""
    action_type: ActionType
    config: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "action_type": self.action_type.value,
            "config": self.config,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ActionConfig":
        """Deserialize from dict."""
        return cls(
            action_type=ActionType(data["action_type"]),
            config=data.get("config", {}),
        )


@dataclass
class AlertRule:
    """Persistent alert rule configuration."""
    id: Optional[str] = None
    name: str = ""
    description: str = ""
    enabled: bool = True
    severity: AlertSeverity = AlertSeverity.MEDIUM
    detection_type: DetectionType = DetectionType.SINGLE_EVENT
    threshold: Optional[ThresholdConfig] = None
    creator_name: str = ""
    query_definition: QueryDefinition = field(default_factory=QueryDefinition.empty)
    generated_kql: str = ""
    action: ActionConfig = field(default_factory=lambda: ActionConfig(ActionType.LOG_ALERT))
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> dict:
        """Serialize to dict (excluding query_definition)."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "severity": self.severity.value,
            "detection_type": self.detection_type.value,
            "threshold": self.threshold.to_dict() if self.threshold else None,
            "creator_name": self.creator_name,
            "generated_kql": self.generated_kql,
            "action": self.action.to_dict(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AlertRule":
        """Deserialize from dict."""
        # Query definition stored separately in database
        return cls(
            id=data.get("id"),
            name=data.get("name", ""),
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
            severity=AlertSeverity(data.get("severity", "medium")),
            detection_type=DetectionType(data.get("detection_type", "single_event")),
            threshold=ThresholdConfig.from_dict(data["threshold"]) if data.get("threshold") else None,
            creator_name=data.get("creator_name", ""),
            generated_kql=data.get("generated_kql", ""),
            action=ActionConfig.from_dict(data.get("action", {"action_type": "log_alert"})),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            updated_at=data.get("updated_at", datetime.utcnow().isoformat()),
        )


@dataclass
class AlertStatistics:
    """Statistics for an alert rule."""
    rule_id: str
    trigger_count: int = 0
    action_count: int = 0
    successful_action_count: int = 0
    failed_action_count: int = 0
    last_triggered_at: Optional[str] = None
    last_action_at: Optional[str] = None
    
    @property
    def success_rate(self) -> Optional[float]:
        """Calculate success rate as percentage."""
        if self.action_count == 0:
            return None
        return (self.successful_action_count / self.action_count) * 100.0
    
    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "rule_id": self.rule_id,
            "trigger_count": self.trigger_count,
            "action_count": self.action_count,
            "successful_action_count": self.successful_action_count,
            "failed_action_count": self.failed_action_count,
            "last_triggered_at": self.last_triggered_at,
            "last_action_at": self.last_action_at,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AlertStatistics":
        """Deserialize from dict."""
        return cls(
            rule_id=data["rule_id"],
            trigger_count=data.get("trigger_count", 0),
            action_count=data.get("action_count", 0),
            successful_action_count=data.get("successful_action_count", 0),
            failed_action_count=data.get("failed_action_count", 0),
            last_triggered_at=data.get("last_triggered_at"),
            last_action_at=data.get("last_action_at"),
        )


@dataclass
class AlertHistoryRecord:
    """Record of a single alert trigger and action execution."""
    id: Optional[str] = None
    rule_id: str = ""
    triggered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    event_id: Optional[str] = None  # ID of event that matched
    event_ids: List[int] = field(default_factory=list)  # IDs for threshold-triggering events
    group_key: Optional[str] = None
    action_type: ActionType = ActionType.LOG_ALERT
    action_status: ActionStatus = ActionStatus.PENDING
    action_executed_at: Optional[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "triggered_at": self.triggered_at,
            "event_id": self.event_id,
            "event_ids": list(self.event_ids),
            "group_key": self.group_key,
            "action_type": self.action_type.value,
            "action_status": self.action_status.value,
            "action_executed_at": self.action_executed_at,
            "error_message": self.error_message,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AlertHistoryRecord":
        """Deserialize from dict."""
        return cls(
            id=data.get("id"),
            rule_id=data.get("rule_id", ""),
            triggered_at=data.get("triggered_at", datetime.utcnow().isoformat()),
            event_id=data.get("event_id"),
            event_ids=list(data.get("event_ids", []) or []),
            group_key=data.get("group_key"),
            action_type=ActionType(data.get("action_type", "log_alert")),
            action_status=ActionStatus(data.get("action_status", "pending")),
            action_executed_at=data.get("action_executed_at"),
            error_message=data.get("error_message"),
        )


__all__ = [
    "AlertRule",
    "AlertSeverity",
    "ActionType",
    "ActionConfig",
    "ActionStatus",
    "DetectionType",
    "TimeUnit",
    "ThresholdConfig",
    "AlertStatistics",
    "AlertHistoryRecord",
]
