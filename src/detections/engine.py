"""Detection engine for evaluating normalized events against active rules."""

import logging
import re
import threading
from typing import Any, Dict, List, Optional, Tuple

from ..alerts import AlertRule, ActionConfig, ActionType, AlertHistoryRecord, ActionStatus
from ..query.query_model import Condition, ConditionGroup, ComparisonOperator, LogicalOperator

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Evaluate normalized events against active detection rules."""

    def __init__(self, db):
        self.db = db
        self._lock = threading.RLock()

    def evaluate_event(self, event: Optional[Dict[str, Any]]) -> List["Detection"]:
        """Evaluate a single normalized event against all active rules."""
        if not event:
            return []

        event_id = event.get("id")
        if event_id is None and event.get("trigger_event_id") is not None:
            event_id = event.get("trigger_event_id")

        detections: List["Detection"] = []
        active_rules = self.db.alerts.get_all_rules(enabled_only=True)
        for rule in active_rules:
            try:
                if not self._rule_matches(rule, event):
                    continue

                existing = self.db.detections.get_detection_for_rule_event(rule.id, event_id)
                if existing:
                    continue

                detection = self.db.detections.create_detection(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    rule_source="cyberion",
                    trigger_event_id=event_id,
                    severity=rule.severity.value,
                    status="new",
                    metadata={"rule_description": rule.description or ""},
                )
                detections.append(detection)
                self._create_alert_for_detection(detection, rule, event_id)
            except Exception as exc:  # pragma: no cover - defensive guard
                logger.exception("Detection evaluation failed for rule %s: %s", getattr(rule, "id", None), exc)
        return detections

    def _rule_matches(self, rule: AlertRule, event: Dict[str, Any]) -> bool:
        """Evaluate a rule against a normalized event."""
        if not rule or not rule.query_definition:
            return False
        try:
            return self._evaluate_group(rule.query_definition.root_group, event)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.exception("Rule evaluation failed for rule %s: %s", getattr(rule, "id", None), exc)
            return False

    def _evaluate_group(self, group, event: Dict[str, Any]) -> bool:
        """Evaluate a condition group with AND/OR logic."""
        if not group or group.is_empty():
            return True

        results = []
        for condition in group.conditions:
            results.append(self._evaluate_condition(condition, event))
        for child_group in group.groups:
            results.append(self._evaluate_group(child_group, event))

        if not results:
            return True

        if group.logical_operator == LogicalOperator.OR:
            return any(results)
        return all(results)

    def _evaluate_condition(self, condition, event: Dict[str, Any]) -> bool:
        """Evaluate a single condition against a normalized event."""
        value = self._get_event_value(event, condition.field)
        operator = condition.operator

        if operator == ComparisonOperator.IS_EMPTY:
            return value is None or str(value) == ""
        if operator == ComparisonOperator.IS_NOT_EMPTY:
            return value is not None and str(value) != ""

        if value is None:
            return False

        if operator == ComparisonOperator.EQUALS:
            return str(value).lower() == str(condition.value).lower()
        if operator == ComparisonOperator.NOT_EQUALS:
            return str(value).lower() != str(condition.value).lower()
        if operator == ComparisonOperator.CONTAINS:
            return str(condition.value).lower() in str(value).lower()
        if operator == ComparisonOperator.NOT_CONTAINS:
            return str(condition.value).lower() not in str(value).lower()
        if operator == ComparisonOperator.STARTS_WITH:
            return str(value).lower().startswith(str(condition.value).lower())
        if operator == ComparisonOperator.ENDS_WITH:
            return str(value).lower().endswith(str(condition.value).lower())
        if operator == ComparisonOperator.REGEX:
            return self._safe_regex_match(str(condition.value), str(value))
        if operator == ComparisonOperator.NOT_REGEX:
            return not self._safe_regex_match(str(condition.value), str(value))
        if operator == ComparisonOperator.GREATER_THAN:
            try:
                return float(value) > float(condition.value)
            except (TypeError, ValueError):
                return False
        if operator == ComparisonOperator.LESS_THAN:
            try:
                return float(value) < float(condition.value)
            except (TypeError, ValueError):
                return False
        if operator == ComparisonOperator.GREATER_THAN_EQUAL:
            try:
                return float(value) >= float(condition.value)
            except (TypeError, ValueError):
                return False
        if operator == ComparisonOperator.LESS_THAN_EQUAL:
            try:
                return float(value) <= float(condition.value)
            except (TypeError, ValueError):
                return False
        return False

    def _get_event_value(self, event: Dict[str, Any], field: str) -> Any:
        """Resolve an event field from normalized event data and its structured payload."""
        if not event:
            return None

        if field in event:
            return event[field]

        structured = event.get("structured")
        if isinstance(structured, dict):
            if field in structured:
                return structured[field]
            if field == "process_name" and "process" in structured:
                return structured["process"]
            if field == "command" and "command_line" in structured:
                return structured["command_line"]

        aliases = {
            "process_name": ["process", "proc"],
            "command": ["command_line", "cmd"],
            "filepath": ["file"],
        }
        for alias in aliases.get(field, []):
            if alias in event:
                return event[alias]
            if isinstance(structured, dict) and alias in structured:
                return structured[alias]
        return None

    def _safe_regex_match(self, pattern: str, candidate: str) -> bool:
        # Guardrails for untrusted imported patterns.
        if not pattern or len(pattern) > 256:
            return False
        text = candidate if len(candidate) <= 4000 else candidate[:4000]
        try:
            return re.search(pattern, text, flags=re.IGNORECASE) is not None
        except re.error:
            return False

    def _create_alert_for_detection(self, detection, rule: AlertRule, event_id: Optional[int]) -> None:
        """Create a persisted alert entry for the detection via the existing alert system."""
        try:
            history = AlertHistoryRecord(
                rule_id=rule.id,
                triggered_at=detection.detected_at,
                event_id=event_id,
                action_type=rule.action.action_type,
                action_status=ActionStatus.SUCCESS,
            )
            self.db.alerts.add_history_record(history)
            self.db.alerts.increment_trigger_count(rule.id)
            self.db.alerts.increment_action_count(rule.id, success=True)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.exception("Failed to create alert history for detection %s: %s", detection.detection_id, exc)


__all__ = ["DetectionEngine"]
