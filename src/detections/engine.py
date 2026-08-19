"""Detection engine for evaluating normalized events against active rules."""

import logging
import re
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..alerts import AlertRule, AlertHistoryRecord, ActionStatus, DetectionType, TimeUnit
from ..query.query_model import Condition, ConditionGroup, ComparisonOperator, LogicalOperator

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Evaluate normalized events against active detection rules."""

    def __init__(self, db):
        self.db = db
        self._lock = threading.RLock()
        self._threshold_windows = defaultdict(deque)
        self._threshold_last_trigger = {}
        self._threshold_seen_events = set()

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
                if rule.detection_type == DetectionType.THRESHOLD:
                    detection = self._evaluate_threshold_rule(rule, event)
                    if detection:
                        detections.append(detection)
                    continue

                detection = self._evaluate_single_event_rule(rule, event, event_id)
                if detection:
                    detections.append(detection)
            except Exception as exc:  # pragma: no cover - defensive guard
                logger.exception("Detection evaluation failed for rule %s: %s", getattr(rule, "id", None), exc)
        return detections

    def _evaluate_single_event_rule(self, rule: AlertRule, event: Dict[str, Any], event_id: Optional[int]):
        if not self._rule_matches(rule, event):
            return None

        existing = self.db.detections.get_detection_for_rule_event(rule.id, event_id)
        if existing:
            return None

        detection = self.db.detections.create_detection(
            rule_id=rule.id,
            rule_name=rule.name,
            rule_source="cyberion",
            trigger_event_id=event_id,
            severity=rule.severity.value,
            status="new",
            metadata={
                "rule_description": rule.description or "",
                "creator_name": rule.creator_name or "",
                "detection_type": DetectionType.SINGLE_EVENT.value,
            },
        )
        self._create_alert_for_detection(detection, rule, event_id=event_id, event_ids=[event_id] if event_id is not None else [], group_key=None)
        return detection

    def _evaluate_threshold_rule(self, rule: AlertRule, event: Dict[str, Any]):
        cfg = self._validate_threshold_config(rule)
        if not cfg:
            return None

        if not self._rule_matches(rule, event):
            return None

        event_id = event.get("id")
        if event_id is None and event.get("trigger_event_id") is not None:
            event_id = event.get("trigger_event_id")

        group_key, group_values = self._build_group_key(event, cfg["group_by"])
        rule_group_key = (rule.id, group_key)

        if event_id is not None:
            dedup_key = (rule.id, int(event_id))
            if dedup_key in self._threshold_seen_events:
                return None
            self._threshold_seen_events.add(dedup_key)

        event_ts = self._event_timestamp(event)
        window = self._threshold_windows[rule_group_key]
        window.append((event_ts, int(event_id) if event_id is not None else None))

        self._evict_old_window_entries(window, event_ts, cfg["window_seconds"])
        current_event_ids = [eid for _, eid in window if eid is not None]

        if len(window) < cfg["count"]:
            return None

        cooldown_until = self._threshold_last_trigger.get(rule_group_key)
        if cooldown_until and event_ts < cooldown_until:
            return None

        detection = self.db.detections.create_detection(
            rule_id=rule.id,
            rule_name=rule.name,
            rule_source="cyberion",
            trigger_event_id=int(event_id) if event_id is not None else None,
            severity=rule.severity.value,
            status="new",
            metadata={
                "rule_description": rule.description or "",
                "creator_name": rule.creator_name or "",
                "detection_type": DetectionType.THRESHOLD.value,
                "threshold": {
                    "count": cfg["count"],
                    "window": cfg["window"],
                    "unit": cfg["unit"],
                    "window_seconds": cfg["window_seconds"],
                    "group_by": cfg["group_by"],
                    "group_values": group_values,
                    "cooldown": cfg["cooldown"],
                    "cooldown_unit": cfg["cooldown_unit"],
                    "cooldown_seconds": cfg["cooldown_seconds"],
                },
                "trigger_event_ids": current_event_ids,
                "trigger_event_count": len(current_event_ids),
                "group_key": group_key,
            },
        )

        if cfg["cooldown_seconds"] > 0:
            self._threshold_last_trigger[rule_group_key] = event_ts + timedelta(seconds=cfg["cooldown_seconds"])

        self._create_alert_for_detection(
            detection,
            rule,
            event_id=int(event_id) if event_id is not None else None,
            event_ids=current_event_ids,
            group_key=group_key,
        )
        return detection

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

    def _validate_threshold_config(self, rule: AlertRule) -> Optional[Dict[str, Any]]:
        cfg = rule.threshold
        if cfg is None:
            return None

        count = int(cfg.count)
        window = int(cfg.window)
        if count < 1 or window <= 0:
            return None

        unit = cfg.unit.value
        cooldown_unit = cfg.cooldown_unit.value
        window_seconds = self._to_seconds(window, unit)
        cooldown = int(cfg.cooldown)
        cooldown_seconds = self._to_seconds(cooldown, cooldown_unit) if cooldown > 0 else 0

        group_by = [field for field in (cfg.group_by or []) if isinstance(field, str) and field.strip()]
        return {
            "count": count,
            "window": window,
            "unit": unit,
            "window_seconds": window_seconds,
            "group_by": group_by,
            "cooldown": cooldown,
            "cooldown_unit": cooldown_unit,
            "cooldown_seconds": cooldown_seconds,
        }

    def _to_seconds(self, value: int, unit: str) -> int:
        if unit == TimeUnit.SECONDS.value:
            return value
        if unit == TimeUnit.MINUTES.value:
            return value * 60
        if unit == TimeUnit.HOURS.value:
            return value * 3600
        raise ValueError(f"Unsupported time unit: {unit}")

    def _event_timestamp(self, event: Dict[str, Any]) -> datetime:
        for key in ("timestamp", "received_at"):
            raw = event.get(key)
            if not raw:
                continue
            try:
                text = str(raw)
                if text.endswith("Z"):
                    text = text[:-1] + "+00:00"
                parsed = datetime.fromisoformat(text)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except Exception:
                continue
        return datetime.now(timezone.utc)

    def _evict_old_window_entries(self, window: deque, current_ts: datetime, window_seconds: int) -> None:
        cutoff = current_ts - timedelta(seconds=window_seconds)
        while window and window[0][0] < cutoff:
            window.popleft()

    def _build_group_key(self, event: Dict[str, Any], group_by: List[str]) -> Tuple[str, Dict[str, Any]]:
        if not group_by:
            return "__global__", {}

        values = {}
        tokens = []
        for field in group_by:
            val = self._get_event_value(event, field)
            values[field] = val
            tokens.append(f"{field}={'' if val is None else str(val)}")
        return "|".join(tokens), values

    def _create_alert_for_detection(self, detection, rule: AlertRule, event_id: Optional[int], event_ids: List[int], group_key: Optional[str]) -> None:
        """Create a persisted alert entry for the detection via the existing alert system."""
        try:
            history = AlertHistoryRecord(
                rule_id=rule.id,
                triggered_at=detection.detected_at,
                event_id=event_id,
                event_ids=event_ids,
                group_key=group_key,
                action_type=rule.action.action_type,
                action_status=ActionStatus.SUCCESS,
            )
            self.db.alerts.add_history_record(history)
            self.db.alerts.increment_trigger_count(rule.id)
            self.db.alerts.increment_action_count(rule.id, success=True)
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.exception("Failed to create alert history for detection %s: %s", detection.detection_id, exc)


__all__ = ["DetectionEngine"]
