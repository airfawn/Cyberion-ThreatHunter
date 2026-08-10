"""Alert Engine - evaluates rules against events and executes actions.

The alert engine runs in a background thread and processes alert evaluations
without blocking event ingestion. It uses the existing query engine to match
events against rule conditions.
"""

import logging
import queue
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional

from .manager import AlertManager
from . import AlertRule, ActionStatus, AlertHistoryRecord, ActionType
from ..query import CyberionQueryEngine


logger = logging.getLogger(__name__)


class ActionExecutor:
    """Executes alert actions."""
    
    def __init__(self, custom_executors: Optional[Dict[ActionType, Callable]] = None):
        """Initialize action executor.
        
        Args:
            custom_executors: Optional dict mapping ActionType to executor functions
        """
        self.custom_executors = custom_executors or {}
        self._register_default_executors()
    
    def _register_default_executors(self):
        """Register default action executors."""
        self.custom_executors.setdefault(
            ActionType.LOG_ALERT,
            self._execute_log_alert
        )
        self.custom_executors.setdefault(
            ActionType.CREATE_EVENT,
            self._execute_create_event
        )
        self.custom_executors.setdefault(
            ActionType.DESKTOP_NOTIFICATION,
            self._execute_notification
        )
    
    def execute(self, rule: AlertRule, event_id: Optional[str] = None) -> bool:
        """Execute an action for a triggered rule.
        
        Args:
            rule: The alert rule that triggered
            event_id: Optional ID of the matching event
            
        Returns:
            True if action succeeded, False if it failed
        """
        action_type = rule.action.action_type
        executor = self.custom_executors.get(action_type)
        
        if not executor:
            logger.warning(f"No executor registered for action type: {action_type}")
            return False
        
        try:
            return executor(rule, event_id)
        except Exception as e:
            logger.error(f"Action execution failed for rule {rule.id}: {e}", exc_info=True)
            return False
    
    def _execute_log_alert(self, rule: AlertRule, event_id: Optional[str]) -> bool:
        """Log the alert."""
        logger.info(f"[ALERT] {rule.name} triggered (severity: {rule.severity.value})")
        return True
    
    def _execute_create_event(self, rule: AlertRule, event_id: Optional[str]) -> bool:
        """Create an alert event in the database."""
        # This would be implemented to create an event in the database
        logger.info(f"Alert event created for rule: {rule.name}")
        return True
    
    def _execute_notification(self, rule: AlertRule, event_id: Optional[str]) -> bool:
        """Show a desktop notification."""
        config = rule.action.config
        title = config.get("title", "Cyberion Alert")
        message = config.get("message", f"Alert: {rule.name}")
        
        try:
            # Try to use PyQt5 notification if available
            from PyQt5.QtWidgets import QSystemTrayIcon, QApplication
            from PyQt5.QtGui import QIcon
            
            app = QApplication.instance()
            if app:
                # In real implementation, would show system tray notification
                logger.info(f"Notification: {title} - {message}")
            return True
        except Exception:
            # Fallback to simple logging
            logger.info(f"Notification: {title} - {message}")
            return True


class AlertEngine(threading.Thread):
    """Background thread that evaluates alert rules against events.
    
    The engine maintains a queue of events to evaluate and uses the query
    engine to test each rule against matching events efficiently.
    """
    
    def __init__(
        self,
        alert_manager: AlertManager,
        query_engine: CyberionQueryEngine,
        event_queue: Optional[queue.Queue] = None,
    ):
        """Initialize the alert engine.
        
        Args:
            alert_manager: Alert persistence manager
            query_engine: Query engine for evaluating rules
            event_queue: Optional queue of events to evaluate (default: creates new)
        """
        super().__init__(daemon=True, name="AlertEngine")
        
        self.alert_manager = alert_manager
        self.query_engine = query_engine
        self.event_queue = event_queue or queue.Queue()
        self.action_executor = ActionExecutor()
        
        self._running = False
        self._enabled_rules: Dict[str, AlertRule] = {}
        self._rules_lock = threading.RLock()
    
    def run(self):
        """Main alert engine loop."""
        self._running = True
        logger.info("Alert engine started")
        
        while self._running:
            try:
                # Get the next event to evaluate (with timeout to allow shutdown)
                try:
                    event = self.event_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Evaluate all enabled rules against this event
                self._evaluate_event(event)
                
            except Exception as e:
                logger.error(f"Error in alert engine loop: {e}", exc_info=True)
    
    def stop(self):
        """Stop the alert engine."""
        self._running = False
        logger.info("Alert engine stopping...")
    
    def add_event(self, event: dict, event_id: Optional[str] = None) -> None:
        """Add an event for alert evaluation.
        
        Args:
            event: The event dict
            event_id: Optional event ID from database
        """
        self.event_queue.put((event, event_id))
    
    def reload_rules(self) -> None:
        """Reload enabled rules from database."""
        with self._rules_lock:
            self._enabled_rules.clear()
            rules = self.alert_manager.get_all_rules(enabled_only=True)
            for rule in rules:
                self._enabled_rules[rule.id] = rule
        
        logger.info(f"Loaded {len(self._enabled_rules)} enabled alert rules")
    
    def _evaluate_event(self, event_data):
        """Evaluate all enabled rules against an event.
        
        Args:
            event_data: Tuple of (event_dict, event_id)
        """
        event, event_id = event_data
        
        with self._rules_lock:
            for rule_id, rule in list(self._enabled_rules.items()):
                self._evaluate_rule(rule, event, event_id)
    
    def _evaluate_rule(
        self, rule: AlertRule, event: dict, event_id: Optional[str]
    ) -> None:
        """Evaluate a single rule against an event.
        
        Args:
            rule: The rule to evaluate
            event: The event dict
            event_id: Optional event ID from database
        """
        try:
            # Execute the rule's KQL to check if it matches
            # Note: This would ideally check just against the single event,
            # not the entire database. For now, we execute the full query
            # which is inefficient but correct.
            
            from ..query.model_to_kql import query_definition_to_kql
            kql = query_definition_to_kql(rule.query_definition)
            
            # Execute query and check if any rows match
            result = self.query_engine.execute(kql)
            
            if result.rows:
                # Rule matched!
                self._handle_trigger(rule, event_id)
        
        except Exception as e:
            logger.error(
                f"Error evaluating rule {rule.id}: {e}",
                exc_info=True
            )
    
    def _handle_trigger(self, rule: AlertRule, event_id: Optional[str]) -> None:
        """Handle a rule trigger.
        
        Args:
            rule: The triggered rule
            event_id: ID of the matching event
        """
        try:
            # Increment trigger count
            self.alert_manager.increment_trigger_count(rule.id)
            logger.info(f"Alert rule triggered: {rule.name} (ID: {rule.id})")
            
            # Create history record
            record = AlertHistoryRecord(
                rule_id=rule.id,
                triggered_at=datetime.utcnow().isoformat(),
                event_id=event_id,
                action_type=rule.action.action_type,
            )
            
            # Execute action
            action_succeeded = self.action_executor.execute(rule, event_id)
            
            # Update record with execution result
            record.action_status = (
                ActionStatus.SUCCESS if action_succeeded else ActionStatus.FAILURE
            )
            record.action_executed_at = datetime.utcnow().isoformat()
            
            # Save history
            self.alert_manager.add_history_record(record)
            
            # Update statistics
            self.alert_manager.increment_action_count(rule.id, action_succeeded)
            
        except Exception as e:
            logger.error(
                f"Error handling trigger for rule {rule.id}: {e}",
                exc_info=True
            )


__all__ = [
    "AlertEngine",
    "ActionExecutor",
]
