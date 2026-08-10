"""Alert persistence layer - manages alert rules, statistics, and history in database."""

import json
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import AlertRule, AlertStatistics, AlertHistoryRecord, ActionType


class AlertPersistenceError(Exception):
    """Raised when alert persistence operations fail."""
    pass


class AlertManager:
    """Manages persistent storage of alert rules, statistics, and history."""
    
    def __init__(self, conn: sqlite3.Connection):
        """Initialize with a database connection.
        
        Args:
            conn: SQLite3 connection to use for persistence
        """
        self.conn = conn
        self._lock = threading.RLock()
        self._create_schema()
    
    def _create_schema(self):
        """Create alert-related tables if they don't exist."""
        with self._lock:
            cur = self.conn.cursor()
            
            # Alert rules table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_rules (
                    id              TEXT PRIMARY KEY,
                    name            TEXT NOT NULL,
                    description     TEXT,
                    enabled         INTEGER DEFAULT 1,
                    severity        TEXT,
                    query_definition TEXT NOT NULL,
                    generated_kql   TEXT NOT NULL,
                    action_type     TEXT,
                    action_config   TEXT,
                    created_at      TEXT,
                    updated_at      TEXT
                )
                """
            )
            
            # Alert statistics table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_statistics (
                    rule_id                  TEXT PRIMARY KEY,
                    trigger_count            INTEGER DEFAULT 0,
                    action_count             INTEGER DEFAULT 0,
                    successful_action_count  INTEGER DEFAULT 0,
                    failed_action_count      INTEGER DEFAULT 0,
                    last_triggered_at        TEXT,
                    last_action_at           TEXT,
                    FOREIGN KEY(rule_id) REFERENCES alert_rules(id)
                )
                """
            )
            
            # Alert history table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_history (
                    id                 TEXT PRIMARY KEY,
                    rule_id            TEXT NOT NULL,
                    triggered_at       TEXT,
                    event_id           TEXT,
                    action_type        TEXT,
                    action_status      TEXT,
                    action_executed_at TEXT,
                    error_message      TEXT,
                    FOREIGN KEY(rule_id) REFERENCES alert_rules(id)
                )
                """
            )
            
            # Index alert history by rule for fast lookups
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_history_rule "
                "ON alert_history(rule_id)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_history_triggered "
                "ON alert_history(triggered_at)"
            )
            
            self.conn.commit()
    
    # ============================================================================
    # Alert Rules
    # ============================================================================
    
    def create_rule(self, rule: AlertRule) -> AlertRule:
        """Create and persist a new alert rule.
        
        Args:
            rule: The alert rule to create
            
        Returns:
            The created rule with ID set
            
        Raises:
            AlertPersistenceError: If persistence fails
        """
        try:
            with self._lock:
                rule.id = str(uuid.uuid4())
                cur = self.conn.cursor()
                
                cur.execute(
                    """
                    INSERT INTO alert_rules 
                    (id, name, description, enabled, severity, query_definition, 
                     generated_kql, action_type, action_config, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rule.id,
                        rule.name,
                        rule.description,
                        1 if rule.enabled else 0,
                        rule.severity.value,
                        json.dumps(rule.query_definition.to_dict()),
                        rule.generated_kql,
                        rule.action.action_type.value,
                        json.dumps(rule.action.config),
                        rule.created_at,
                        rule.updated_at,
                    )
                )
                
                # Create statistics record
                cur.execute(
                    """
                    INSERT INTO alert_statistics (rule_id)
                    VALUES (?)
                    """,
                    (rule.id,)
                )
                
                self.conn.commit()
                return rule
        except Exception as e:
            raise AlertPersistenceError(f"Failed to create alert rule: {e}") from e
    
    def get_rule(self, rule_id: str) -> Optional[AlertRule]:
        """Get an alert rule by ID.
        
        Args:
            rule_id: The rule ID
            
        Returns:
            The alert rule or None if not found
        """
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                SELECT id, name, description, enabled, severity, query_definition,
                       generated_kql, action_type, action_config, created_at, updated_at
                FROM alert_rules
                WHERE id = ?
                """,
                (rule_id,)
            )
            
            row = cur.fetchone()
            if not row:
                return None
            
            return self._row_to_rule(row)
    
    def get_all_rules(self, enabled_only: bool = False) -> List[AlertRule]:
        """Get all alert rules.
        
        Args:
            enabled_only: If True, return only enabled rules
            
        Returns:
            List of alert rules
        """
        with self._lock:
            cur = self.conn.cursor()
            
            if enabled_only:
                cur.execute(
                    """
                    SELECT id, name, description, enabled, severity, query_definition,
                           generated_kql, action_type, action_config, created_at, updated_at
                    FROM alert_rules
                    WHERE enabled = 1
                    ORDER BY created_at DESC
                    """
                )
            else:
                cur.execute(
                    """
                    SELECT id, name, description, enabled, severity, query_definition,
                           generated_kql, action_type, action_config, created_at, updated_at
                    FROM alert_rules
                    ORDER BY created_at DESC
                    """
                )
            
            return [self._row_to_rule(row) for row in cur.fetchall()]
    
    def update_rule(self, rule: AlertRule) -> None:
        """Update an existing alert rule.
        
        Args:
            rule: The updated rule
            
        Raises:
            AlertPersistenceError: If update fails
        """
        try:
            with self._lock:
                rule.updated_at = datetime.utcnow().isoformat()
                cur = self.conn.cursor()
                
                cur.execute(
                    """
                    UPDATE alert_rules
                    SET name = ?, description = ?, enabled = ?, severity = ?,
                        query_definition = ?, generated_kql = ?, action_type = ?,
                        action_config = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        rule.name,
                        rule.description,
                        1 if rule.enabled else 0,
                        rule.severity.value,
                        json.dumps(rule.query_definition.to_dict()),
                        rule.generated_kql,
                        rule.action.action_type.value,
                        json.dumps(rule.action.config),
                        rule.updated_at,
                        rule.id,
                    )
                )
                
                self.conn.commit()
        except Exception as e:
            raise AlertPersistenceError(f"Failed to update alert rule: {e}") from e
    
    def delete_rule(self, rule_id: str) -> None:
        """Delete an alert rule and its associated data.
        
        Args:
            rule_id: The rule ID
            
        Raises:
            AlertPersistenceError: If deletion fails
        """
        try:
            with self._lock:
                cur = self.conn.cursor()
                
                # Delete statistics
                cur.execute(
                    "DELETE FROM alert_statistics WHERE rule_id = ?",
                    (rule_id,)
                )
                
                # Delete history (cascading delete)
                cur.execute(
                    "DELETE FROM alert_history WHERE rule_id = ?",
                    (rule_id,)
                )
                
                # Delete rule
                cur.execute(
                    "DELETE FROM alert_rules WHERE id = ?",
                    (rule_id,)
                )
                
                self.conn.commit()
        except Exception as e:
            raise AlertPersistenceError(f"Failed to delete alert rule: {e}") from e
    
    def enable_rule(self, rule_id: str) -> None:
        """Enable a disabled rule."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "UPDATE alert_rules SET enabled = 1 WHERE id = ?",
                (rule_id,)
            )
            self.conn.commit()
    
    def disable_rule(self, rule_id: str) -> None:
        """Disable an enabled rule."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "UPDATE alert_rules SET enabled = 0 WHERE id = ?",
                (rule_id,)
            )
            self.conn.commit()
    
    # ============================================================================
    # Statistics
    # ============================================================================
    
    def get_statistics(self, rule_id: str) -> Optional[AlertStatistics]:
        """Get statistics for a rule.
        
        Args:
            rule_id: The rule ID
            
        Returns:
            Alert statistics or None if not found
        """
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                SELECT rule_id, trigger_count, action_count,
                       successful_action_count, failed_action_count,
                       last_triggered_at, last_action_at
                FROM alert_statistics
                WHERE rule_id = ?
                """,
                (rule_id,)
            )
            
            row = cur.fetchone()
            if not row:
                return None
            
            return AlertStatistics(
                rule_id=row[0],
                trigger_count=row[1],
                action_count=row[2],
                successful_action_count=row[3],
                failed_action_count=row[4],
                last_triggered_at=row[5],
                last_action_at=row[6],
            )
    
    def increment_trigger_count(self, rule_id: str) -> None:
        """Increment trigger count for a rule."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                UPDATE alert_statistics
                SET trigger_count = trigger_count + 1,
                    last_triggered_at = ?
                WHERE rule_id = ?
                """,
                (datetime.utcnow().isoformat(), rule_id)
            )
            self.conn.commit()
    
    def increment_action_count(self, rule_id: str, success: bool) -> None:
        """Increment action and success/failure counts."""
        with self._lock:
            cur = self.conn.cursor()
            if success:
                cur.execute(
                    """
                    UPDATE alert_statistics
                    SET action_count = action_count + 1,
                        successful_action_count = successful_action_count + 1,
                        last_action_at = ?
                    WHERE rule_id = ?
                    """,
                    (datetime.utcnow().isoformat(), rule_id)
                )
            else:
                cur.execute(
                    """
                    UPDATE alert_statistics
                    SET action_count = action_count + 1,
                        failed_action_count = failed_action_count + 1,
                        last_action_at = ?
                    WHERE rule_id = ?
                    """,
                    (datetime.utcnow().isoformat(), rule_id)
                )
            self.conn.commit()
    
    # ============================================================================
    # History
    # ============================================================================
    
    def add_history_record(self, record: AlertHistoryRecord) -> AlertHistoryRecord:
        """Add an alert history record.
        
        Args:
            record: The history record to add
            
        Returns:
            The record with ID set
            
        Raises:
            AlertPersistenceError: If insertion fails
        """
        try:
            with self._lock:
                record.id = str(uuid.uuid4())
                cur = self.conn.cursor()
                
                cur.execute(
                    """
                    INSERT INTO alert_history
                    (id, rule_id, triggered_at, event_id, action_type,
                     action_status, action_executed_at, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.id,
                        record.rule_id,
                        record.triggered_at,
                        record.event_id,
                        record.action_type.value,
                        record.action_status.value,
                        record.action_executed_at,
                        record.error_message,
                    )
                )
                
                self.conn.commit()
                return record
        except Exception as e:
            raise AlertPersistenceError(f"Failed to add history record: {e}") from e
    
    def get_rule_history(
        self, rule_id: str, limit: int = 100, offset: int = 0
    ) -> List[AlertHistoryRecord]:
        """Get alert history for a rule.
        
        Args:
            rule_id: The rule ID
            limit: Maximum records to return
            offset: Starting record offset
            
        Returns:
            List of history records
        """
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                SELECT id, rule_id, triggered_at, event_id, action_type,
                       action_status, action_executed_at, error_message
                FROM alert_history
                WHERE rule_id = ?
                ORDER BY triggered_at DESC
                LIMIT ? OFFSET ?
                """,
                (rule_id, limit, offset)
            )
            
            return [self._history_row_to_record(row) for row in cur.fetchall()]
    
    # ============================================================================
    # Helpers
    # ============================================================================
    
    def _row_to_rule(self, row) -> AlertRule:
        """Convert a database row to AlertRule."""
        from . import AlertRule, ActionConfig, ActionType, AlertSeverity
        from ..query.query_model import QueryDefinition
        
        query_def_dict = json.loads(row[5]) if row[5] else {}
        query_def = QueryDefinition.from_dict(query_def_dict)
        
        action_config = json.loads(row[8]) if row[8] else {}
        action = ActionConfig(
            action_type=ActionType(row[7]) if row[7] else ActionType.LOG_ALERT,
            config=action_config
        )
        
        return AlertRule(
            id=row[0],
            name=row[1],
            description=row[2],
            enabled=bool(row[3]),
            severity=AlertSeverity(row[4]) if row[4] else AlertSeverity.MEDIUM,
            query_definition=query_def,
            generated_kql=row[6],
            action=action,
            created_at=row[9],
            updated_at=row[10],
        )
    
    def _history_row_to_record(self, row) -> AlertHistoryRecord:
        """Convert a database row to AlertHistoryRecord."""
        from . import AlertHistoryRecord, ActionType, ActionStatus
        
        event_id = row[3]
        if isinstance(event_id, str):
            try:
                event_id = int(event_id)
            except ValueError:
                pass
        return AlertHistoryRecord(
            id=row[0],
            rule_id=row[1],
            triggered_at=row[2],
            event_id=event_id,
            action_type=ActionType(row[4]) if row[4] else ActionType.LOG_ALERT,
            action_status=ActionStatus(row[5]) if row[5] else ActionStatus.PENDING,
            action_executed_at=row[6],
            error_message=row[7],
        )


__all__ = [
    "AlertManager",
    "AlertPersistenceError",
]
