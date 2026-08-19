"""Alert persistence layer - manages alert rules, statistics, and history in database."""

import json
import sqlite3
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import AlertRule, AlertStatistics, AlertHistoryRecord, ActionType, AlertLifecycleStatus


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
                    detection_type  TEXT DEFAULT 'single_event',
                    threshold_config TEXT,
                    creator_name    TEXT,
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
                    event_ids          TEXT,
                    group_key          TEXT,
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
            
            # Migrate schema first to ensure columns exist before creating indexes
            self._migrate_schema(cur)
            
            # Now create indexes (lifecycle_status column should exist now)
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_history_lifecycle "
                "ON alert_history(lifecycle_status)"
            )
            
            self.conn.commit()

    def _migrate_schema(self, cur) -> None:
        """Add new columns when upgrading existing databases."""
        cur.execute("PRAGMA table_info(alert_rules)")
        rule_cols = {row[1] for row in cur.fetchall()}
        if "detection_type" not in rule_cols:
            cur.execute("ALTER TABLE alert_rules ADD COLUMN detection_type TEXT DEFAULT 'single_event'")
        if "threshold_config" not in rule_cols:
            cur.execute("ALTER TABLE alert_rules ADD COLUMN threshold_config TEXT")
        if "creator_name" not in rule_cols:
            cur.execute("ALTER TABLE alert_rules ADD COLUMN creator_name TEXT")

        cur.execute("PRAGMA table_info(alert_history)")
        history_cols = {row[1] for row in cur.fetchall()}
        if "event_ids" not in history_cols:
            cur.execute("ALTER TABLE alert_history ADD COLUMN event_ids TEXT")
        if "group_key" not in history_cols:
            cur.execute("ALTER TABLE alert_history ADD COLUMN group_key TEXT")
        if "lifecycle_status" not in history_cols:
            cur.execute("ALTER TABLE alert_history ADD COLUMN lifecycle_status TEXT DEFAULT 'new'")
        else:
            # Migrate existing 'open' -> 'new', 'closed' -> 'resolved' for backward compatibility
            cur.execute(
                "UPDATE alert_history SET lifecycle_status = 'new' WHERE lifecycle_status = 'open'"
            )
            cur.execute(
                "UPDATE alert_history SET lifecycle_status = 'resolved' WHERE lifecycle_status = 'closed'"
            )
        if "assignee" not in history_cols:
            cur.execute("ALTER TABLE alert_history ADD COLUMN assignee TEXT")
        if "note" not in history_cols:
            cur.execute("ALTER TABLE alert_history ADD COLUMN note TEXT")
        if "updated_at" not in history_cols:
            cur.execute("ALTER TABLE alert_history ADD COLUMN updated_at TEXT")
    
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
                    (id, name, description, enabled, severity, detection_type, threshold_config, creator_name, query_definition, 
                     generated_kql, action_type, action_config, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rule.id,
                        rule.name,
                        rule.description,
                        1 if rule.enabled else 0,
                        rule.severity.value,
                        rule.detection_type.value,
                        json.dumps(rule.threshold.to_dict()) if rule.threshold else None,
                        (rule.creator_name or "unknown"),
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
                  SELECT id, name, description, enabled, severity,
                      detection_type, threshold_config, creator_name, query_definition,
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
                    SELECT id, name, description, enabled, severity,
                           detection_type, threshold_config, creator_name, query_definition,
                              generated_kql, action_type, action_config, created_at, updated_at
                    FROM alert_rules
                    WHERE enabled = 1
                    ORDER BY created_at DESC
                    """
                )
            else:
                cur.execute(
                    """
                    SELECT id, name, description, enabled, severity,
                           detection_type, threshold_config, creator_name, query_definition,
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
                    SET name = ?, description = ?, enabled = ?, severity = ?, detection_type = ?,
                        threshold_config = ?, creator_name = ?, query_definition = ?, generated_kql = ?, action_type = ?,
                        action_config = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        rule.name,
                        rule.description,
                        1 if rule.enabled else 0,
                        rule.severity.value,
                        rule.detection_type.value,
                        json.dumps(rule.threshold.to_dict()) if rule.threshold else None,
                        (rule.creator_name or "unknown"),
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
                    (id, rule_id, triggered_at, event_id, event_ids, group_key, action_type,
                     action_status, action_executed_at, error_message, lifecycle_status,
                     assignee, note, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.id,
                        record.rule_id,
                        record.triggered_at,
                        record.event_id,
                        json.dumps(record.event_ids or []),
                        record.group_key,
                        record.action_type.value,
                        record.action_status.value,
                        record.action_executed_at,
                        record.error_message,
                        record.lifecycle_status.value,
                        record.assignee,
                        record.note,
                        record.updated_at,
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
                SELECT id, rule_id, triggered_at, event_id, event_ids, group_key,
                     action_type,
                     action_status, action_executed_at, error_message,
                     lifecycle_status, assignee, note, updated_at
                FROM alert_history
                WHERE rule_id = ?
                ORDER BY triggered_at DESC
                LIMIT ? OFFSET ?
                """,
                (rule_id, limit, offset)
            )
            
            return [self._history_row_to_record(row) for row in cur.fetchall()]

    def get_recent_history(self, limit: int = 200, open_only: bool = False) -> List[dict]:
        """Get recent triggered alerts across all rules for dashboard views."""
        with self._lock:
            cur = self.conn.cursor()
            query = """
                SELECT h.id, h.rule_id, r.name, r.severity, h.triggered_at, h.action_status,
                       h.lifecycle_status, h.assignee, h.note, h.group_key, h.event_id,
                       h.error_message, h.updated_at
                FROM alert_history h
                JOIN alert_rules r ON r.id = h.rule_id
            """
            params = []
            if open_only:
                query += " WHERE h.lifecycle_status != 'closed'"
            query += " ORDER BY h.triggered_at DESC LIMIT ?"
            params.append(limit)
            cur.execute(query, tuple(params))
            rows = cur.fetchall()

            result = []
            for row in rows:
                result.append({
                    "id": row[0],
                    "rule_id": row[1],
                    "rule_name": row[2],
                    "severity": row[3],
                    "triggered_at": row[4],
                    "action_status": row[5],
                    "lifecycle_status": row[6] or "new",
                    "assignee": row[7] or "",
                    "note": row[8] or "",
                    "group_key": row[9] or "",
                    "event_id": row[10] or "",
                    "error_message": row[11] or "",
                    "updated_at": row[12] or "",
                })
            return result

    def get_alert_overview(self) -> dict:
        """Get alert overview statistics across all alert history."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
                    SUM(CASE WHEN lifecycle_status = 'new' THEN 1 ELSE 0 END) as new,
                    SUM(CASE WHEN lifecycle_status = 'acknowledged' THEN 1 ELSE 0 END) as acknowledged,
                    SUM(CASE WHEN lifecycle_status = 'investigating' THEN 1 ELSE 0 END) as investigating,
                    SUM(CASE WHEN lifecycle_status = 'resolved' THEN 1 ELSE 0 END) as resolved,
                    SUM(CASE WHEN lifecycle_status = 'false_positive' THEN 1 ELSE 0 END) as false_positive
                FROM alert_history h
                JOIN alert_rules r ON r.id = h.rule_id
            """)
            row = cur.fetchone()
            return {
                "total": row[0] or 0,
                "critical": row[1] or 0,
                "high": row[2] or 0,
                "medium": row[3] or 0,
                "low": row[4] or 0,
                "new": row[5] or 0,
                "acknowledged": row[6] or 0,
                "investigating": row[7] or 0,
                "resolved": row[8] or 0,
                "false_positive": row[9] or 0,
            }
    
    def get_alerts(
        self,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        group_key: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[dict]:
        """Get alerts with filtering and pagination.
        
        Args:
            rule_id: Filter by rule ID
            severity: Filter by severity (critical, high, medium, low)
            status: Filter by lifecycle_status (new, acknowledged, investigating, resolved, false_positive)
            group_key: Filter by group_key
            limit: Maximum records to return
            offset: Starting record offset
            
        Returns:
            List of alert dicts with associated rule data including MITRE technique
        """
        from . import AlertRule, AlertSeverity
        
        with self._lock:
            cur = self.conn.cursor()
            query = """
                SELECT 
                    h.id, h.rule_id, r.name as rule_name, r.severity as rule_severity, 
                    h.triggered_at, h.action_status,
                    h.lifecycle_status, h.assignee, h.note, h.group_key, h.event_id,
                    h.error_message, h.updated_at
                FROM alert_history h
                JOIN alert_rules r ON r.id = h.rule_id
                WHERE 1=1
            """
            params = []
            
            if rule_id:
                query += " AND h.rule_id = ?"
                params.append(rule_id)
            
            if severity:
                query += " AND r.severity = ?"
                params.append(severity)
            
            if status:
                query += " AND h.lifecycle_status = ?"
                params.append(status)
            
            if group_key:
                query += " AND h.group_key = ?"
                params.append(group_key)
            
            query += " ORDER BY h.triggered_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cur.execute(query, params)
            rows = cur.fetchall()
            
            # Extract MITRE technique from rule's generated_kql
            mitre_map = {
                "T1059": "T1059.001",
                "T1027": "T1027",
                "T1110": "T1110",
                "T1059.001": "T1059.001",
                "T1048": "T1048",
                "T1033": "T1033",
                "T1078": "T1078",
                "T1078.004": "T1078.004",
                "T1059.005": "T1059.005",
                "T1566": "T1566",
                "T1021": "T1021",
                "T1040": "T1040",
                "T1071": "T1071",
                "T1095": "T1095",
                "T1203": "T1203",
                "T1499": "T1499",
            }
            
            result = []
            for row, rule_row in zip(rows, [None] * len(rows)):
                # Get the rule for MITRE extraction
                rule = None
                if row[1]:  # rule_id
                    rule = self.get_rule(row[1])
                
                mitre_technique = ""
                if rule and rule.generated_kql:
                    kql = rule.generated_kql.lower()
                    for mitre_pattern, mitre_id in mitre_map.items():
                        if mitre_pattern.lower() in kql:
                            mitre_technique = mitre_id
                            break
                
                result.append({
                    "id": row[0],
                    "rule_id": row[1],
                    "rule_name": row[2],
                    "severity": row[3] or "",
                    "triggered_at": row[4],
                    "action_status": row[5],
                    "lifecycle_status": row[6] or "new",
                    "assignee": row[7] or "",
                    "note": row[8] or "",
                    "group_key": row[9] or "",
                    "event_id": row[10] or "",
                    "error_message": row[11] or "",
                    "updated_at": row[12] or "",
                    "mitre_technique": mitre_technique,
                    "source_ip": "",
                    "destination_ip": "",
                    "hostname": "",
                    "user": "",
                })
            return result
    
    def count_alerts(
        self,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        group_key: Optional[str] = None,
    ) -> int:
        """Count alerts matching the given filters."""
        with self._lock:
            cur = self.conn.cursor()
            query = """
                SELECT COUNT(*)
                FROM alert_history h
                JOIN alert_rules r ON r.id = h.rule_id
                WHERE 1=1
            """
            params = []
            
            if rule_id:
                query += " AND h.rule_id = ?"
                params.append(rule_id)
            
            if severity:
                query += " AND r.severity = ?"
                params.append(severity)
            
            if status:
                query += " AND h.lifecycle_status = ?"
                params.append(status)
            
            if group_key:
                query += " AND h.group_key = ?"
                params.append(group_key)
            
            cur.execute(query, params)
            return cur.fetchone()[0]
    
    def update_alert_status(self, alert_id: str, lifecycle_status: AlertLifecycleStatus, assignee: Optional[str] = None, note: Optional[str] = None) -> None:
        """Update the lifecycle status and optional assignee/note of an alert."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                UPDATE alert_history
                SET lifecycle_status = ?,
                    assignee = COALESCE(?, assignee),
                    note = COALESCE(?, note),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    lifecycle_status.value,
                    assignee,
                    note,
                    datetime.utcnow().isoformat(),
                    alert_id,
                ),
            )
            self.conn.commit()

    def update_history_lifecycle(
        self,
        history_id: str,
        lifecycle_status: AlertLifecycleStatus,
        assignee: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        """Update lifecycle state for a triggered alert record."""
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                UPDATE alert_history
                SET lifecycle_status = ?,
                    assignee = COALESCE(?, assignee),
                    note = COALESCE(?, note),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    lifecycle_status.value,
                    assignee,
                    note,
                    datetime.utcnow().isoformat(),
                    history_id,
                ),
            )
            self.conn.commit()
    
    # ============================================================================
    # Helpers
    # ============================================================================
    
    def _row_to_rule(self, row) -> AlertRule:
        """Convert a database row to AlertRule."""
        from . import AlertRule, ActionConfig, ActionType, AlertSeverity, DetectionType, ThresholdConfig
        from ..query.query_model import QueryDefinition
        
        query_def_dict = json.loads(row[8]) if row[8] else {}
        query_def = QueryDefinition.from_dict(query_def_dict)
        
        threshold_config = json.loads(row[6]) if row[6] else None
        threshold = ThresholdConfig.from_dict(threshold_config) if threshold_config else None

        action_config = json.loads(row[11]) if row[11] else {}
        action = ActionConfig(
            action_type=ActionType(row[10]) if row[10] else ActionType.LOG_ALERT,
            config=action_config
        )
        
        return AlertRule(
            id=row[0],
            name=row[1],
            description=row[2],
            enabled=bool(row[3]),
            severity=AlertSeverity(row[4]) if row[4] else AlertSeverity.MEDIUM,
            detection_type=DetectionType(row[5]) if row[5] else DetectionType.SINGLE_EVENT,
            threshold=threshold,
            creator_name=row[7] or "",
            query_definition=query_def,
            generated_kql=row[9],
            action=action,
            created_at=row[12],
            updated_at=row[13],
        )
    
    def _history_row_to_record(self, row) -> AlertHistoryRecord:
        """Convert a database row to AlertHistoryRecord."""
        from . import AlertHistoryRecord, ActionType, ActionStatus, AlertLifecycleStatus
        
        event_id = row[3]
        if isinstance(event_id, str):
            try:
                event_id = int(event_id)
            except ValueError:
                pass

        event_ids = []
        if row[4]:
            try:
                raw_ids = json.loads(row[4])
                if isinstance(raw_ids, list):
                    event_ids = [int(v) for v in raw_ids if isinstance(v, (int, float, str)) and str(v).isdigit()]
            except Exception:
                event_ids = []
        return AlertHistoryRecord(
            id=row[0],
            rule_id=row[1],
            triggered_at=row[2],
            event_id=event_id,
            event_ids=event_ids,
            group_key=row[5],
            action_type=ActionType(row[6]) if row[6] else ActionType.LOG_ALERT,
            action_status=ActionStatus(row[7]) if row[7] else ActionStatus.PENDING,
            action_executed_at=row[8],
            error_message=row[9],
            lifecycle_status=AlertLifecycleStatus(row[10] or "new"),
            assignee=row[11],
            note=row[12],
            updated_at=row[13],
        )


__all__ = [
    "AlertManager",
    "AlertPersistenceError",
]
