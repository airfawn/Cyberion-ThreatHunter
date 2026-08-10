"""Detection persistence manager for storing and loading detections."""

import json
import threading
from typing import Any, Dict, List, Optional

from . import Detection, DetectionStatus


class DetectionManager:
    """Persist detections in SQLite using the existing database connection."""

    def __init__(self, conn):
        self.conn = conn
        self._lock = threading.RLock()
        self._create_schema()

    def _create_schema(self) -> None:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id TEXT PRIMARY KEY,
                    rule_id TEXT,
                    rule_name TEXT,
                    rule_source TEXT,
                    trigger_event_id INTEGER,
                    severity TEXT,
                    status TEXT,
                    detected_at TEXT,
                    metadata TEXT
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_detections_rule_id ON detections(rule_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_detections_trigger_event_id ON detections(trigger_event_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_detections_detected_at ON detections(detected_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity)")
            self.conn.commit()

    def create_detection(
        self,
        *,
        rule_id: Optional[str],
        rule_name: str,
        rule_source: str,
        trigger_event_id: Optional[int],
        severity: str,
        status: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Detection:
        detection = Detection(
            detection_id=self._new_id(),
            rule_id=rule_id,
            rule_name=rule_name,
            rule_source=rule_source,
            trigger_event_id=trigger_event_id,
            severity=severity,
            status=status,
            metadata=metadata or {},
        )
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                INSERT INTO detections (
                    detection_id, rule_id, rule_name, rule_source,
                    trigger_event_id, severity, status, detected_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    detection.detection_id,
                    detection.rule_id,
                    detection.rule_name,
                    detection.rule_source,
                    detection.trigger_event_id,
                    detection.severity,
                    detection.status,
                    detection.detected_at,
                    json.dumps(detection.metadata or {}, ensure_ascii=False),
                ),
            )
            self.conn.commit()
        return detection

    def get_detection(self, detection_id: str) -> Optional[Detection]:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT detection_id, rule_id, rule_name, rule_source, trigger_event_id, severity, status, detected_at, metadata FROM detections WHERE detection_id = ?", (detection_id,))
            row = cur.fetchone()
            return self._row_to_detection(row) if row else None

    def get_all_detections(self, limit: int = 100, offset: int = 0) -> List[Detection]:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT detection_id, rule_id, rule_name, rule_source, trigger_event_id, severity, status, detected_at, metadata FROM detections ORDER BY detected_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            return [self._row_to_detection(row) for row in cur.fetchall()]

    def get_detection_for_rule_event(self, rule_id: Optional[str], trigger_event_id: Optional[int]) -> Optional[Detection]:
        if not rule_id or trigger_event_id is None:
            return None
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT detection_id, rule_id, rule_name, rule_source, trigger_event_id, severity, status, detected_at, metadata FROM detections WHERE rule_id = ? AND trigger_event_id = ? ORDER BY detected_at DESC LIMIT 1",
                (rule_id, trigger_event_id),
            )
            row = cur.fetchone()
            return self._row_to_detection(row) if row else None

    def get_summary(self) -> Dict[str, int]:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM detections")
            total = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM detections WHERE status = ?", (DetectionStatus.NEW.value,))
            new_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM detections WHERE severity IN ('high', 'critical')")
            high_critical = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM detections WHERE status = ?", (DetectionStatus.RESOLVED.value,))
            resolved = cur.fetchone()[0]
            return {"total": total, "new": new_count, "high_critical": high_critical, "resolved": resolved}

    def update_status(self, detection_id: str, status: str) -> None:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE detections SET status = ? WHERE detection_id = ?", (status, detection_id))
            self.conn.commit()

    def _row_to_detection(self, row) -> Detection:
        if not row:
            return None
        detection_id, rule_id, rule_name, rule_source, trigger_event_id, severity, status, detected_at, metadata = row
        meta = {}
        if metadata:
            try:
                meta = json.loads(metadata)
            except (TypeError, json.JSONDecodeError):
                meta = {}
        return Detection(
            detection_id=detection_id,
            rule_id=rule_id,
            rule_name=rule_name,
            rule_source=rule_source,
            trigger_event_id=trigger_event_id,
            severity=severity,
            status=status,
            detected_at=detected_at,
            metadata=meta,
        )

    def _new_id(self) -> str:
        import uuid
        return f"DET-{uuid.uuid4().hex[:8].upper()}"


__all__ = ["DetectionManager"]
