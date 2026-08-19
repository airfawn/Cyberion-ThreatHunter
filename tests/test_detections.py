import queue
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.alerts import AlertRule, AlertSeverity, ActionConfig, ActionType
from src.alerts import DetectionType, ThresholdConfig, TimeUnit
from src.database import CyberionDB, EventPersistenceWorker
from src.detections.engine import DetectionEngine
from src.query.query_model import Condition, ConditionGroup, ComparisonOperator, LogicalOperator, QueryDefinition


def _build_rule(name: str, enabled: bool = True) -> AlertRule:
    query_def = QueryDefinition.empty()
    query_def.root_group.logical_operator = LogicalOperator.AND
    query_def.root_group.add_condition(
        Condition(field="process_name", operator=ComparisonOperator.EQUALS, value="powershell.exe")
    )
    query_def.root_group.add_condition(
        Condition(field="command", operator=ComparisonOperator.CONTAINS, value="-enc")
    )
    return AlertRule(
        name=name,
        description="Detect PowerShell encoding",
        severity=AlertSeverity.HIGH,
        enabled=enabled,
        query_definition=query_def,
        generated_kql="events | where process_name == \"powershell.exe\" and command contains \"-enc\"",
        action=ActionConfig(ActionType.LOG_ALERT),
    )


def _build_threshold_rule(name: str, count: int = 10, window: int = 60, group_by=None, cooldown: int = 0, cooldown_unit: TimeUnit = TimeUnit.MINUTES) -> AlertRule:
    query_def = QueryDefinition.empty()
    query_def.root_group.logical_operator = LogicalOperator.AND
    query_def.root_group.add_condition(
        Condition(field="event_type", operator=ComparisonOperator.EQUALS, value="authentication_failure")
    )
    return AlertRule(
        name=name,
        description="Threshold auth failure detector",
        severity=AlertSeverity.HIGH,
        detection_type=DetectionType.THRESHOLD,
        threshold=ThresholdConfig(
            count=count,
            window=window,
            unit=TimeUnit.SECONDS,
            group_by=group_by or ["ip_address"],
            cooldown=cooldown,
            cooldown_unit=cooldown_unit,
        ),
        query_definition=query_def,
        generated_kql="events | where event_type == \"authentication_failure\"",
        action=ActionConfig(ActionType.LOG_ALERT),
        creator_name="qa-user",
    )


def _insert_auth_failure(db, ts: datetime, ip: str = "10.0.0.1", user: str = "alice") -> dict:
    event_id = db.insert_event({
        "timestamp": ts.isoformat(),
        "source": "test",
        "event_type": "authentication_failure",
        "ip_address": ip,
        "user": user,
        "raw_event": '{"event_type":"authentication_failure"}',
        "structured": {
            "event_type": "authentication_failure",
            "ip_address": ip,
            "user": user,
        },
    })
    return db.get_event(event_id)


def test_detection_engine_creates_detection_for_matching_event(tmp_path):
    db = CyberionDB(tmp_path / "detections.db")
    rule = db.alerts.create_rule(_build_rule("PowerShell Encoded"))

    event_id = db.insert_event({
        "source": "test",
        "raw_event": '{"process": "powershell.exe", "command": "powershell.exe -enc XXXXX"}',
        "structured": {
            "process_name": "powershell.exe",
            "command": "powershell.exe -enc XXXXX",
        },
    })
    event = db.get_event(event_id)

    engine = DetectionEngine(db)
    detections = engine.evaluate_event(event)

    assert len(detections) == 1
    assert detections[0].rule_id == rule.id
    assert detections[0].trigger_event_id == event_id
    assert detections[0].status == "new"


def test_detection_engine_skips_inactive_rules(tmp_path):
    db = CyberionDB(tmp_path / "inactive.db")
    db.alerts.create_rule(_build_rule("Disabled Rule", enabled=False))

    event_id = db.insert_event({
        "source": "test",
        "raw_event": '{"process": "powershell.exe", "command": "powershell.exe -enc XXXXX"}',
        "structured": {
            "process_name": "powershell.exe",
            "command": "powershell.exe -enc XXXXX",
        },
    })
    event = db.get_event(event_id)

    engine = DetectionEngine(db)
    detections = engine.evaluate_event(event)

    assert detections == []


def test_detection_engine_prevents_duplicates_for_same_event_and_rule(tmp_path):
    db = CyberionDB(tmp_path / "dup.db")
    db.alerts.create_rule(_build_rule("Dup Rule"))

    event_id = db.insert_event({
        "source": "test",
        "raw_event": '{"process": "powershell.exe", "command": "powershell.exe -enc XXXXX"}',
        "structured": {
            "process_name": "powershell.exe",
            "command": "powershell.exe -enc XXXXX",
        },
    })
    event = db.get_event(event_id)

    engine = DetectionEngine(db)
    first = engine.evaluate_event(event)
    second = engine.evaluate_event(event)

    assert len(first) == 1
    assert second == []


def test_detection_engine_creates_alert_history_entry(tmp_path):
    db = CyberionDB(tmp_path / "alert-history.db")
    rule = db.alerts.create_rule(_build_rule("Alert History Rule"))

    event_id = db.insert_event({
        "source": "test",
        "raw_event": '{"process": "powershell.exe", "command": "powershell.exe -enc XXXXX"}',
        "structured": {
            "process_name": "powershell.exe",
            "command": "powershell.exe -enc XXXXX",
        },
    })
    event = db.get_event(event_id)

    engine = DetectionEngine(db)
    detections = engine.evaluate_event(event)

    assert len(detections) == 1
    history = db.alerts.get_rule_history(rule.id)
    assert len(history) == 1
    assert history[0].event_id == event_id


def test_event_persistence_worker_creates_detection_for_inserted_event(tmp_path):
    db = CyberionDB(tmp_path / "worker.db")
    db.alerts.create_rule(_build_rule("Worker Rule"))

    input_queue = queue.Queue()
    output_queue = queue.Queue()
    worker = EventPersistenceWorker(db, input_queue, output_queue, batch_size=1, flush_interval=0.01)
    worker.start()

    input_queue.put({
        "source": "test",
        "raw_event": '{"process": "powershell.exe", "command": "powershell.exe -enc XXXXX"}',
        "structured": {
            "process_name": "powershell.exe",
            "command": "powershell.exe -enc XXXXX",
        },
    })

    worker.stop()

    assert output_queue.qsize() == 1
    detections = db.detections.get_all_detections(limit=10)
    assert len(detections) == 1


def test_threshold_10_events_within_60_seconds_triggers_alert(tmp_path):
    db = CyberionDB(tmp_path / "threshold-hit.db")
    db.alerts.create_rule(_build_threshold_rule("Auth Fail Burst", count=10, window=60))
    engine = DetectionEngine(db)

    start = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    all_detections = []
    for i in range(10):
        event = _insert_auth_failure(db, start + timedelta(seconds=i), ip="10.0.0.9")
        all_detections.extend(engine.evaluate_event(event))

    assert len(all_detections) == 1
    assert all_detections[0].metadata.get("detection_type") == "threshold"


def test_threshold_9_events_within_60_seconds_no_alert(tmp_path):
    db = CyberionDB(tmp_path / "threshold-miss.db")
    db.alerts.create_rule(_build_threshold_rule("Auth Fail Burst", count=10, window=60))
    engine = DetectionEngine(db)

    start = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    all_detections = []
    for i in range(9):
        event = _insert_auth_failure(db, start + timedelta(seconds=i), ip="10.0.0.9")
        all_detections.extend(engine.evaluate_event(event))

    assert all_detections == []


def test_threshold_events_spread_beyond_window_no_alert(tmp_path):
    db = CyberionDB(tmp_path / "threshold-window-expired.db")
    db.alerts.create_rule(_build_threshold_rule("Auth Fail Spread", count=10, window=60))
    engine = DetectionEngine(db)

    start = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    all_detections = []
    for i in range(10):
        event = _insert_auth_failure(db, start + timedelta(seconds=i * 7), ip="10.0.0.9")
        all_detections.extend(engine.evaluate_event(event))

    assert all_detections == []


def test_threshold_grouping_separates_ip_counters(tmp_path):
    db = CyberionDB(tmp_path / "threshold-group-ip.db")
    db.alerts.create_rule(_build_threshold_rule("Per-IP Failures", count=3, window=60, group_by=["ip_address"]))
    engine = DetectionEngine(db)
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    for i in range(2):
        engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=i), ip="10.0.0.1"))
    for i in range(2):
        engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=i), ip="10.0.0.2"))

    # Third event for ip1 should trigger one detection, ip2 remains below threshold.
    detections = engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=3), ip="10.0.0.1"))
    assert len(detections) == 1


def test_threshold_multiple_group_by_fields(tmp_path):
    db = CyberionDB(tmp_path / "threshold-group-multi.db")
    db.alerts.create_rule(_build_threshold_rule("Per IP/User", count=2, window=60, group_by=["ip_address", "user"]))
    engine = DetectionEngine(db)
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Same IP but different users should not share counters.
    engine.evaluate_event(_insert_auth_failure(db, base, ip="10.0.0.4", user="alice"))
    engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=1), ip="10.0.0.4", user="bob"))
    detections = engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=2), ip="10.0.0.4", user="alice"))
    assert len(detections) == 1


def test_threshold_cooldown_suppresses_duplicate_alerts(tmp_path):
    db = CyberionDB(tmp_path / "threshold-cooldown.db")
    db.alerts.create_rule(_build_threshold_rule("Cooldown Rule", count=3, window=60, cooldown=10, cooldown_unit=TimeUnit.MINUTES))
    engine = DetectionEngine(db)
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    detections = []
    for i in range(3):
        detections.extend(engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=i), ip="10.0.0.5")))
    assert len(detections) == 1

    # More matching events inside cooldown should not raise another alert.
    for i in range(4, 8):
        assert engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=i), ip="10.0.0.5")) == []


def test_threshold_window_expiration_removes_old_events(tmp_path):
    db = CyberionDB(tmp_path / "threshold-expire.db")
    db.alerts.create_rule(_build_threshold_rule("Window Expiration", count=3, window=60, group_by=["ip_address"]))
    engine = DetectionEngine(db)
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=0), ip="10.0.0.6"))
    engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=1), ip="10.0.0.6"))
    # This event arrives after first two are out of window, so should not trigger.
    detections = engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=70), ip="10.0.0.6"))
    assert detections == []


def test_threshold_alert_contains_triggering_events(tmp_path):
    db = CyberionDB(tmp_path / "threshold-trigger-events.db")
    rule = db.alerts.create_rule(_build_threshold_rule("Trigger Events", count=3, window=60, group_by=["ip_address"]))
    engine = DetectionEngine(db)
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    detections = []
    for i in range(3):
        detections.extend(engine.evaluate_event(_insert_auth_failure(db, base + timedelta(seconds=i), ip="10.0.0.7")))

    assert len(detections) == 1
    trigger_ids = detections[0].metadata.get("trigger_event_ids")
    assert isinstance(trigger_ids, list)
    assert len(trigger_ids) == 3

    history = db.alerts.get_rule_history(rule.id)
    assert len(history) == 1
    assert len(history[0].event_ids) == 3


def test_existing_single_event_rule_still_functions(tmp_path):
    db = CyberionDB(tmp_path / "single-regression.db")
    db.alerts.create_rule(_build_rule("PowerShell Encoded"))
    engine = DetectionEngine(db)

    event_id = db.insert_event({
        "source": "test",
        "raw_event": '{"process": "powershell.exe", "command": "powershell.exe -enc XXXXX"}',
        "structured": {
            "process_name": "powershell.exe",
            "command": "powershell.exe -enc XXXXX",
        },
    })
    detections = engine.evaluate_event(db.get_event(event_id))
    assert len(detections) == 1
    assert detections[0].metadata.get("detection_type") == "single_event"
