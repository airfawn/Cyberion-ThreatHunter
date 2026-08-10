"""Tests for the persistent event database layer, query engine foundation,
and event repository.

Run from the project root:  python3 -m pytest tests/test_database.py -v
"""

import json
import os
import queue
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

from src.database import (  # noqa: E402
    SCHEMA_COLUMNS,
    CyberionDB,
    EventPersistenceWorker,
    default_db_path,
)
from src.event_repository import EventRepository  # noqa: E402
from src.query_engine import QueryCondition, QueryEngine, normalize_conditions  # noqa: E402


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _base_event(i: int) -> dict:
    return {
        "timestamp": f"2026-08-0{i % 9 + 1}T00:00:00.000000Z",
        "received_at": f"2026-08-0{i % 9 + 1}T00:00:01.000000Z",
        "source": "log:test",
        "raw_event": json.dumps(
            {"event_type": "auth", "message": f"login #{i}", "severity": i % 5}
        ),
        "event_type": "auth",
        "message": f"login #{i}",
        "severity": i % 5,
        "process": "sshd",
    }


# ---------------------------------------------------------------------------
# Schema / lifecycle
# ---------------------------------------------------------------------------


def test_default_db_path_is_project_data_dir():
    path = default_db_path()
    assert path.name == "cyberion.db"
    assert "data" in path.parts


def test_create_schema(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    assert db.db_path.exists()
    cur = db.conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
    )
    assert cur.fetchone() is not None
    db.close()


def test_close_is_idempotent(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.close()
    db.close()


# ---------------------------------------------------------------------------
# Insert / retrieve
# ---------------------------------------------------------------------------


def test_insert_event_returns_id_and_retrievable_by_id(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    event_id = db.insert_event(_base_event(1))
    assert isinstance(event_id, int)
    row = db.get_event(event_id)
    assert row is not None
    assert row["id"] == event_id
    assert row["message"] == "login #1"
    assert row["source"] == "log:test"
    db.close()


def test_get_event_missing_returns_none(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    assert db.get_event(9999) is None
    db.close()


def test_insert_events_bulk(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    count = db.insert_events([_base_event(i) for i in range(10)])
    assert count == 10
    assert db.count_events() == 10
    db.close()


def test_insert_event_accepts_server_wire_5_tuple(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    event_id = db.insert_event(
        (
            "2026-08-06T00:00:00Z",  # received_at
            "log:auth",  # source
            '{"event_type": "auth", "message": "hello"}',  # raw_event
            '{"event_type": "auth", "message": "hello"}',  # raw_message
            {"event_type": "auth", "message": "hello"},  # structured
        )
    )
    row = db.get_event(event_id)
    assert row["source"] == "log:auth"
    assert row["message"] == "hello"
    assert row["raw_message"] == '{"event_type": "auth", "message": "hello"}'
    db.close()


def test_insert_event_accepts_server_wire_3_tuple(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    event_id = db.insert_event(("2026-08-06T00:00:00Z", "log:auth", '{"a": 1}'))
    row = db.get_event(event_id)
    assert row["source"] == "log:auth"
    assert row["raw_message"] == '{"a": 1}'
    db.close()


def test_empty_db_returns_no_events(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    assert db.get_events() == []
    assert db.count_events() == 0
    db.close()


def test_reopen_db_persists_events(tmp_path):
    path = tmp_path / "cyberion.db"
    db = CyberionDB(path)
    db.insert_events([_base_event(i) for i in range(5)])
    db.close()

    db2 = CyberionDB(path)
    assert db2.count_events() == 5
    events = db2.get_events()
    assert len(events) == 5
    assert all(e["raw_message"] for e in events)
    db2.close()


def test_raw_event_preserved_verbatim(tmp_path):
    raw = '{"event_type": "custom", "message": "héllo wörld", "n": 42}'
    db = CyberionDB(tmp_path / "cyberion.db")
    event_id = db.insert_event({"raw_event": raw, "source": "log:x"})
    row = db.get_event(event_id)
    assert row["raw_event"] == raw
    assert row["raw_message"] == raw
    db.close()


def test_raw_event_dict_serialized_not_crashed(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    event_id = db.insert_event({"raw_event": {"event_type": "x"}, "source": "log:y"})
    row = db.get_event(event_id)
    assert json.loads(row["raw_event"]) == {"event_type": "x"}
    db.close()


# ---------------------------------------------------------------------------
# Dynamic fields
# ---------------------------------------------------------------------------


def test_optional_and_dynamic_fields_roundtrip(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    event_id = db.insert_event(
        {
            "raw_event": '{"custom_metric": 42}',
            "source": "log:dyn",
            "hostname": "host-1",
            "custom_metric": 42,
            "nested": {"a": 1},
        }
    )
    row = db.get_event(event_id)
    assert row["hostname"] == "host-1"
    assert row["custom_metric"] == 42
    assert row["nested"] == {"a": 1}
    db.close()


def test_alias_field_process_stored_in_process_name(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    event_id = db.insert_event(
        {"raw_event": "{}", "source": "log:a", "process": "sshd"}
    )
    row = db.get_event(event_id)
    assert row["process_name"] == "sshd"
    db.close()


def test_dynamic_field_searchable(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_events(
        [
            {
                "raw_event": "{}",
                "source": "log:dyn",
                "event_type": "auth",
                "attack_scenario": "brute force",
            },
            {
                "raw_event": "{}",
                "source": "log:dyn",
                "event_type": "auth",
                "attack_scenario": "lateral movement",
            },
        ]
    )
    results = db.search_events(
        [{"field": "attack_scenario", "op": "contains", "value": "force"}]
    )
    assert len(results) == 1
    assert results[0]["attack_scenario"] == "brute force"
    db.close()


# ---------------------------------------------------------------------------
# Ordering / pagination
# ---------------------------------------------------------------------------


def test_get_events_newest_first(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    ids = [db.insert_event(_base_event(i)) for i in range(5)]
    events = db.get_events()
    assert [e["id"] for e in events] == list(reversed(ids))
    db.close()


def test_get_events_pagination_limit_and_offset(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    ids = [db.insert_event(_base_event(i)) for i in range(5)]
    page1 = db.get_events(limit=2, offset=0)
    page2 = db.get_events(limit=2, offset=2)
    assert [e["id"] for e in page1] == ids[-1:-3:-1]
    assert [e["id"] for e in page2] == ids[-3:-5:-1]
    db.close()


def test_get_events_since(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_event(_base_event(1))  # 2026-08-02
    db.insert_event(_base_event(8))  # 2026-08-09
    results = db.get_events_since("2026-08-05T00:00:00")
    assert len(results) == 1
    assert results[0]["timestamp"].startswith("2026-08-09")
    db.close()


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def test_filter_operators(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_events([_base_event(i) for i in range(1, 4)])  # severities 1,2,3
    assert len(db.search_events([{"field": "severity", "op": ">=", "value": 3}])) == 1
    assert len(db.search_events([{"field": "severity", "op": "<", "value": 3}])) == 2
    assert len(db.search_events([{"field": "severity", "op": "==", "value": 2}])) == 1
    assert len(db.search_events([{"field": "severity", "op": "!=", "value": 2}])) == 2
    assert len(db.search_events([{"field": "severity", "op": ">", "value": 2}])) == 1
    assert len(db.search_events([{"field": "severity", "op": "<=", "value": 2}])) == 2
    db.close()


def test_string_pattern_operators(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_events([_base_event(i) for i in range(1, 4)])  # messages login #1..3
    assert len(db.search_events([{"field": "message", "op": "contains", "value": "ogin"}])) == 3
    assert len(db.search_events([{"field": "message", "op": "startswith", "value": "login #3"}])) == 1
    assert len(db.search_events([{"field": "message", "op": "endswith", "value": "#2"}])) == 1
    db.close()


def test_search_combined_conditions_and_count(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_events(
        [
            {**_base_event(1), "event_type": "auth", "hostname": "h1"},
            {**_base_event(2), "event_type": "auth", "hostname": "h2"},
            {**_base_event(3), "event_type": "network", "hostname": "h1"},
        ]
    )
    conditions = [
        {"field": "hostname", "op": "==", "value": "h1"},
        {"field": "event_type", "op": "==", "value": "auth"},
    ]
    assert len(db.search_events(conditions)) == 1
    assert db.count_events(conditions) == 1
    db.close()


def test_distinct_values(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_events(
        [
            {**_base_event(1), "event_type": "auth", "hostname": "h1"},
            {**_base_event(2), "event_type": "auth", "hostname": "h2"},
            {**_base_event(3), "event_type": "network", "hostname": "h1"},
        ]
    )
    assert sorted(db.get_distinct_values("event_type")) == ["auth", "network"]
    assert sorted(db.get_distinct_values("hostname")) == ["h1", "h2"]
    assert db.get_distinct_values("nonexistent_thing") == []
    db.close()


def test_execute_query_requires_where_fragment(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_events([_base_event(i) for i in range(3)])
    assert len(db.execute_query("WHERE event_type = ?", ["auth"])) == 3
    with pytest.raises(ValueError):
        db.execute_query("DELETE FROM events", [])
    db.close()


# ---------------------------------------------------------------------------
# Malformed input / injection safety
# ---------------------------------------------------------------------------


def test_malformed_conditions_rejected(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    with pytest.raises(ValueError):
        db.search_events([{"field": "message", "op": "~~", "value": "x"}])
    with pytest.raises(ValueError):
        db.search_events([{"field": "bad field!", "op": "==", "value": "x"}])
    with pytest.raises(ValueError):
        db.search_events([{"field": "message", "op": "=="}])
    with pytest.raises(ValueError):
        db.search_events(["not-a-dict"])
    with pytest.raises(ValueError):
        db.search_events({"field": "message", "op": "==", "value": "x"})
    db.close()


def test_sql_injection_in_value_does_not_leak(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_events([_base_event(i) for i in range(3)])
    results = db.search_events(
        [{"field": "message", "op": "==", "value": "' OR '1'='1"}]
    )
    assert results == []
    results = db.search_events(
        [{"field": "message", "op": "contains", "value": "%' OR 1=1 --"}]
    )
    assert results == []
    db.close()


def test_sql_injection_in_field_rejected(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    with pytest.raises(ValueError):
        db.search_events(
            [{"field": "message' OR '1'='1", "op": "==", "value": "x"}]
        )
    with pytest.raises(ValueError):
        db.search_events(
            [{"field": "message; DROP TABLE events; --", "op": "==", "value": "x"}]
        )
    db.close()


# ---------------------------------------------------------------------------
# Query engine
# ---------------------------------------------------------------------------


def test_query_condition_validation():
    QueryCondition("severity", ">=", 3)
    with pytest.raises(ValueError):
        QueryCondition("severity", "~~", 3)
    with pytest.raises(ValueError):
        QueryCondition("weird field", "==", 3)


def test_query_condition_canonicalizes_alias():
    assert QueryCondition("process", "==", "sshd").field == "process_name"


def test_normalize_conditions():
    conds = normalize_conditions(
        [QueryCondition.eq("event_type", "auth"), {"field": "severity", "op": ">", "value": 2}]
    )
    assert conds == [
        {"field": "event_type", "op": "==", "value": "auth"},
        {"field": "severity", "op": ">", "value": 2},
    ]
    assert normalize_conditions(None) == []
    with pytest.raises(ValueError):
        normalize_conditions("nope")


def test_query_engine_search_and_count(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_events([_base_event(i) for i in range(5)])
    engine = QueryEngine(db)
    assert engine.count() == 5
    assert engine.count([QueryCondition.eq("event_type", "auth")]) == 5
    assert len(engine.get_events(limit=2)) == 2
    assert engine.get_event(1) is not None
    assert engine.distinct("event_type") == ["auth"]
    assert "message" in engine.field_names()
    db.close()


def test_repository_boundary(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    db.insert_events([_base_event(i) for i in range(4)])
    repo = EventRepository(db=db)
    assert len(repo.load_recent(limit=2)) == 2
    assert repo.event_count() == 4
    assert repo.get_by_id(1) is not None
    assert repo.get_by_id(999) is None
    assert len(repo.search("event_type", "==", "auth")) == 4
    assert len(repo.search_conditions([QueryCondition.eq("severity", 2)])) == 1
    assert repo.count([QueryCondition.eq("severity", 2)]) == 1
    assert repo.distinct_values("event_type") == ["auth"]
    assert "process_name" in repo.known_fields()
    db.close()


def test_repository_requires_engine_or_db(tmp_path):
    with pytest.raises(ValueError):
        EventRepository()


# ---------------------------------------------------------------------------
# Persistence worker
# ---------------------------------------------------------------------------


def test_worker_batches_inserts_and_forwards(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    inbox = queue.Queue()
    outbox = queue.Queue()
    worker = EventPersistenceWorker(db, inbox, outbox, batch_size=10, flush_interval=0.05)
    worker.start()
    try:
        for i in range(25):
            inbox.put(_base_event(i))
        deadline = time.time() + 5
        while outbox.qsize() < 25 and time.time() < deadline:
            time.sleep(0.01)
        assert outbox.qsize() == 25
        assert db.count_events() == 25
    finally:
        worker.stop()
    db.close()


def test_worker_stop_drains_queued_events(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    inbox = queue.Queue()
    outbox = queue.Queue()
    worker = EventPersistenceWorker(db, inbox, outbox, batch_size=100, flush_interval=60)
    worker.start()
    try:
        for i in range(7):
            inbox.put(_base_event(i))
        worker.stop()
    finally:
        pass
    assert db.count_events() == 7
    assert outbox.qsize() == 7
    db.close()


def test_worker_persists_server_wire_tuples(tmp_path):
    db = CyberionDB(tmp_path / "cyberion.db")
    inbox = queue.Queue()
    outbox = queue.Queue()
    worker = EventPersistenceWorker(db, inbox, outbox, batch_size=2, flush_interval=0.05)
    worker.start()
    try:
        for _ in range(3):
            inbox.put(
                (
                    "2026-08-06T00:00:00Z",
                    "log:auth",
                    '{"event_type": "auth", "message": "hello"}',
                    '{"event_type": "auth", "message": "hello"}',
                    {"event_type": "auth", "message": "hello"},
                )
            )
        deadline = time.time() + 5
        while outbox.qsize() < 3 and time.time() < deadline:
            time.sleep(0.01)
        assert outbox.qsize() == 3
        assert db.count_events() == 3
        events = db.get_events()
        assert all(e["message"] == "hello" for e in events)
    finally:
        worker.stop()
    db.close()


def test_worker_survives_db_error_and_still_forwards(tmp_path, monkeypatch):
    db = CyberionDB(tmp_path / "cyberion.db")

    def boom(events):
        raise RuntimeError("disk full")

    monkeypatch.setattr(db, "insert_events", boom)
    inbox = queue.Queue()
    outbox = queue.Queue()
    worker = EventPersistenceWorker(db, inbox, outbox, batch_size=5, flush_interval=0.05)
    worker.start()
    try:
        for i in range(6):
            inbox.put(_base_event(i))
        deadline = time.time() + 5
        while outbox.qsize() < 6 and time.time() < deadline:
            time.sleep(0.01)
        assert outbox.qsize() == 6
        assert worker._thread.is_alive()
    finally:
        worker.stop()
    db.close()


# ---------------------------------------------------------------------------
# GUI startup load (repository -> MainWindow)
# ---------------------------------------------------------------------------


def test_mainwindow_loads_persisted_events_on_startup(monkeypatch, tmp_path):
    from PyQt5.QtWidgets import QApplication

    from src.main import MainWindow

    app = QApplication.instance() or QApplication([])
    db_path = tmp_path / "cyberion.db"
    monkeypatch.setattr("src.database.default_db_path", lambda: db_path)

    db = CyberionDB(db_path)
    db.insert_event(
        {
            "timestamp": "2026-08-06T00:00:00Z",
            "source": "log:auth",
            "raw_event": '{"event_type": "auth", "message": "hello"}',
            "event_type": "auth",
            "process": "sshd",
        }
    )
    db.close()

    port = _free_port()
    aux_port = _free_port()
    win = MainWindow(host="127.0.0.1", port=port, aux_host="127.0.0.1", aux_port=aux_port)
    try:
        assert len(win.events) >= 1
        assert win.event_counter >= 1
        assert win.events[0]["event_type"] == "auth"
        assert win.events[0]["process"] == "sshd"
        assert win.events[0]["raw_message"] == '{"event_type": "auth", "message": "hello"}'
    finally:
        try:
            win.server_thread.stop()
            win.server_thread.join(timeout=1)
        except Exception:
            pass
        try:
            win.persistence_worker.stop()
        except Exception:
            pass
        try:
            win.db.close()
        except Exception:
            pass
