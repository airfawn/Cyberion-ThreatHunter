"""Focused pipeline verification tests for Cyberion ThreatHunter.

Run from the project root:  python3 -m pytest tests/ -v
"""

import json
import os
import queue
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget  # noqa: E402

from Agent.log_queue import LogEntry, LogQueue, LogSender  # noqa: E402
from Agent.connector import connector as Connector  # noqa: E402
from src.database import EventDB  # noqa: E402
from src.main import EventDetailsDialog, MainWindow  # noqa: E402
from src.server import ServerThread  # noqa: E402


def make_entry(log_id=None, source="test"):
    return LogEntry(
        log_id=log_id or str(__import__("uuid").uuid4()),
        source=source,
        raw_event='{"event_type": "auth", "message": "hello"}',
        timestamp="2026-08-06T00:00:00.000000Z",
        event_type="auth",
        agent_id="agent-1",
    )


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# LogQueue / LogSender
# ---------------------------------------------------------------------------


def test_log_ids_unique():
    ids = {make_entry().log_id for _ in range(200)}
    assert len(ids) == 200


def test_queue_put_batch_mark_ack():
    q = LogQueue(max_size=10)
    entries = [make_entry() for _ in range(5)]
    for e in entries:
        assert q.put(e) is True

    stats = q.get_stats()
    assert stats["queued"] == 5 and stats["pending"] == 0

    batch = q.get_batch(5)
    assert len(batch) == 5
    assert q.get_stats()["queued"] == 0

    q.mark_sent(batch)
    assert q.get_stats()["pending"] == 5

    q.mark_acked([e.log_id for e in batch])
    stats = q.get_stats()
    assert stats["queued"] == 0 and stats["pending"] == 0


def test_ack_timeout_requeues_for_retry():
    q = LogQueue()
    sender = LogSender(log_queue=q, send_func=lambda m: True, agent_id="agent-1")
    entry = make_entry()
    q.put(entry)
    sender._send_batch(q.get_batch(5))

    assert q.get_stats()["pending"] == 1
    assert entry.log_id in sender._pending_acks

    sender._pending_acks[entry.log_id] = time.time() - 999
    sender.check_timeouts()

    stats = q.get_stats()
    assert stats["pending"] == 0
    assert stats["queued"] == 1


def test_send_failure_does_not_lose_entries():
    q = LogQueue()
    sender = LogSender(log_queue=q, send_func=lambda m: False, agent_id="agent-1")
    entries = [make_entry() for _ in range(3)]
    for e in entries:
        q.put(e)

    sender._send_batch(q.get_batch(5))

    stats = q.get_stats()
    assert stats["queued"] == 3, "entries must be requeued, not dropped, on send failure"
    assert stats["pending"] == 0


def test_retried_pending_entry_not_duplicated_on_failure():
    q = LogQueue()
    sender = LogSender(log_queue=q, send_func=lambda m: True, agent_id="agent-1")
    entry = make_entry()
    q.put(entry)
    sender._send_batch(q.get_batch(5))
    assert q.get_stats()["pending"] == 1

    entry.last_sent = 0.0
    retried = q.get_batch(5)
    assert len(retried) == 1

    sender.send_func = lambda m: False
    sender._send_batch(retried)

    stats = q.get_stats()
    assert stats["queued"] == 0
    assert stats["pending"] == 1, "pending entry must stay in pending, not be duplicated into queue"


def test_requeue_and_resend_flow():
    q = LogQueue()
    sender = LogSender(log_queue=q, send_func=lambda m: True, agent_id="agent-1")
    entry = make_entry()
    q.put(entry)
    sender._send_batch(q.get_batch(5))
    assert q.get_stats()["pending"] == 1

    sender._pending_acks[entry.log_id] = time.time() - 999
    sender.check_timeouts()
    assert q.get_stats()["queued"] == 1

    sender._send_batch(q.get_batch(5))
    assert q.get_stats()["pending"] == 1
    sender.log_queue.mark_acked([entry.log_id])
    assert q.get_stats()["pending"] == 0


def test_reconnect_no_duplicate_threads():
    sender = LogSender(log_queue=LogQueue(), send_func=lambda m: True, agent_id="agent-1")
    dummy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sender.start(recv_socket=dummy)
    first_sender, first_receiver = sender._sender_thread, sender._receiver_thread
    assert first_sender.is_alive() and first_receiver.is_alive()

    sender.start(recv_socket=dummy)
    assert sender._sender_thread is first_sender, "second start must not spawn duplicates"

    sender.stop()
    assert not first_sender.is_alive() and not first_receiver.is_alive()

    sender.start(recv_socket=dummy)
    assert sender._sender_thread is not first_sender
    assert sender._sender_thread.is_alive() and sender._receiver_thread.is_alive()
    sender.stop()
    dummy.close()


def test_offline_entries_retained():
    q = LogQueue()
    for _ in range(4):
        q.put(make_entry())
    assert q.get_stats()["queued"] == 4


def test_max_retries_drops_stale_entries():
    q = LogQueue()
    sender = LogSender(log_queue=q, send_func=lambda m: True, agent_id="a", max_retries=2)
    entry = make_entry()
    q.put(entry)

    for _ in range(2):
        entry.last_sent = 0.0
        sender._send_batch(q.get_batch(5))
        assert q.get_stats()["pending"] == 1

    assert entry.sent_count == 2
    entry.last_sent = 0.0
    sender._send_batch(q.get_batch(5))
    assert q.get_stats()["pending"] == 0
    assert entry.log_id not in sender._pending_acks
    assert q.get_batch(5) == []


def test_requeue_pending_preserves_sent_count():
    q = LogQueue()
    sender = LogSender(log_queue=q, send_func=lambda m: True, agent_id="a", max_retries=3)
    entry = make_entry()
    q.put(entry)
    sender._send_batch(q.get_batch(5))
    assert entry.sent_count == 1
    q.requeue_pending([entry.log_id])
    assert entry.sent_count == 1, "sent_count must persist across requeues"
    assert q.get_stats()["queued"] == 1


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


def test_server_log_batch_ack_and_dedup():
    event_queue = queue.Queue()
    port = _free_port()
    srv = ServerThread("127.0.0.1", port, event_queue)
    srv.start()
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.settimeout(5)
        log_id = "dedup-test-1"
        batch = {
            "type": "LOG_BATCH",
            "agent_id": "agent-1",
            "logs": [
                {
                    "log_id": log_id,
                    "source": "log:auth",
                    "raw_event": '{"event_type": "auth", "user": "bob", "message": "login"}',
                    "timestamp": "2026-08-06T00:00:00.000000Z",
                    "event_type": "auth",
                }
            ],
        }
        for _ in range(2):
            sock.sendall((json.dumps(batch) + "\n").encode("utf-8"))
            ack_line = b""
            while b"\n" not in ack_line:
                ack_line += sock.recv(4096)
            ack = json.loads(ack_line.decode().strip())
            assert ack["type"] == "ACK"
            assert log_id in ack["log_ids"]

        time.sleep(0.2)
        assert event_queue.qsize() == 1, "retransmitted log_id must not be queued twice"

        item = event_queue.get_nowait()
        assert len(item) == 5
        received_at, source, raw_event, raw_message, structured = item
        assert source == "log:auth"
        assert log_id in raw_message
        assert structured["event_type"] == "auth"
        assert structured["user"] == "bob"
        assert structured["raw_message"] == raw_message
    finally:
        sock.close()
        srv.stop()
        srv.join(timeout=3)


def test_server_bind_failure_retries():
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = _free_port()
    blocker.bind(("127.0.0.1", port))
    blocker.listen(1)

    statuses = []
    q = queue.Queue()
    srv = ServerThread("127.0.0.1", port, q, status_callback=statuses.append)
    srv.start()
    time.sleep(0.3)
    assert statuses and "Bind failed" in statuses[-1], f"got {statuses}"
    assert srv.is_alive()

    blocker.close()
    time.sleep(1.3)
    assert statuses[-1] == "Waiting for connection", f"got {statuses}"
    srv.stop()
    srv.join(timeout=3)
    assert not srv.is_alive()


def test_server_stop_quick_on_wildcard_bind():
    port = _free_port()
    q = queue.Queue()
    srv = ServerThread("0.0.0.0", port, q)
    srv.start()
    time.sleep(0.3)
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    time.sleep(0.1)
    srv.stop()
    start = time.time()
    srv.join(timeout=5)
    assert not srv.is_alive()
    assert time.time() - start < 3, "stop() must not hang on a wildcard bind"
    client.close()


def test_server_heartbeat_ack():
    event_queue = queue.Queue()
    port = _free_port()
    srv = ServerThread("127.0.0.1", port, event_queue)
    srv.start()
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.settimeout(5)
        hb = {"type": "HEARTBEAT", "agent_id": "agent-1", "timestamp": "2026-08-06T00:00:00.000000Z"}
        sock.sendall((json.dumps(hb) + "\n").encode("utf-8"))
        data = b""
        while b"\n" not in data:
            data += sock.recv(4096)
        reply = json.loads(data.decode().strip())
        assert reply["type"] == "HEARTBEAT_ACK"
        assert event_queue.empty()
    finally:
        sock.close()
        srv.stop()
        srv.join(timeout=3)


def test_server_legacy_event_queue_shape():
    event_queue = queue.Queue()
    port = _free_port()
    srv = ServerThread("127.0.0.1", port, event_queue)
    srv.start()
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        msg = {
            "source": "InitialData",
            "raw_event": json.dumps({"hostname": "h1", "ip_address": "10.0.0.5"}),
            "timestamp": "2026-08-06T00:00:00.000000Z",
            "event_type": "agent_info",
        }
        sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
        time.sleep(0.2)
        item = event_queue.get_nowait()
        assert len(item) == 5
        assert item[1] == "InitialData"
        assert item[3]  # raw_message present
        assert item[4]["hostname"] == "h1"
    finally:
        sock.close()
        srv.stop()
        srv.join(timeout=3)


def test_parse_raw_event():
    srv = ServerThread("127.0.0.1", _free_port(), queue.Queue())
    structured = srv._parse_raw_event(
        '{"event_type": "exec", "process": "bash", "pid": "12", "user": "root", "command": "ls"}'
    )
    assert structured["event_type"] == "exec"
    assert structured["process"] == "bash"
    assert structured["pid"] == "12"
    assert structured["user"] == "root"
    assert structured["command"] == "ls"

    plain = srv._parse_raw_event("some plain syslog line")
    assert plain["message"] == "some plain syslog line"


# ---------------------------------------------------------------------------
# GUI normalisation / dynamic fields / heartbeat gating
# ---------------------------------------------------------------------------


_QT_APP = None


def _build_window() -> MainWindow:
    global _QT_APP
    if _QT_APP is None:
        _QT_APP = QApplication([])
    win = MainWindow.__new__(MainWindow)
    win.available_fields = [
        ("timestamp", "Timestamp"),
        ("source", "Source"),
        ("event_type", "Event Type"),
        ("process", "Process"),
        ("pid", "PID"),
        ("user", "User"),
        ("ip_address", "IP Address"),
        ("message", "Message"),
        ("raw_message", "Raw Message"),
    ]
    win.default_selected_fields = {"timestamp", "source", "event_type", "message"}
    win.selected_fields = set(win.default_selected_fields)
    win.field_checkboxes = {}
    win.known_fields = {key for key, _ in win.available_fields}
    parent = QWidget()
    win.fields_layout = QVBoxLayout(parent)
    win.fields_layout.addStretch(1)
    win._test_parent = parent  # keep QWidget alive while the window is alive
    return win


def test_normalize_event_structured_dynamic_field():
    win = _build_window()
    structured = {
        "timestamp": "t1",
        "source": "s1",
        "event_type": "auth",
        "user": "bob",
        "message": "login",
    }
    result = win._normalize_event("t0", "fallback-src", "raw", "raw_message_value", structured)
    assert result["raw_message"] == "raw_message_value"
    assert result["source"] == "s1"
    assert result["timestamp"] == "t1"
    assert result["user"] == "bob"

    result = win._normalize_event("t0", "s1", "raw", "rm", {"command": "apt install"})
    assert result["command"] == "apt install"
    assert "command" in win.known_fields
    assert "command" in win.field_checkboxes
    assert any(key == "command" for key, _ in win.available_fields)


def test_normalize_event_legacy_path():
    win = _build_window()
    raw = json.dumps({"event_type": "sudo", "user": "alice", "message": "ran sudo"})
    result = win._normalize_event("t0", "log:auth", raw, "rm")
    assert result["event_type"] == "sudo"
    assert result["user"] == "alice"
    assert result["source"] == "log:auth"
    assert result["timestamp"] == "t0"
    assert result["raw_message"] == "rm"


def test_normalize_event_unknown_plain_text():
    win = _build_window()
    result = win._normalize_event("t0", "log:kern", "kernel oops line", "kernel oops line")
    assert result["message"] == "kernel oops line"
    assert result["raw_message"] == "kernel oops line"


def test_connector_heartbeat_interval_and_gating():
    conn = Connector(server_ip="127.0.0.1", server_port=9090)
    assert conn.heartbeat_interval == 60.0
    assert conn._last_heartbeat == 0.0

    sent = []
    conn.socket = object()

    class StubSender:
        def send_heartbeat(self):
            sent.append(1)
            return True

    conn.log_sender = StubSender()

    conn._last_heartbeat = time.time()
    conn._maybe_send_heartbeat()
    assert len(sent) == 0, "heartbeat must not send before interval elapses"

    conn._last_heartbeat = 0.0
    conn._maybe_send_heartbeat()
    assert len(sent) == 1
    assert conn._last_heartbeat != 0.0, "last_heartbeat must update on success"

    class FailingSender:
        def send_heartbeat(self):
            return False

    conn.log_sender = FailingSender()
    conn._last_heartbeat = 0.0
    conn._maybe_send_heartbeat()
    assert conn._last_heartbeat == 0.0, "last_heartbeat must not update on failed send"


def test_eventdb_roundtrip(tmp_path):
    db = EventDB(tmp_path / "test.db")
    row_id = db.insert_event("t0", "log:auth", '{"a": 1}')
    rows = db.fetch_all()
    assert len(rows) == 1
    assert rows[0][0] == row_id
    assert rows[0][1] == "t0"
    assert rows[0][2] == "log:auth"
    db.close()


# ---------------------------------------------------------------------------
# Test-message removal
# ---------------------------------------------------------------------------


def test_connector_has_no_automatic_test_message_generation():
    conn = Connector(server_ip="127.0.0.1", server_port=9090)
    assert not hasattr(conn, "_send_test_message")
    assert not hasattr(conn, "_last_test_message")


def test_agent_sends_no_automatic_test_events():
    event_queue = queue.Queue()
    port = _free_port()
    srv = ServerThread("127.0.0.1", port, event_queue)
    srv.start()
    conn = Connector(server_ip="127.0.0.1", server_port=port)
    t = threading.Thread(target=conn.run, daemon=True)
    t.start()
    time.sleep(5)
    conn.stop()
    t.join(timeout=5)
    srv.stop()
    srv.join(timeout=3)

    events = []
    while not event_queue.empty():
        events.append(event_queue.get_nowait())
    assert any(item[1] == "InitialData" for item in events), "agent should connect and send initial data"
    for item in events:
        assert item[4].get("event_type") != "test", "no fake test events allowed"
        assert "Test Message" not in item[2]


# ---------------------------------------------------------------------------
# Event details / raw JSON
# ---------------------------------------------------------------------------


def test_event_details_dialog_shows_all_fields():
    _build_window()
    event = {
        "timestamp": "t0",
        "event_type": "exec",
        "source": "log:auth",
        "process": "bash",
        "pid": "12",
        "user": "root",
        "command": "ls -la /var/log",
        "status": "success",
        "raw_message": json.dumps({"a": 1}),
    }
    dlg = EventDetailsDialog(event)
    texts = {lbl.text() for lbl in dlg.findChildren(QLabel)}
    for expected in ("Timestamp", "Event Type", "Source", "Process", "Pid", "User", "Command", "Status"):
        assert expected in texts, f"missing field label {expected}"
    assert "Raw Message" not in texts, "raw_message is shown via View Raw JSON instead"
    dlg.close()


def test_event_details_raw_json_pretty():
    dlg = EventDetailsDialog.__new__(EventDetailsDialog)
    dlg.raw_json = json.dumps({"timestamp": "t0", "pid": 1234, "command": "apt install"})
    pretty = dlg._pretty_raw_json()
    assert json.loads(pretty) == {"timestamp": "t0", "pid": 1234, "command": "apt install"}
    assert "\n" in pretty, "raw JSON must be pretty-printed with indentation"


def test_on_table_clicked_maps_to_correct_event(monkeypatch):
    win = _build_window()
    win.events = [
        {"timestamp": "t0", "message": "first"},
        {"timestamp": "t1", "message": "second"},
    ]
    win.search_query = ""
    captured = []

    class FakeDialog:
        def __init__(self, event, parent):
            captured.append(event)

        def exec_(self):
            return None

    monkeypatch.setattr("src.main.EventDetailsDialog", FakeDialog)

    class FakeIndex:
        def __init__(self, row):
            self._row = row

        def row(self):
            return self._row

    win._on_table_clicked(FakeIndex(1))
    assert len(captured) == 1
    assert captured[0]["message"] == "second"

    win._on_table_clicked(FakeIndex(0))
    assert len(captured) == 2
    assert captured[1]["message"] == "first"
