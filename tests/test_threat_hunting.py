"""Tests for threat hunting core modules."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from src.database import CyberionDB
from src.hunting.correlation_engine import CorrelationEngine
from src.hunting.hypothesis_manager import HypothesisManager
from src.hunting.indicator_extractor import IndicatorExtractor
from src.hunting.models import ThreatHypothesis


def test_indicator_extractor_and_public_ip_detection():
    extractor = IndicatorExtractor()
    event = {
        "ip_address": "8.8.8.8",
        "pid": 444,
        "ppid": 111,
        "process_name": "powershell.exe",
        "user": "alice",
        "hostname": "ws-01",
        "command": "powershell -enc AAA",
        "filepath": "C:/Temp/script.ps1",
        "sha256": "abc123",
    }

    indicators = extractor.extract_from_event(event)
    assert "source_ip" in indicators
    assert "8.8.8.8" in indicators["source_ip"]
    assert indicators["pid"] == ["444"]

    public_ips = extractor.public_ips(indicators)
    assert public_ips == ["8.8.8.8"]


def test_correlation_engine_links_parent_child_and_user(tmp_path):
    db = CyberionDB(db_path=tmp_path / "hunt.db")

    seed = {
        "timestamp": "2026-08-16T12:00:00+00:00",
        "source": "agent-1",
        "event_type": "process_start",
        "pid": 2000,
        "ppid": 1500,
        "process_name": "powershell.exe",
        "user": "alice",
        "hostname": "host-1",
        "command": "powershell -enc test",
        "raw_event": "{}",
    }
    db.insert_event(seed)

    child = {
        "timestamp": "2026-08-16T12:01:00+00:00",
        "source": "agent-1",
        "event_type": "process_start",
        "pid": 2100,
        "ppid": 2000,
        "process_name": "cmd.exe",
        "user": "alice",
        "hostname": "host-1",
        "raw_event": "{}",
    }
    db.insert_event(child)

    unrelated = {
        "timestamp": "2026-08-16T12:02:00+00:00",
        "source": "agent-2",
        "event_type": "network",
        "pid": 999,
        "ppid": 998,
        "process_name": "chrome.exe",
        "user": "bob",
        "hostname": "host-2",
        "raw_event": "{}",
    }
    db.insert_event(unrelated)

    all_events = db.get_events(limit=10)
    seed_row = next(item for item in all_events if item.get("pid") == 2000)

    correlated = CorrelationEngine(db).correlate(seed_row, window_minutes=5, limit=50)

    assert correlated
    assert any(item.get("pid") == 2100 for item in correlated)
    assert all(item.get("pid") != 999 for item in correlated)


def test_hypothesis_manager_round_trip(tmp_path):
    manager = HypothesisManager(
        hypotheses_path=tmp_path / "hypotheses.json",
        investigations_path=tmp_path / "investigations.json",
    )

    hypothesis = ThreatHypothesis.new_default()
    hypothesis.name = "Test Hunt"
    hypothesis.query_kql = "events | take 10"

    manager.upsert_hypothesis(hypothesis)

    loaded = manager.list_hypotheses()
    assert len(loaded) == 1
    assert loaded[0].name == "Test Hunt"
