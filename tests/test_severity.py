"""Tests for the severity classification engine, its YAML configuration, and
the severity-aware log viewer (indicators, colors, labels, filtering, sorting,
and large-volume behavior).

Run from the project root:  python3 -m pytest tests/test_severity.py -v
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

from src.severity import (  # noqa: E402
    SEVERITY_LEVELS,
    SeverityConfigError,
    SeverityEngine,
    SeverityCondition,
    default_config_path,
    load_severity_engine,
)

from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtGui import QStandardItemModel  # noqa: E402
from PyQt5.QtWidgets import (  # noqa: E402
    QApplication,
    QHBoxLayout,
    QLabel,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from src.main import (  # noqa: E402
    SEV_COLUMN_KEY,
    SEVERITY_FILTER_LEVELS,
    EventDetailsDialog,
    MainWindow,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_APP = None


def _make_window() -> MainWindow:
    global _APP
    if _APP is None:
        _APP = QApplication([])

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

    win.events = []
    win.search_query = ""
    win.severity_filter = None
    win.severity_engine = load_severity_engine()
    win.severity_filter_buttons = {}
    win._sort_column = None
    win._sort_order = Qt.DescendingOrder
    win._table_events = []
    win.is_query_mode = False

    win.table_model = QStandardItemModel(0, 0)
    win.table_view = QTableView()
    win.table_view.setModel(win.table_model)
    win._test_parent = parent
    return win


def _classified_event(level: str, **fields) -> dict:
    engine = load_severity_engine()
    event = dict(fields)
    engine.classify_event(event)  # no mutation
    event["_severity"] = level
    pres = engine.presentation(level)
    event["_severity_presentation"] = dict(pres)
    event["_severity_reason"] = "test rule"
    return event


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class TestClassification:
    def setup_method(self):
        self.engine = load_severity_engine()

    def test_normal_event_classified_good(self):
        assert self.engine.classify(
            {"event_type": "authentication", "status": "success"}
        ) == "good"

    def test_informational_event_classified_info(self):
        assert self.engine.classify({"event_type": "system"}) == "info"
        assert self.engine.classify({"event_type": "syslog"}) == "info"

    def test_suspicious_event_classified_warning(self):
        assert self.engine.classify(
            {"event_type": "authentication", "status": "failure"}
        ) == "warning"
        assert self.engine.classify({"event_type": "process", "suspicious": True}) == "warning"

    def test_malicious_event_classified_bad(self):
        assert self.engine.classify({"event_type": "malware"}) == "bad"
        assert self.engine.classify({"severity": 4}) == "bad"

    def test_critical_detection_classified_critical(self):
        assert self.engine.classify(
            {"event_type": "detection", "severity": "critical"}
        ) == "critical"
        assert self.engine.classify({"event_type": "ransomware", "confirmed": True}) == "critical"

    def test_no_matching_rule_uses_default_info(self):
        assert self.engine.classify({"event_type": "unknown_thing"}) == "info"
        assert self.engine.classify({}) == "info"

    def test_precedence_highest_severity_wins(self):
        # Matches good (auth success), warning (suspicious), bad (malware).
        event = {
            "event_type": "malware",
            "status": "success",
            "suspicious": True,
            "message": "malicious payload",
        }
        assert self.engine.classify(event) == "bad"
        # critical beats bad
        event = {"event_type": "malware", "confirmed": True}
        assert self.engine.classify(event) == "bad"
        # critical detection beats bad
        event = {"event_type": "detection", "severity": "critical"}
        assert self.engine.classify(event) == "critical"

    def test_classifier_does_not_mutate_event(self):
        original = {"event_type": "malware", "message": "x"}
        before = dict(original)
        self.engine.classify_event(original)
        assert original == before

    def test_classification_returns_presentation_metadata(self):
        result = self.engine.classify_event(
            {"event_type": "ransomware", "confirmed": True}
        )
        assert result.level == "critical"
        assert result.color == "#DC2626"
        assert result.symbol
        assert result.label == "CRITICAL"
        assert "ransomware" in result.reason

    def test_unknown_event_fields_are_ignored(self):
        assert self.engine.classify(
            {"event_type": "system", "unexpected_field": 123, "other": "x"}
        ) == "info"

    def test_classify_event_non_dict_is_safe(self):
        assert self.engine.classify_event(None).level == "info"
        assert self.engine.classify_event("string").level == "info"

    def test_severity_level_order_is_documented(self):
        assert SEVERITY_LEVELS == ("critical", "bad", "warning", "info", "good")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfig:
    def test_config_file_exists_and_is_valid_yaml(self):
        path = default_config_path()
        assert path.exists(), "config/log_severity.yaml must exist"
        engine = SeverityEngine(path)
        assert engine.errors == []

    def test_valid_yaml_loads_all_levels(self, tmp_path):
        path = tmp_path / "sev.yaml"
        path.write_text(
            """
severity:
  good:
    label: GOOD
    symbol: G
    color: "#22C55E"
    conditions:
      - event_type: authentication
        status: success
  info:
    label: INFO
    symbol: I
    color: "#3B82F6"
    conditions:
      - event_type: system
  warning:
    label: WARNING
    symbol: W
    color: "#F59E0B"
    conditions:
      - event_type: authentication
        status: failure
  bad:
    label: BAD
    symbol: B
    color: "#EF4444"
    conditions:
      - event_type: malware
  critical:
    label: CRITICAL
    symbol: C
    color: "#DC2626"
    conditions:
      - event_type: detection
        severity: critical
"""
        )
        engine = SeverityEngine(path)
        assert engine.errors == []
        assert set(engine.levels) == set(SEVERITY_LEVELS)
        assert engine.classify({"event_type": "malware"}) == "bad"

    def test_malformed_yaml_uses_fallback(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("severity: [unclosed")
        engine = SeverityEngine(path)
        assert engine.errors, "malformed YAML must record an error"
        assert len(engine.levels) == 5
        # Fallback still classifies correctly.
        assert engine.classify({"event_type": "malware"}) == "bad"

    def test_missing_config_uses_fallback(self, tmp_path):
        engine = SeverityEngine(tmp_path / "missing.yaml")
        assert engine.errors
        assert len(engine.levels) == 5
        assert engine.classify({"event_type": "system"}) == "info"

    def test_root_not_a_mapping_uses_fallback(self, tmp_path):
        path = tmp_path / "root.yaml"
        path.write_text("just: a: list\n- one\n- two\n")
        engine = SeverityEngine(path)
        assert engine.errors
        assert len(engine.levels) == 5

    def test_unknown_severity_level_is_ignored(self, tmp_path):
        path = tmp_path / "unknown.yaml"
        path.write_text(
            """
severity:
  foo:
    label: FOO
    color: "#123456"
    conditions:
      - event_type: anything
"""
        )
        engine = SeverityEngine(path)
        assert any("unknown severity level" in e for e in engine.errors)
        # All canonical levels still present (fallback used for the rest).
        assert set(engine.levels) == set(SEVERITY_LEVELS)

    def test_invalid_color_uses_fallback_color(self, tmp_path):
        path = tmp_path / "color.yaml"
        path.write_text(
            """
severity:
  good:
    label: GOOD
    symbol: G
    color: "not-a-color"
    conditions:
      - event_type: authentication
        status: success
"""
        )
        engine = SeverityEngine(path)
        assert any("invalid color" in e for e in engine.errors)
        assert engine.levels["good"].color == "#22C55E"

    def test_unsupported_operator_condition_skipped(self, tmp_path):
        path = tmp_path / "op.yaml"
        path.write_text(
            """
severity:
  good:
    label: GOOD
    symbol: G
    color: "#22C55E"
    conditions:
      - event_type:
          op: no_such_op
          value: x
  info:
    label: INFO
    symbol: I
    color: "#3B82F6"
    conditions:
      - event_type: system
"""
        )
        engine = SeverityEngine(path)
        assert any("Unsupported operator" in e for e in engine.errors)
        # Good falls back to the built-in rules, info still works.
        assert engine.classify({"event_type": "system"}) == "info"

    def test_missing_value_condition_skipped(self, tmp_path):
        path = tmp_path / "novalue.yaml"
        path.write_text(
            """
severity:
  good:
    label: GOOD
    symbol: G
    color: "#22C55E"
    conditions:
      - event_type:
          op: contains
  info:
    label: INFO
    symbol: I
    color: "#3B82F6"
    conditions:
      - event_type: system
"""
        )
        engine = SeverityEngine(path)
        assert any("missing a value" in e for e in engine.errors)

    def test_condition_spec_not_a_mapping_skipped(self, tmp_path):
        path = tmp_path / "badcond.yaml"
        path.write_text(
            """
severity:
  good:
    label: GOOD
    symbol: G
    color: "#22C55E"
    conditions:
      - "just a string"
  info:
    label: INFO
    symbol: I
    color: "#3B82F6"
    conditions:
      - event_type: system
"""
        )
        engine = SeverityEngine(path)
        assert any("Invalid condition spec" in e for e in engine.errors)

    def test_overlapping_rules_precedence(self):
        engine = SeverityEngine()
        # severity 5 matches warning (>=3), bad (>=4) and critical (>=5);
        # the highest-severity match must win.
        event = {"event_type": "detection", "severity": 5}
        assert engine.classify(event) == "critical"
        # malware + severity 4 matches warning (>=3) and bad (>=4); bad wins.
        event = {"event_type": "malware", "severity": 4}
        assert engine.classify(event) == "bad"
        # plain severity 3 matches warning only.
        assert engine.classify({"event_type": "system", "severity": 3}) == "warning"

    def test_condition_with_multiple_terms_requires_all(self):
        cond = SeverityCondition({"event_type": "authentication", "status": "success"})
        assert cond.matches({"event_type": "authentication", "status": "success"})
        assert not cond.matches({"event_type": "authentication", "status": "failure"})
        assert not cond.matches({"event_type": "authentication"})

    def test_presentation_returns_metadata_for_any_level(self):
        engine = SeverityEngine()
        pres = engine.presentation("bad")
        assert pres["color"] == "#EF4444"
        assert pres["label"] == "BAD"
        assert pres["symbol"]

    def test_rank_higher_is_more_severe(self):
        engine = SeverityEngine()
        assert engine.rank("critical") > engine.rank("bad") > engine.rank("warning") \
            > engine.rank("info") > engine.rank("good")


# ---------------------------------------------------------------------------
# UI: indicators, colors, labels
# ---------------------------------------------------------------------------


class TestUI:
    def _populate(self, win, events):
        win.events = events
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win._refresh_table()
        return win

    def test_severity_indicator_column_shows_symbols(self):
        win = _make_window()
        events = [
            _classified_event("good", event_type="authentication", status="success"),
            _classified_event("warning", event_type="authentication", status="failure"),
            _classified_event("critical", event_type="detection", severity="critical"),
        ]
        win.events = events
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win._refresh_table()
        assert win.table_model.columnCount() == 5  # sev + 4 selected fields
        assert win.table_model.item(0, 0).text() == "🟢"
        assert win.table_model.item(1, 0).text() == "🟡"
        assert win.table_model.item(2, 0).text() == "⛔"
        assert win._table_events == events

    def test_severity_column_header_label(self):
        win = _make_window()
        win.events = [_classified_event("info", event_type="system")]
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win._refresh_table()
        assert win.table_model.horizontalHeaderItem(0).text() == "Sev"

    def test_severity_colors_applied_to_items(self):
        win = _make_window()
        events = [
            _classified_event("bad", event_type="malware"),
            _classified_event("good", event_type="authentication", status="success"),
        ]
        win.events = events
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win._refresh_table()
        bad_item = win.table_model.item(0, 0)
        assert bad_item.foreground().color().name().upper() == "#EF4444"
        assert bad_item.background().color().alpha() > 0  # subtle tint
        good_item = win.table_model.item(1, 0)
        assert good_item.foreground().color().name().upper() == "#22C55E"

    def test_long_values_are_tooltipped(self):
        win = _make_window()
        long_message = "x" * 500
        event = _classified_event("info", event_type="syslog", message=long_message)
        win.events = [event]
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win._refresh_table()
        item = win.table_model.item(0, 4)  # message column
        assert item.toolTip() == long_message

    def test_private_severity_keys_not_displayed_as_columns(self):
        win = _make_window()
        event = _classified_event("info", event_type="system")
        win.events = [event]
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win._refresh_table()
        headers = [
            win.table_model.horizontalHeaderItem(c).text()
            for c in range(win.table_model.columnCount())
        ]
        assert "_severity" not in headers
        assert "Sev" in headers

    def test_event_details_dialog_shows_severity_and_reason(self):
        event = _classified_event("warning", event_type="authentication", status="failure")
        event["_severity_reason"] = "event_type eq authentication, status eq failure"
        dlg = EventDetailsDialog(event)
        texts = {lbl.text() for lbl in dlg.findChildren(QLabel)}
        assert any("WARNING" in t for t in texts)
        assert any("Matched:" in t for t in texts)
        dlg.close()

    def test_event_details_dialog_hides_private_keys(self):
        event = _classified_event("info", event_type="system")
        event["_severity_reason"] = "r"
        dlg = EventDetailsDialog(event)
        labels = {lbl.text() for lbl in dlg.findChildren(QLabel)}
        assert "_Severity" not in labels
        assert "_Severity Reason" not in labels
        dlg.close()


# ---------------------------------------------------------------------------
# UI: filtering
# ---------------------------------------------------------------------------


class TestFiltering:
    def _window_with(self, events):
        win = _make_window()
        win.events = events
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win._refresh_table()
        return win

    def test_severity_filter_filters_table(self):
        win = self._window_with(
            [
                _classified_event("good", event_type="authentication", status="success"),
                _classified_event("warning", event_type="authentication", status="failure"),
                _classified_event("bad", event_type="malware"),
                _classified_event("info", event_type="syslog"),
            ]
        )
        win.severity_filter = "warning"
        win._refresh_table()
        assert win.table_model.rowCount() == 1
        assert win.table_model.item(0, 0).text() == "🟡"

    def test_all_filter_shows_everything(self):
        win = self._window_with(
            [_classified_event("good", event_type="authentication", status="success"),
             _classified_event("bad", event_type="malware")]
        )
        win.severity_filter = None
        win._refresh_table()
        assert win.table_model.rowCount() == 2

    def test_severity_and_text_search_combine(self):
        win = self._window_with(
            [
                _classified_event("bad", event_type="malware", message="ransomware detected"),
                _classified_event("bad", event_type="malware", message="something else"),
                _classified_event("warning", event_type="authentication", status="failure"),
            ]
        )
        win.severity_filter = "bad"
        win.search_query = "ransomware"
        win._refresh_table()
        assert win.table_model.rowCount() == 1

    def test_filter_buttons_are_created_for_all_levels(self):
        win = _make_window()
        layout = QHBoxLayout()
        win._add_severity_filter_button(layout, "All", None, checked=True)
        for level in SEVERITY_FILTER_LEVELS:
            pres = win.severity_engine.presentation(level)
            win._add_severity_filter_button(layout, pres["label"], level, color=pres["color"])
        assert set(win.severity_filter_buttons) == {None, "good", "info", "warning", "bad", "critical"}
        assert win.severity_filter_buttons[None].isChecked()


# ---------------------------------------------------------------------------
# UI: sorting
# ---------------------------------------------------------------------------


class TestSorting:
    def test_severity_sort_uses_precedence_not_alphabet(self):
        win = _make_window()
        events = [
            _classified_event("good", timestamp="t1"),
            _classified_event("info", timestamp="t2"),
            _classified_event("warning", timestamp="t3"),
            _classified_event("bad", timestamp="t4"),
            _classified_event("critical", timestamp="t5"),
        ]
        win.events = events
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = 0
        win._sort_order = 1  # descending
        win._refresh_table()
        order = [win.table_model.item(r, 0).text() for r in range(win.table_model.rowCount())]
        assert order == ["⛔", "🔴", "🟡", "🔵", "🟢"]

    def test_timestamp_sort(self):
        win = _make_window()
        events = [
            _classified_event("info", timestamp="2026-08-01T00:00:00Z"),
            _classified_event("info", timestamp="2026-08-03T00:00:00Z"),
            _classified_event("info", timestamp="2026-08-02T00:00:00Z"),
        ]
        win.events = events
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = win._column_index("timestamp")
        win._sort_order = 0  # ascending
        win._refresh_table()
        stamps = [win.table_model.item(r, win._sort_column).text() for r in range(win.table_model.rowCount())]
        assert stamps == sorted(stamps)

    def test_pid_sort_is_numeric(self):
        win = _make_window()
        win.selected_fields.add("pid")
        events = [
            _classified_event("info", pid="100"),
            _classified_event("info", pid="9"),
            _classified_event("info", pid="50"),
        ]
        win.events = events
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = win._column_index("pid")
        win._sort_order = 0
        win._refresh_table()
        pids = [win.table_model.item(r, win._sort_column).text() for r in range(win.table_model.rowCount())]
        assert pids == ["9", "50", "100"]

    def test_header_click_toggles_order(self):
        win = _make_window()
        win.events = [
            _classified_event("info", timestamp="t2"),
            _classified_event("info", timestamp="t1"),
        ]
        win.search_query = ""
        win.severity_filter = None
        col = win._column_index("timestamp")
        win._sort_column = None
        win._on_header_section_clicked(col)
        assert win._sort_column == col
        first_order = win._sort_order
        win._on_header_section_clicked(col)
        assert win._sort_order != first_order

    def test_sort_events_returns_new_list(self):
        win = _make_window()
        events = [_classified_event("info", timestamp="t2"), _classified_event("info", timestamp="t1")]
        win.events = events
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = win._column_index("timestamp")
        win._sort_order = 0
        result = win._sort_events(list(events))
        assert result != events
        assert len(result) == len(events)


# ---------------------------------------------------------------------------
# UI: large volumes / performance
# ---------------------------------------------------------------------------


class TestVolume:
    def test_incremental_append_grows_table(self):
        win = _make_window()
        win.events = []
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win._refresh_table()
        assert win.table_model.rowCount() == 0

        batch = [_classified_event("info", event_type="syslog", message=f"m{i}") for i in range(100)]
        win.events = list(batch)
        win._append_rows(batch)
        assert win.table_model.rowCount() == 100
        assert win._table_events == batch

    def test_poll_queue_appends_incrementally_when_unfiltered(self):
        import queue as queue_mod

        win = _make_window()
        win.events = []
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win.is_query_mode = False
        win.event_counter = 0
        win.event_count_lbl = QLabel()
        win.side_event_count_lbl = QLabel()

        q = queue_mod.Queue()
        for i in range(50):
            q.put(
                (
                    f"t{i}", "log:sys",
                    '{"event_type": "syslog"}',
                    '{"event_type": "syslog"}',
                    {"event_type": "syslog"},
                )
            )
        win.event_queue = q
        win._poll_queue()
        assert len(win.events) == 50
        assert win.table_model.rowCount() == 50
        assert win._table_events == win.events
        assert win.event_counter == 50

    def test_bounded_buffer_trims_old_events(self, monkeypatch):
        import src.main as main_mod

        monkeypatch.setattr(main_mod, "MAX_EVENTS", 20)
        win = _make_window()
        win.events = []
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = None
        win.is_query_mode = False
        win.event_counter = 0
        win.event_count_lbl = QLabel()
        win.side_event_count_lbl = QLabel()

        import queue as queue_mod

        q = queue_mod.Queue()
        for i in range(30):
            q.put(
                (
                    f"t{i}", "log:sys",
                    '{"event_type": "syslog"}',
                    '{"event_type": "syslog"}',
                    {"event_type": "syslog"},
                )
            )
        win.event_queue = q
        win._poll_queue()
        assert len(win.events) == 20
        assert win.event_counter == 30  # counter counts everything, buffer is bounded
        assert win.table_model.rowCount() == 20

    def test_full_refresh_with_thousands_events(self):
        win = _make_window()
        win.events = [
            _classified_event("info", event_type="syslog", message=f"m{i}")
            for i in range(2000)
        ]
        win.events[0]["_severity"] = "critical"
        win.events[0]["_severity_presentation"] = {
            "color": "#DC2626", "label": "CRITICAL", "symbol": "⛔"
        }
        win.search_query = ""
        win.severity_filter = None
        win._sort_column = 0
        win._sort_order = 1
        win._refresh_table()
        assert win.table_model.rowCount() == 2000
        assert win.table_model.item(0, 0).text() == "⛔"

    def test_classification_applied_through_normalize(self):
        win = _make_window()
        event = win._normalize_event(
            "t0", "log:auth",
            '{"event_type": "authentication", "status": "success"}',
            '{"event_type": "authentication", "status": "success"}',
            {"event_type": "authentication", "status": "success"},
        )
        win._classify_event(event)
        assert event["_severity"] == "good"
        assert event["_severity_presentation"]["symbol"] == "🟢"
