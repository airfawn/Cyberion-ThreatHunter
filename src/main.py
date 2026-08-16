# python src/main.py
"""Cyberion GUI with event monitoring, sidebar controls and TCP status display."""

import ipaddress
import json
import os
import queue
import socket
import sys
import threading
import time
from pathlib import Path

from PyQt5.QtCore import QEasingCurve, QObject, QPropertyAnimation, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QFont, QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTabBar,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from .database import SCHEMA_COLUMNS, CyberionDB, EventPersistenceWorker  # type: ignore
    from .event_repository import EventRepository  # type: ignore
    from .server import ServerThread  # type: ignore
    from .query import CyberionQueryEngine, QueryEngineError  # type: ignore
    from .hunting import ThreatHuntingController  # type: ignore
    from .severity import load_severity_engine  # type: ignore
    from .ui import SearchPage, ThreatHuntingPage  # type: ignore
    from .ui.alerts_page import AlertsPage  # type: ignore
    from .ui.detections_page import DetectionsPage  # type: ignore
    from .ui.theme import COLORS, theme_font, apply_global_theme  # type: ignore
except ImportError:
    from src.database import SCHEMA_COLUMNS, CyberionDB, EventPersistenceWorker  # type: ignore
    from src.event_repository import EventRepository  # type: ignore
    from src.server import ServerThread  # type: ignore
    from src.query import CyberionQueryEngine, QueryEngineError  # type: ignore
    from src.hunting import ThreatHuntingController  # type: ignore
    from src.severity import load_severity_engine  # type: ignore
    from src.ui import SearchPage, ThreatHuntingPage  # type: ignore
    from src.ui.alerts_page import AlertsPage  # type: ignore
    from src.ui.detections_page import DetectionsPage  # type: ignore
    from src.ui.theme import COLORS, theme_font, apply_global_theme  # type: ignore
except Exception as e:  # pragma: no cover - startup guard
    print("Failed to import server/database modules:", e)
    sys.exit(1)


MAX_EVENTS = 5000
SETTINGS_FILE = "cyberion_settings.json"

# Severity indicator column (always the leftmost table column).
SEV_COLUMN_KEY = "sev"
# Severity filter order shown in the UI (All + levels).
SEVERITY_FILTER_LEVELS = ("good", "info", "warning", "bad", "critical")
# Numeric rank used for severity sorting (higher = more severe).
SEV_RANK = {level: rank for rank, level in enumerate(SEVERITY_FILTER_LEVELS)}
# Display columns styled with a monospace font for readability.
MONO_FIELDS = {"timestamp", "pid", "ip_address", "message", "command", "filepath", "raw_message"}


class AgentStatusSignal(QObject):
    status_changed = pyqtSignal(str)


class EventDetailsDialog(QDialog):
    """Shows every field of a single event plus its original raw JSON.

    The severity classification and the rule that produced it are shown at
    the top when the event was classified (i.e. it carries ``_severity`` /
    ``_severity_reason`` metadata). The underlying event is never modified.
    """

    def __init__(self, event: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Event Details")
        self.setMinimumSize(560, 420)
        self.resize(680, 500)
        # raw_message holds the exact JSON received from the agent
        # (the server sets it to json.dumps() of the incoming message/log entry).
        self.raw_json = str(event.get("raw_message", ""))

        layout = QVBoxLayout(self)

        severity_level = event.get("_severity")
        if severity_level:
            sev = event.get("_severity_presentation", {})
            header = QFrame()
            header.setStyleSheet(
                "QFrame { background-color: #151B23; border: 1px solid #27313D;"
                " border-radius: 6px; }"
            )
            header_layout = QHBoxLayout(header)
            header_layout.setContentsMargins(12, 8, 12, 8)
            symbol_lbl = QLabel(str(sev.get("symbol", "")))
            symbol_lbl.setFont(theme_font(16))
            label_lbl = QLabel(str(sev.get("label", severity_level.upper())))
            label_lbl.setFont(theme_font(13, QFont.DemiBold))
            label_lbl.setStyleSheet(f"color: {sev.get('color', '#FFFFFF')};")
            header_layout.addWidget(symbol_lbl)
            header_layout.addWidget(label_lbl)
            header_layout.addSpacing(6)
            reason_lbl = QLabel(
                f"Matched: {event.get('_severity_reason') or 'no explicit rule'}"
            )
            reason_lbl.setWordWrap(True)
            reason_lbl.setStyleSheet("color: #94A3B8;")
            header_layout.addWidget(reason_lbl, 1)
            layout.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        grid = QGridLayout(content)
        grid.setColumnStretch(1, 1)
        row = 0
        for key, value in event.items():
            if key in {"raw_message", "_severity", "_severity_reason", "_severity_presentation"}:
                continue
            name_lbl = QLabel(key.replace("_", " ").title())
            name_lbl.setStyleSheet("color: #9aa0a6;")
            name_lbl.setWordWrap(True)
            value_lbl = QLabel("" if value is None else str(value))
            value_lbl.setWordWrap(True)
            value_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(name_lbl, row, 0, Qt.AlignTop)
            grid.addWidget(value_lbl, row, 1)
            row += 1
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)

        btn_row = QHBoxLayout()
        raw_btn = QPushButton("View Raw JSON")
        raw_btn.clicked.connect(self._show_raw_json)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(raw_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

    def _pretty_raw_json(self) -> str:
        """Return the original raw JSON pretty-printed with indentation."""
        try:
            parsed = json.loads(self.raw_json)
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            return self.raw_json

    def _show_raw_json(self):
        """Display the original raw JSON payload, pretty-printed with indentation."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Raw JSON")
        dialog.resize(700, 540)
        lay = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setFont(QFont("Menlo", 11))
        text.setPlainText(self._pretty_raw_json())
        lay.addWidget(text, 1)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_row.addWidget(close_btn)
        lay.addLayout(btn_row)
        dialog.exec_()


def _get_env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(f"Invalid integer for {name}: {raw!r}. Using {default}.")
        return default
    if value <= 0 or value > 65535:
        print(f"Out-of-range port for {name}: {value}. Using {default}.")
        return default
    return value


def get_runtime_network_config() -> tuple[str, int, str, int]:
    bind_host = os.getenv("THREATHUNTER_BIND_HOST", "0.0.0.0")
    port = _get_env_int("THREATHUNTER_PORT", 9090)
    aux_host = os.getenv("THREATHUNTER_AUX_HOST", "127.0.0.1")
    aux_port = _get_env_int("THREATHUNTER_AUX_PORT", 12345)
    return bind_host, port, aux_host, aux_port


class MainWindow(QMainWindow):
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9090,
        aux_host: str = "127.0.0.1",
        aux_port: int = 12345,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        self.setWindowTitle("Cyberion ThreatShield")
        self.setGeometry(100, 100, 1320, 820)
        self.setObjectName("mainWindow")

        self.server_host = host
        self.server_port = port
        self.aux_host = aux_host
        self.aux_port = aux_port
        self.current_status = "Waiting for connection"

        self.available_fields = [
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
        self.default_selected_fields = {"timestamp", "source", "event_type", "message"}
        self.selected_fields = set(self.default_selected_fields)
        self.field_checkboxes: dict[str, QCheckBox] = {}
        self.fields_layout: QVBoxLayout | None = None
        self.known_fields: set[str] = {key for key, _ in self.available_fields}

        self.events: list[dict[str, str]] = []
        self.event_counter = 0
        self.search_query = ""

        self.event_queue: "queue.Queue[tuple[str, str, str, str, dict[str, str]]]" = queue.Queue()
        self.persist_queue: "queue.Queue[tuple[str, str, str, str, dict[str, str]]]" = queue.Queue()
        self.db = CyberionDB()
        self.event_repo = EventRepository(db=self.db)
        self.query_engine = CyberionQueryEngine(self.db)
        self.hunting_controller = ThreatHuntingController(self.db, self.query_engine)
        self.persistence_worker = EventPersistenceWorker(
            self.db, self.persist_queue, self.event_queue
        )
        self._page_fade_animation = None
        
        # Query state
        self.current_query = ""
        self.query_results = []
        self.is_query_mode = False  # True when showing query results, False when live

        # Severity classification + filtering state
        self.severity_engine = load_severity_engine()
        self.severity_filter: str | None = None  # None = All
        self.severity_filter_buttons: dict[str, QPushButton] = {}

        # Sorting state (None = arrival order). severity sorting uses rank.
        self._sort_column: int | None = None
        self._sort_order = Qt.DescendingOrder

        # Events currently shown in the table (row -> event mapping).
        self._table_events: list[dict] = []

        self.socket_message_queue: "queue.Queue[str]" = queue.Queue()
        self.socket_server_stop = threading.Event()
        self.socket_accept_thread = None
        self.server_socket = None

        self._build_ui()
        self._apply_styles()

        self.status_signal = AgentStatusSignal()
        self.status_signal.status_changed.connect(self._on_status_change)
        self.server_thread = ServerThread(
            self.server_host,
            self.server_port,
            self.persist_queue,
            status_callback=self.status_signal.status_changed.emit,
        )
        self.server_thread.start()
        self.persistence_worker.start()

        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(200)
        self.poll_timer.timeout.connect(self._poll_queue)
        self.poll_timer.start()

        self.socket_poll_timer = QTimer(self)
        self.socket_poll_timer.setInterval(200)
        self.socket_poll_timer.timeout.connect(self._poll_socket_messages)
        self.socket_poll_timer.start()

        self.start_server()
        self._load_events_from_db()
        self._refresh_table()

    def _build_ui(self):
        main_container = QWidget()
        self.setCentralWidget(main_container)
        root_layout = QHBoxLayout(main_container)
        root_layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        root_layout.addWidget(splitter)

        sidebar = self._build_sidebar()
        content = self._build_content_area()

        splitter.addWidget(sidebar)
        splitter.addWidget(content)
        splitter.setSizes([340, 980])

    def _build_sidebar(self) -> QWidget:
        self.side_panel = QFrame()
        self.side_panel.setObjectName("sidebar")
        self.side_panel.setFrameStyle(QFrame.NoFrame)
        side_layout = QVBoxLayout(self.side_panel)
        side_layout.setContentsMargins(18, 18, 18, 18)
        side_layout.setSpacing(12)

        title_row = QHBoxLayout()
        title = QLabel("Cyberion")
        title.setFont(theme_font(20, QFont.DemiBold))
        title_row.addWidget(title)
        title_row.addStretch(1)
        side_layout.addLayout(title_row)

        subtitle = QLabel("ThreatShield Console")
        subtitle.setFont(theme_font(11))
        subtitle.setProperty("secondary", True)
        side_layout.addWidget(subtitle)

        side_layout.addSpacing(8)
        server_lbl = QLabel("Server Status")
        server_lbl.setFont(theme_font(12, QFont.DemiBold))
        server_lbl.setProperty("secondary", True)
        side_layout.addWidget(server_lbl)

        status_card = QFrame()
        status_card.setObjectName("statusCard")
        status_card_layout = QVBoxLayout(status_card)
        status_card_layout.setContentsMargins(12, 10, 12, 10)
        status_card_layout.setSpacing(4)
        self.side_agent_status_lbl = QLabel("● Waiting for connection")
        self.side_agent_status_lbl.setFont(theme_font(12))
        self.side_event_count_lbl = QLabel("Events received: 0")
        self.side_event_count_lbl.setFont(theme_font(11))
        self.side_event_count_lbl.setProperty("secondary", True)
        status_card_layout.addWidget(self.side_agent_status_lbl)
        status_card_layout.addWidget(self.side_event_count_lbl)
        side_layout.addWidget(status_card)

        side_layout.addSpacing(8)
        fields_lbl = QLabel("Visible Data Fields")
        fields_lbl.setFont(theme_font(12, QFont.DemiBold))
        fields_lbl.setProperty("secondary", True)
        side_layout.addWidget(fields_lbl)

        fields_scroll = QScrollArea()
        fields_scroll.setWidgetResizable(True)
        fields_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        fields_scroll.setMinimumHeight(220)
        fields_scroll.setFrameShape(QFrame.NoFrame)

        self.fields_widget = QWidget()
        self.fields_layout = QVBoxLayout(self.fields_widget)
        self.fields_layout.setContentsMargins(0, 0, 0, 0)
        self.fields_layout.setSpacing(6)

        for key, label in self.available_fields:
            checkbox = QCheckBox(label)
            checkbox.setChecked(key in self.selected_fields)
            checkbox.stateChanged.connect(self._on_field_selector_changed)
            self.fields_layout.addWidget(checkbox)
            self.field_checkboxes[key] = checkbox

        self.fields_layout.addStretch(1)
        fields_scroll.setWidget(self.fields_widget)
        side_layout.addWidget(fields_scroll)

        side_layout.addSpacing(8)
        settings_lbl = QLabel("Settings")
        settings_lbl.setFont(theme_font(12, QFont.DemiBold))
        settings_lbl.setProperty("secondary", True)
        side_layout.addWidget(settings_lbl)

        settings_card = QFrame()
        settings_card.setObjectName("settingsCard")
        settings_layout = QVBoxLayout(settings_card)
        settings_layout.setContentsMargins(12, 10, 12, 10)
        settings_layout.setSpacing(8)

        ip_label = QLabel("Server IP")
        ip_label.setProperty("secondary", True)
        self.server_ip_edit = QLineEdit(self.server_host)
        settings_layout.addWidget(ip_label)
        settings_layout.addWidget(self.server_ip_edit)

        port_label = QLabel("Server Port")
        port_label.setProperty("secondary", True)
        self.server_port_edit = QLineEdit(str(self.server_port))
        settings_layout.addWidget(port_label)
        settings_layout.addWidget(self.server_port_edit)

        self.save_settings_btn = QPushButton("Save")
        self.save_settings_btn.setObjectName("primaryButton")
        self.save_settings_btn.clicked.connect(self._save_settings)
        settings_layout.addWidget(self.save_settings_btn)

        self.settings_feedback_lbl = QLabel("")
        self.settings_feedback_lbl.setWordWrap(True)
        self.settings_feedback_lbl.setProperty("secondary", True)
        settings_layout.addWidget(self.settings_feedback_lbl)
        side_layout.addWidget(settings_card)

        return self.side_panel

    def _build_content_area(self) -> QWidget:
        main_pane = QWidget()
        main_layout = QVBoxLayout(main_pane)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        self.top_nav = QTabBar()
        self.top_nav.addTab("Search")
        self.top_nav.addTab("Event Monitoring")
        self.top_nav.addTab("Alerts")
        self.top_nav.addTab("Detections")
        self.top_nav.addTab("Threat Hunting")
        main_layout.addWidget(self.top_nav)

        self.main_stack = QStackedWidget()
        self.main_stack.addWidget(self._build_search_page())
        self.main_stack.addWidget(self._build_event_monitor_page())
        self.main_stack.addWidget(self._build_alerts_page())
        self.main_stack.addWidget(self._build_detections_page())
        self.main_stack.addWidget(self._build_threat_hunting_page())
        main_layout.addWidget(self.main_stack)

        self.top_nav.currentChanged.connect(self._on_nav_changed)
        self.top_nav.setCurrentIndex(0)
        return main_pane

    def _build_search_page(self) -> QWidget:
        """Build the Search page with visual query builder."""
        return SearchPage(query_engine=self.query_engine, parent=self)

    def _build_event_monitor_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(8)

        header_row = QHBoxLayout()
        self.agent_status_lbl = QLabel("Agent Status: Waiting for connection")
        self.agent_status_lbl.setFont(theme_font(16, QFont.DemiBold))
        header_row.addWidget(self.agent_status_lbl)
        header_row.addStretch(1)
        layout.addLayout(header_row)

        self.event_count_lbl = QLabel("Events Received: 0")
        self.event_count_lbl.setFont(theme_font(11))
        self.event_count_lbl.setProperty("secondary", True)
        layout.addWidget(self.event_count_lbl)

        # Query bar
        query_bar_layout = QHBoxLayout()
        query_label = QLabel("Query")
        query_label.setFont(theme_font(12, QFont.DemiBold))
        query_label.setProperty("secondary", True)
        query_bar_layout.addWidget(query_label)

        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText(
            'Example: events | where severity >= 3 | take 100'
        )
        self.query_input.returnPressed.connect(self._on_query_execute)
        query_bar_layout.addWidget(self.query_input)

        self.query_run_btn = QPushButton("Run Query")
        self.query_run_btn.setObjectName("primaryButton")
        self.query_run_btn.clicked.connect(self._on_query_execute)
        query_bar_layout.addWidget(self.query_run_btn)

        self.query_clear_btn = QPushButton("Clear")
        self.query_clear_btn.clicked.connect(self._on_query_clear)
        query_bar_layout.addWidget(self.query_clear_btn)

        layout.addLayout(query_bar_layout)

        # Query result / status
        self.query_status_lbl = QLabel("")
        self.query_status_lbl.setStyleSheet("color: #888888; font-size: 10px;")
        layout.addWidget(self.query_status_lbl)

        # Legacy search box (for live mode filter)
        # Severity filter row: [ All ] [ Good ] [ Info ] [ Warning ] [ Bad ] [ Critical ]
        sev_filter_row = QHBoxLayout()
        sev_filter_label = QLabel("Severity")
        sev_filter_label.setFont(theme_font(11, QFont.DemiBold))
        sev_filter_label.setProperty("secondary", True)
        sev_filter_row.addWidget(sev_filter_label)
        self._add_severity_filter_button(sev_filter_row, "All", None, checked=True)
        for level in SEVERITY_FILTER_LEVELS:
            pres = self.severity_engine.presentation(level)
            self._add_severity_filter_button(
                sev_filter_row, pres["label"], level, color=pres["color"]
            )
        sev_filter_row.addStretch(1)
        layout.addLayout(sev_filter_row)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search events in live mode (contains)...")
        self.search_input.textChanged.connect(self._on_search_changed)
        layout.addWidget(self.search_input)

        self.table_model = QStandardItemModel(0, 0, self)
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.verticalHeader().hide()
        self.table_view.verticalHeader().setDefaultSectionSize(26)
        self.table_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.table_view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.table_view.setWordWrap(False)
        self.table_view.setTextElideMode(Qt.ElideRight)
        self.table_view.setHorizontalScrollMode(QTableView.ScrollPerPixel)
        self.table_view.setVerticalScrollMode(QTableView.ScrollPerPixel)
        self.table_view.horizontalHeader().setStretchLastSection(False)
        self.table_view.setSortingEnabled(False)
        self.table_view.horizontalHeader().setSortIndicatorShown(True)
        self.table_view.horizontalHeader().setSectionsClickable(True)
        self.table_view.horizontalHeader().sectionClicked.connect(self._on_header_section_clicked)
        self.table_view.clicked.connect(self._on_table_clicked)
        layout.addWidget(self.table_view, 1)

        self.messages_display = QListWidget()
        self.messages_display.setMinimumHeight(90)
        self.messages_display.setMaximumHeight(140)
        layout.addWidget(self.messages_display)

        return page

    def _build_alerts_page(self) -> QWidget:
        """Build the Alerts management page."""
        return AlertsPage(alert_manager=self.db.alerts, parent=self)

    def _build_detections_page(self) -> QWidget:
        """Build the Detections management page."""
        return DetectionsPage(detection_manager=self.db.detections, parent=self)

    def _build_threat_hunting_page(self) -> QWidget:
        """Build the analyst-driven threat hunting page."""
        return ThreatHuntingPage(controller=self.hunting_controller, parent=self)

    def _on_nav_changed(self, index: int) -> None:
        self.main_stack.setCurrentIndex(index)
        self._animate_page_transition()

    def _animate_page_transition(self) -> None:
        page = self.main_stack.currentWidget()
        if page is None:
            return
        effect = QGraphicsOpacityEffect(page)
        page.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(180)
        anim.setStartValue(0.55)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)

        def _cleanup():
            page.setGraphicsEffect(None)

        anim.finished.connect(_cleanup)
        self._page_fade_animation = anim
        anim.start()

    def _apply_styles(self):
        app = QApplication.instance()
        if app is not None:
            apply_global_theme(app)
        self.setStyleSheet(
            """
            QMainWindow#mainWindow {
                background-color: #0B0F14;
            }
            QFrame#statusCard, QFrame#settingsCard {
                background-color: #151B23;
                border: 1px solid #27313D;
                border-radius: 8px;
            }
            QTableView {
                margin-top: 4px;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox, QDateTimeEdit {
                min-height: 28px;
            }
            """
        )

    def _config_path(self) -> Path:
        return Path(__file__).resolve().parent.parent / SETTINGS_FILE

    def _load_saved_settings(self) -> dict:
        path = self._config_path()
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            print(f"Failed to read settings file {path}: {exc}")
            return {}

    def _write_settings(self, settings: dict):
        path = self._config_path()
        try:
            with path.open("w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)
        except Exception as exc:
            self.settings_feedback_lbl.setText(f"Failed to save settings: {exc}")

    def _save_settings(self):
        host_text = self.server_ip_edit.text().strip()
        port_text = self.server_port_edit.text().strip()

        if not host_text:
            self.settings_feedback_lbl.setText("Server IP cannot be empty.")
            return

        try:
            ipaddress.ip_address(host_text)
        except ValueError:
            self.settings_feedback_lbl.setText("Server IP must be a valid IPv4/IPv6 address.")
            return

        try:
            port_value = int(port_text)
        except ValueError:
            self.settings_feedback_lbl.setText("Server Port must be numeric.")
            return

        if port_value <= 0 or port_value > 65535:
            self.settings_feedback_lbl.setText("Server Port must be between 1 and 65535.")
            return

        self.server_host = host_text
        self.server_port = port_value

        os.environ["THREATHUNTER_BIND_HOST"] = self.server_host
        os.environ["THREATHUNTER_PORT"] = str(self.server_port)

        saved = self._load_saved_settings()
        saved["bind_host"] = self.server_host
        saved["port"] = self.server_port
        saved["aux_host"] = self.aux_host
        saved["aux_port"] = self.aux_port
        self._write_settings(saved)

        self._restart_server_thread()
        self.settings_feedback_lbl.setText(
            f"Saved. Server listening on {self.server_host}:{self.server_port}."
        )

    def _restart_server_thread(self):
        try:
            self.server_thread.stop()
            self.server_thread.join(timeout=1)
        except Exception:
            pass

        self.server_thread = ServerThread(
            self.server_host,
            self.server_port,
            self.persist_queue,
            status_callback=self.status_signal.status_changed.emit,
        )
        self.server_thread.start()

    def _normalize_event(
        self,
        received_at: str,
        source: str,
        raw_event: str,
        raw_message: str = "",
        structured: dict[str, str] | None = None,
    ) -> dict[str, str]:
        if structured is not None:
            result = dict(structured)
            result["raw_message"] = raw_message or raw_event
            if "source" not in result or not result["source"]:
                result["source"] = source
            if "timestamp" not in result or not result["timestamp"]:
                result["timestamp"] = received_at
            for key, value in result.items():
                if key not in self.known_fields:
                    self.known_fields.add(key)
                    self._add_new_field(key, key.replace("_", " ").title())
            return result

        payload = {}
        if isinstance(raw_event, str):
            try:
                payload = json.loads(raw_event)
            except Exception:
                payload = {}

        event_type = payload.get("event_type", "") if isinstance(payload, dict) else ""
        process = payload.get("process", "") if isinstance(payload, dict) else ""
        pid = payload.get("pid", "") if isinstance(payload, dict) else ""
        user = payload.get("user", "") if isinstance(payload, dict) else ""
        ip_address = payload.get("ip_address", "") if isinstance(payload, dict) else ""

        message = ""
        if isinstance(payload, dict):
            message = payload.get("message") or payload.get("raw_event") or ""
        if not message:
            message = raw_event

        normalized = {
            "timestamp": str(payload.get("timestamp", received_at)) if isinstance(payload, dict) else received_at,
            "source": str(payload.get("source", source)) if isinstance(payload, dict) else source,
            "event_type": str(event_type),
            "process": str(process),
            "pid": str(pid),
            "user": str(user),
            "ip_address": str(ip_address),
            "message": str(message),
            "raw_message": raw_message or raw_event,
        }

        if isinstance(payload, dict):
            for key, value in payload.items():
                if key not in normalized and key not in {"timestamp", "source", "raw_event", "message"}:
                    normalized[key] = str(value)
                    if key not in self.known_fields:
                        self.known_fields.add(key)
                        self._add_new_field(key, key.replace("_", " ").title())

        return normalized

    def _selected_field_keys(self) -> list[str]:
        return [key for key, _label in self.available_fields if key in self.selected_fields]

    def _selected_field_labels(self) -> list[str]:
        labels = []
        for key, label in self.available_fields:
            if key in self.selected_fields:
                labels.append(label)
        return labels

    def _classify_event(self, event: dict):
        """Attach severity metadata to a normalized display event (no mutation of
        the original wire payload; adds private ``_severity*`` keys only)."""
        engine = self.__dict__.get("severity_engine")
        if engine is None:
            return
        result = engine.classify_event(event)
        event["_severity"] = result.level
        event["_severity_reason"] = result.reason
        event["_severity_presentation"] = {
            "color": result.color,
            "label": result.label,
            "symbol": result.symbol,
        }

    def _filtered_events(self) -> list[dict]:
        results = self.events
        sev = self.__dict__.get("severity_filter")
        if sev is not None:
            results = [e for e in results if e.get("_severity") == sev]

        query = self.search_query.strip().lower()
        if not query:
            return results

        matched = []
        for event in results:
            for value in event.values():
                if query in str(value).lower():
                    matched.append(event)
                    break
        return matched

    # ------------------------------------------------------------------ #
    # Table rendering
    # ------------------------------------------------------------------ #

    def _severity_tint(self, color: str, critical: bool = False):
        """Subtle severity-colored row tint (stronger for critical events)."""
        if not color:
            return None
        base = QColor(color)
        base.setAlpha(26 if not critical else 48)
        return base

    def _make_item(self, event: dict, key: str, text, pres: dict, tint, is_sev: bool = False):
        item = QStandardItem(str(text) if text is not None else "")
        item.setEditable(False)
        item.setToolTip(str(text) if text is not None else "")
        if is_sev:
            item.setTextAlignment(Qt.AlignCenter)
            if pres.get("color"):
                item.setForeground(QBrush(QColor(pres["color"])))
                bold = QFont()
                bold.setBold(True)
                item.setFont(bold)
        elif key in MONO_FIELDS:
            item.setFont(QFont("Menlo", 11))
        if tint is not None:
            item.setBackground(QBrush(tint))
        return item

    def _build_row_items(self, event: dict, selected_keys: list[str]) -> list[QStandardItem]:
        sev = event.get("_severity")
        pres = event.get("_severity_presentation") or {}
        color = pres.get("color", "")
        tint = self._severity_tint(color, critical=(sev == "critical"))
        symbol = pres.get("symbol") or (sev.upper() if sev else "")
        items = [self._make_item(event, SEV_COLUMN_KEY, symbol, pres, tint, is_sev=True)]
        for key in selected_keys:
            items.append(self._make_item(event, key, event.get(key, ""), pres, tint))
        return items

    def _apply_column_widths(self, selected_keys: list[str]):
        header = self.table_view.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        self.table_view.setColumnWidth(0, 42)
        for idx, key in enumerate(selected_keys, start=1):
            header.setSectionResizeMode(idx, QHeaderView.Interactive)
            if key == "timestamp":
                self.table_view.setColumnWidth(idx, 240)
            elif key in {"source", "event_type", "process", "user"}:
                self.table_view.setColumnWidth(idx, 170)
            elif key in {"pid", "ip_address"}:
                self.table_view.setColumnWidth(idx, 130)
            elif key == "message":
                self.table_view.setColumnWidth(idx, 400)
            elif key == "raw_message":
                self.table_view.setColumnWidth(idx, 500)
            else:
                self.table_view.setColumnWidth(idx, 150)

    def _sync_sort_indicator(self):
        header = self.table_view.horizontalHeader()
        if self._sort_column is not None:
            header.setSortIndicator(self._sort_column, self._sort_order)

    def _refresh_table(self):
        selected_keys = self._selected_field_keys()
        selected_labels = self._selected_field_labels()

        events = list(self._filtered_events())
        if self._sort_column is not None:
            events = self._sort_events(events)
        self._table_events = events

        columns = [SEV_COLUMN_KEY] + selected_keys
        headers = ["Sev"] + selected_labels

        model = self.table_model
        model.beginResetModel()
        model.clear()
        model.setColumnCount(len(columns))
        model.setHorizontalHeaderLabels(headers)
        for event in events:
            model.appendRow(self._build_row_items(event, selected_keys))
        model.endResetModel()

        self._apply_column_widths(selected_keys)
        self._sync_sort_indicator()
        self.table_view.viewport().update()

    # ------------------------------------------------------------------ #
    # Severity filtering
    # ------------------------------------------------------------------ #

    def _add_severity_filter_button(self, layout, label: str, level, color: str = "", checked: bool = False):
        btn = QPushButton(label)
        btn.setCheckable(True)
        btn.setChecked(checked)
        if color:
            btn.setStyleSheet(
                f"QPushButton {{ border: 1px solid {color}; padding: 4px 10px; }}"
                f"QPushButton:checked {{ background-color: {color}; color: #0B0F14; font-weight: 600; }}"
            )
        else:
            btn.setStyleSheet(
                "QPushButton { padding: 4px 10px; }"
                "QPushButton:checked { background-color: #1E3A5F; color: #F1F5F9; font-weight: 600; }"
            )
        btn.clicked.connect(
            lambda _checked=False, b=btn, lvl=level: self._on_severity_filter_clicked(lvl)
        )
        layout.addWidget(btn)
        self.severity_filter_buttons[level] = btn

    def _on_severity_filter_clicked(self, level):
        for key, btn in self.severity_filter_buttons.items():
            btn.blockSignals(True)
            btn.setChecked(key == level)
            btn.blockSignals(False)
        self.severity_filter = level
        self._refresh_table()

    # ------------------------------------------------------------------ #
    # Sorting
    # ------------------------------------------------------------------ #

    def _on_header_section_clicked(self, col: int):
        if self.__dict__.get("is_query_mode", False):
            return
        if self._sort_column == col:
            self._sort_order = (
                Qt.AscendingOrder if self._sort_order == Qt.DescendingOrder else Qt.DescendingOrder
            )
        else:
            self._sort_column = col
            # Natural first-click order: critical/newest first for severity and
            # timestamp; alphabetical otherwise.
            self._sort_order = (
                Qt.DescendingOrder if col == 0 or col == self._column_index("timestamp")
                else Qt.AscendingOrder
            )
        self._refresh_table()

    def _column_index(self, key: str) -> int:
        selected_keys = self._selected_field_keys()
        for idx, k in enumerate([SEV_COLUMN_KEY] + selected_keys):
            if k == key:
                return idx
        return -1

    def _sort_events(self, events: list[dict]) -> list[dict]:
        selected_keys = self._selected_field_keys()
        columns = [SEV_COLUMN_KEY] + selected_keys
        if self._sort_column is None or self._sort_column >= len(columns):
            return events
        key_field = columns[self._sort_column]
        reverse = self._sort_order == Qt.DescendingOrder

        if key_field == SEV_COLUMN_KEY:
            def sort_key(e):
                return SEV_RANK.get(e.get("_severity"), -1)
        elif key_field == "timestamp":
            def sort_key(e):
                return str(e.get("timestamp", ""))
        elif key_field == "pid":
            def sort_key(e):
                try:
                    return float(e.get("pid", 0))
                except (TypeError, ValueError):
                    return float("inf")
        else:
            def sort_key(e):
                return str(e.get(key_field, "")).casefold()

        return sorted(events, key=sort_key, reverse=reverse)

    def _on_field_selector_changed(self):
        selected = {key for key, cb in self.field_checkboxes.items() if cb.isChecked()}
        if not selected:
            # Keep at least one visible column to avoid a blank table state.
            first_key, first_cb = next(iter(self.field_checkboxes.items()))
            first_cb.blockSignals(True)
            first_cb.setChecked(True)
            first_cb.blockSignals(False)
            selected = {first_key}

        self.selected_fields = selected
        self._refresh_table()

    def _add_new_field(self, key: str, label: str):
        """Add a newly discovered field to the sidebar and available fields."""
        if key in self.field_checkboxes:
            return
        checkbox = QCheckBox(label)
        checkbox.setChecked(False)
        checkbox.stateChanged.connect(self._on_field_selector_changed)

        if self.fields_layout is not None:
            self.fields_layout.insertWidget(self.fields_layout.count() - 1, checkbox)
            self.field_checkboxes[key] = checkbox
            self.available_fields.append((key, label))

    def _on_search_changed(self, text: str):
        self.search_query = text
        self._refresh_table()

    def _on_table_clicked(self, index):
        """Open the Event Details view for the exact event in the clicked row."""
        events = self.__dict__.get("_table_events") or self._filtered_events()
        if index.row() < 0 or index.row() >= len(events):
            return
        event = events[index.row()]
        EventDetailsDialog(event, self).exec_()

    def _set_connection_status(self, status: str):
        normalized = status.strip()
        if normalized == "Connected":
            text = "● Connected"
        else:
            text = "● Waiting for connection"

        self.current_status = normalized
        self.side_agent_status_lbl.setText(text)
        self.agent_status_lbl.setText(f"Agent Status: {text[2:]}")

    def _on_status_change(self, status: str):
        self._set_connection_status(status)

    def _poll_queue(self):
        new_events = []
        while not self.event_queue.empty():
            try:
                queue_item = self.event_queue.get_nowait()
            except queue.Empty:
                break

            if len(queue_item) == 5:
                received_at, source, raw_event, raw_message, structured = queue_item
            else:
                received_at, source, raw_event = queue_item
                raw_message = raw_event
                structured = None

            event = self._normalize_event(received_at, source, raw_event, raw_message, structured)
            self._classify_event(event)
            new_events.append(event)
            self.event_counter += 1

        if not new_events:
            return

        self.events.extend(new_events)
        overflowed = len(self.events) > MAX_EVENTS
        if overflowed:
            self.events = self.events[-MAX_EVENTS:]

        self.event_count_lbl.setText(f"Events Received: {self.event_counter}")
        self.side_event_count_lbl.setText(f"Events Received: {self.event_counter}")

        if self._can_append_incrementally() and not overflowed:
            self._append_rows(new_events)
        else:
            self._refresh_table()

    def _can_append_incrementally(self) -> bool:
        """True when new events can be appended without rebuilding the table."""
        if self.__dict__.get("is_query_mode", False):
            return False
        if self.search_query.strip():
            return False
        if self.severity_filter is not None:
            return False
        if self._sort_column is not None:
            return False
        return True

    def _append_rows(self, events: list[dict]):
        """Incrementally append rows for new events (batched, no full rebuild)."""
        selected_keys = self._selected_field_keys()
        model = self.table_model
        view = self.table_view
        view.setUpdatesEnabled(False)
        model.blockSignals(True)
        try:
            for event in events:
                model.appendRow(self._build_row_items(event, selected_keys))
                self._table_events.append(event)
        finally:
            view.setUpdatesEnabled(True)
            model.blockSignals(False)
        view.viewport().update()

    def _load_events_from_db(self):
        """Restore previously persisted events into the table on startup."""
        try:
            records = self.event_repo.load_recent(limit=MAX_EVENTS)
        except Exception as exc:
            print("Failed to load events from database:", exc)
            return

        skip_keys = set(SCHEMA_COLUMNS) | {
            "id",
            "received_at",
            "raw_event",
            "raw_message",
            "extra",
            "structured",
        }
        loaded = []
        for row in records:
            try:
                normalized = self._normalize_event(
                    row.get("received_at") or row.get("timestamp") or "",
                    row.get("source") or "",
                    row.get("raw_event") or "",
                    row.get("raw_message") or row.get("raw_event") or "",
                    row.get("structured") or None,
                )
            except Exception as exc:
                print("Failed to normalize stored event:", exc)
                continue

            if not normalized.get("process") and row.get("process_name"):
                normalized["process"] = row["process_name"]

            # Surface the stored severity (numeric risk value) as a display
            # field so the classifier and detail view can use it.
            if row.get("severity") is not None and "severity" not in normalized:
                normalized["severity"] = row["severity"]

            for key, value in row.items():
                if key in skip_keys or key in self.known_fields:
                    continue
                if value is None or value == "" or isinstance(value, (dict, list)):
                    continue
                normalized[key] = str(value)
                self.known_fields.add(key)
                self._add_new_field(key, key.replace("_", " ").title())

            self._classify_event(normalized)
            loaded.append(normalized)

        if not loaded:
            return

        # Records are newest-first; the table expects oldest-first.
        loaded.reverse()
        self.events = loaded
        if len(self.events) > MAX_EVENTS:
            self.events = self.events[-MAX_EVENTS:]
        try:
            self.event_counter = self.event_repo.event_count()
        except Exception:
            self.event_counter = len(loaded)
        self.event_count_lbl.setText(f"Events Received: {self.event_counter}")
        self.side_event_count_lbl.setText(f"Events Received: {self.event_counter}")
        self._refresh_table()

    def start_server(self):
        """Keep legacy auxiliary listener functionality intact."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.aux_host, self.aux_port))
            self.server_socket.listen(5)
            print(f"Auxiliary server is listening on {self.aux_host}:{self.aux_port}...")
        except Exception as exc:
            print(f"Auxiliary server start error: {exc}")
            self.server_socket = None
            return

        def accept_connections():
            while not self.socket_server_stop.is_set():
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"Auxiliary connection from {addr}")
                    t = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket,),
                        daemon=True,
                    )
                    t.start()
                except OSError:
                    break
                except Exception as exc:
                    print(f"Auxiliary accept error: {exc}")

        self.socket_accept_thread = threading.Thread(target=accept_connections, daemon=True)
        self.socket_accept_thread.start()

    def handle_client(self, client_socket):
        try:
            with client_socket:
                while not self.socket_server_stop.is_set():
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    message = data.decode(errors="replace")
                    stamped = f"[{time.strftime('%H:%M:%S')}] - {message}"
                    self.socket_message_queue.put(stamped)
        except Exception as exc:
            print(f"Auxiliary handle client error: {exc}")

    def _poll_socket_messages(self):
        while not self.socket_message_queue.empty():
            try:
                msg = self.socket_message_queue.get_nowait()
            except queue.Empty:
                break
            self.messages_display.addItem(msg)

    def _on_query_execute(self):
        """Execute a query and display results."""
        query_text = self.query_input.text().strip()
        if not query_text:
            self.query_status_lbl.setText("No query entered.")
            return

        try:
            self.query_status_lbl.setText("Executing query...")
            self.query_run_btn.setEnabled(False)

            # Execute the query
            result = self.query_engine.execute(query_text)

            self.current_query = query_text
            self.query_results = result.rows
            self.is_query_mode = True

            # Display results in table
            self._display_query_results(result)

            self.query_status_lbl.setText(
                f"Query returned {result.row_count} events in {result.execution_time_ms:.1f}ms"
            )

        except QueryEngineError as e:
            self.query_status_lbl.setText(f"Query error: {str(e)}")
        except Exception as e:
            self.query_status_lbl.setText(f"Unexpected error: {str(e)}")
        finally:
            self.query_run_btn.setEnabled(True)

    def _display_query_results(self, result):
        """Display query results in the table (with severity indicators)."""
        columns = list(result.columns) if result.columns else self._selected_field_keys()
        rows = result.rows
        self._table_events = rows
        for row in rows:
            if "_severity" not in row:
                self._classify_event(row)

        model = self.table_model
        model.beginResetModel()
        model.clear()
        model.setColumnCount(len(columns) + 1)
        model.setHorizontalHeaderLabels([SEV_COLUMN_KEY.title()] + columns)
        for row_dict in rows:
            model.appendRow(self._build_query_row_items(row_dict, columns))
        model.endResetModel()

        header = self.table_view.horizontalHeader()
        for idx in range(len(columns) + 1):
            header.setSectionResizeMode(idx, QHeaderView.ResizeToContents)
        self._sync_sort_indicator()
        self.table_view.viewport().update()

    def _build_query_row_items(self, row: dict, columns: list[str]) -> list[QStandardItem]:
        sev = row.get("_severity")
        pres = row.get("_severity_presentation") or {}
        color = pres.get("color", "")
        tint = self._severity_tint(color, critical=(sev == "critical"))
        symbol = pres.get("symbol") or (sev.upper() if sev else "")
        items = [
            self._make_item(row, SEV_COLUMN_KEY, symbol, pres, tint, is_sev=True)
        ]
        for col in columns:
            items.append(self._make_item(row, col, row.get(col, ""), pres, tint))
        return items

    def _on_query_clear(self):
        """Clear the query and return to live mode."""
        self.query_input.clear()
        self.query_status_lbl.setText("")
        self.is_query_mode = False
        self.current_query = ""
        self.query_results = []
        self.search_query = ""
        self.search_input.clear()
        self._refresh_table()  # Return to live event display
    def closeEvent(self, event):
        self.socket_server_stop.set()
        try:
            if self.server_socket is not None:
                self.server_socket.close()
        except Exception:
            pass
        try:
            if self.socket_accept_thread is not None:
                self.socket_accept_thread.join(timeout=1)
        except Exception:
            pass
        try:
            self.server_thread.stop()
            self.server_thread.join(timeout=1)
        except Exception:
            pass
        try:
            # Stop the persistence worker after the server so any queued
            # events are drained and flushed before the DB is closed.
            self.persistence_worker.stop()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        event.accept()


if __name__ == "__main__":
    bind_host, port, aux_host, aux_port = get_runtime_network_config()

    config_path = Path(__file__).resolve().parent.parent / SETTINGS_FILE
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as f:
                saved = json.load(f)
            bind_host = str(saved.get("bind_host", bind_host))
            port = int(saved.get("port", port))
            aux_host = str(saved.get("aux_host", aux_host))
            aux_port = int(saved.get("aux_port", aux_port))
        except Exception as exc:
            print(f"Ignoring invalid settings file {config_path}: {exc}")

    print(
        f"Starting UI with ServerThread on {bind_host}:{port} "
        f"and auxiliary listener on {aux_host}:{aux_port}"
    )

    app = QApplication(sys.argv)
    win = MainWindow(host=bind_host, port=port, aux_host=aux_host, aux_port=aux_port)
    win.show()
    sys.exit(app.exec_())
