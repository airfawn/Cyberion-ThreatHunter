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

from PyQt5.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFrame,
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
    from .database import EventDB  # type: ignore
    from .server import ServerThread  # type: ignore
except Exception as e:  # pragma: no cover - startup guard
    print("Failed to import server/database modules:", e)
    sys.exit(1)


MAX_EVENTS = 5000
SETTINGS_FILE = "cyberion_settings.json"


class AgentStatusSignal(QObject):
    status_changed = pyqtSignal(str)


class EventDetailsDialog(QDialog):
    """Shows every field of a single event plus its original raw JSON."""

    def __init__(self, event: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Event Details")
        self.setMinimumSize(560, 420)
        self.resize(680, 500)
        # raw_message holds the exact JSON received from the agent
        # (the server sets it to json.dumps() of the incoming message/log entry).
        self.raw_json = str(event.get("raw_message", ""))

        layout = QVBoxLayout(self)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        grid = QGridLayout(content)
        grid.setColumnStretch(1, 1)
        row = 0
        for key, value in event.items():
            if key == "raw_message":
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
        self.db = EventDB()

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
            self.event_queue,
            status_callback=self.status_signal.status_changed.emit,
        )
        self.server_thread.start()

        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(200)
        self.poll_timer.timeout.connect(self._poll_queue)
        self.poll_timer.start()

        self.socket_poll_timer = QTimer(self)
        self.socket_poll_timer.setInterval(200)
        self.socket_poll_timer.timeout.connect(self._poll_socket_messages)
        self.socket_poll_timer.start()

        self.start_server()
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
        self.side_panel.setFrameStyle(QFrame.Panel | QFrame.Raised)
        side_layout = QVBoxLayout(self.side_panel)
        side_layout.setContentsMargins(14, 14, 14, 14)
        side_layout.setSpacing(10)

        title = QLabel("CYBERION")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        side_layout.addWidget(title)

        side_layout.addSpacing(6)
        server_lbl = QLabel("SERVER")
        server_lbl.setFont(QFont("Arial", 11, QFont.Bold))
        side_layout.addWidget(server_lbl)

        self.side_agent_status_lbl = QLabel("● Waiting for connection")
        side_layout.addWidget(self.side_agent_status_lbl)

        self.side_event_count_lbl = QLabel("Events Received: 0")
        side_layout.addWidget(self.side_event_count_lbl)

        side_layout.addStretch(1)

        fields_lbl = QLabel("DATA FIELDS")
        fields_lbl.setFont(QFont("Arial", 11, QFont.Bold))
        side_layout.addWidget(fields_lbl)

        fields_scroll = QScrollArea()
        fields_scroll.setWidgetResizable(True)
        fields_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        fields_scroll.setMinimumHeight(220)

        self.fields_widget = QWidget()
        self.fields_layout = QVBoxLayout(self.fields_widget)
        self.fields_layout.setContentsMargins(6, 6, 6, 6)
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
        settings_lbl = QLabel("SETTINGS")
        settings_lbl.setFont(QFont("Arial", 11, QFont.Bold))
        side_layout.addWidget(settings_lbl)

        side_layout.addWidget(QLabel("Server IP"))
        self.server_ip_edit = QLineEdit(self.server_host)
        side_layout.addWidget(self.server_ip_edit)

        side_layout.addWidget(QLabel("Server Port"))
        self.server_port_edit = QLineEdit(str(self.server_port))
        side_layout.addWidget(self.server_port_edit)

        self.save_settings_btn = QPushButton("Save")
        self.save_settings_btn.clicked.connect(self._save_settings)
        side_layout.addWidget(self.save_settings_btn)

        self.settings_feedback_lbl = QLabel("")
        self.settings_feedback_lbl.setWordWrap(True)
        side_layout.addWidget(self.settings_feedback_lbl)

        return self.side_panel

    def _build_content_area(self) -> QWidget:
        main_pane = QWidget()
        main_layout = QVBoxLayout(main_pane)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(8)

        self.top_nav = QTabBar()
        self.top_nav.addTab("Event Monitoring")
        self.top_nav.addTab("Alerts")
        main_layout.addWidget(self.top_nav)

        self.main_stack = QStackedWidget()
        self.main_stack.addWidget(self._build_event_monitor_page())
        self.main_stack.addWidget(self._build_alerts_page())
        main_layout.addWidget(self.main_stack)

        self.top_nav.currentChanged.connect(self.main_stack.setCurrentIndex)
        self.top_nav.setCurrentIndex(0)
        return main_pane

    def _build_event_monitor_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(8)

        self.agent_status_lbl = QLabel("Agent Status: Waiting for connection")
        self.agent_status_lbl.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(self.agent_status_lbl)

        self.event_count_lbl = QLabel("Events Received: 0")
        self.event_count_lbl.setFont(QFont("Arial", 11))
        layout.addWidget(self.event_count_lbl)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search events...")
        self.search_input.textChanged.connect(self._on_search_changed)
        layout.addWidget(self.search_input)

        self.table_model = QStandardItemModel(0, 0, self)
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.verticalHeader().hide()
        self.table_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.table_view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.table_view.setWordWrap(False)
        self.table_view.setHorizontalScrollMode(QTableView.ScrollPerPixel)
        self.table_view.setVerticalScrollMode(QTableView.ScrollPerPixel)
        self.table_view.horizontalHeader().setStretchLastSection(False)
        self.table_view.clicked.connect(self._on_table_clicked)
        layout.addWidget(self.table_view, 1)

        self.messages_display = QListWidget()
        self.messages_display.setMinimumHeight(90)
        self.messages_display.setMaximumHeight(140)
        layout.addWidget(self.messages_display)

        return page

    def _build_alerts_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        alerts_placeholder = QLabel("Alerts page is ready.")
        alerts_placeholder.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        layout.addWidget(alerts_placeholder)
        layout.addStretch(1)
        return page

    def _apply_styles(self):
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #1a1a1a;
                color: #ffffff;
            }

            QFrame {
                background-color: #2d2d2d;
                border-radius: 5px;
            }

            QTabBar {
                background-color: #3c3c3c;
                color: #ffffff;
            }

            QTabBar::tab {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 8px 12px;
                margin-right: 2px;
            }

            QTabBar::tab:selected {
                background-color: #4a82ea;
            }

            QTableView {
                background-color: #1e1e1e;
                alternate-background-color: #252525;
                gridline-color: #444444;
                color: #f0f0f0;
                border-radius: 5px;
                padding: 4px;
            }

            QHeaderView::section {
                background-color: #3c3c3c;
                color: #ffffff;
                font-size: 13px;
                padding: 6px;
                border-bottom: 2px solid white;
            }

            QLineEdit {
                background-color: #202020;
                color: #ffffff;
                border: 1px solid #4a4a4a;
                border-radius: 4px;
                padding: 6px;
            }

            QPushButton {
                background-color: #4a82ea;
                color: #ffffff;
                border-radius: 4px;
                padding: 6px 8px;
            }

            QListWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border-radius: 5px;
                padding: 4px;
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
            self.event_queue,
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

    def _filtered_events(self) -> list[dict[str, str]]:
        query = self.search_query.strip().lower()
        if not query:
            return self.events

        matched = []
        for event in self.events:
            for value in event.values():
                if query in str(value).lower():
                    matched.append(event)
                    break
        return matched

    def _refresh_table(self):
        selected_keys = self._selected_field_keys()
        selected_labels = self._selected_field_labels()

        self.table_model.clear()
        self.table_model.setColumnCount(len(selected_keys))
        self.table_model.setHorizontalHeaderLabels(selected_labels)

        for event in self._filtered_events():
            row_items = []
            for key in selected_keys:
                item = QStandardItem(str(event.get(key, "")))
                item.setEditable(False)
                row_items.append(item)
            self.table_model.appendRow(row_items)

        for idx, key in enumerate(selected_keys):
            self.table_view.horizontalHeader().setSectionResizeMode(idx, QHeaderView.Interactive)
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
        events = self._filtered_events()
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
        table_needs_update = False
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

            try:
                self.db.insert_event(received_at, source, raw_event)
            except Exception as exc:
                print("DB insert error:", exc)
                continue

            self.events.append(
                self._normalize_event(received_at, source, raw_event, raw_message, structured)
            )
            self.event_counter += 1
            table_needs_update = True

        if table_needs_update:
            if len(self.events) > MAX_EVENTS:
                self.events = self.events[-MAX_EVENTS:]
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
