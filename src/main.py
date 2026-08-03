# python src/main.py
"""
PyQt5 GUI for Cyberion ThreatShield – Event Monitoring module.

This script starts the UI, launches the background TCP server (ServerThread)
and stores received raw events in an SQLite database while showing them
in a table.
"""

import sys
import json
import queue
import socket
import threading
import time
from datetime import datetime

from PyQt5.QtCore import Qt, QTimer, QObject, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
from PyQt5.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QVBoxLayout,
    QWidget,
    QTableView,
    QHeaderView,
    QSplitter,
    QFrame,
    QTabBar,
    QScrollArea,
    QHBoxLayout,
    QStackedWidget,
    QListWidget,
)

# Local imports – adjust as needed if package structure differs
try:
    from .server import ServerThread  # type: ignore
    from .database import EventDB      # type: ignore
except Exception as e:  # pragma: no cover - debugging fallback
    print("Failed to import server/database modules:", e)
    sys.exit(1)


class AgentStatusSignal(QObject):
    """Simple signal emitter for agent connection status."""

    status_changed = pyqtSignal(str)


class MainWindow(QMainWindow):
    def __init__(self, host: str = "127.0.0.1", port: int = 9999, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set up the main window with improved layout
        self.setWindowTitle("Cyberion ThreatShield – Event Monitoring")
        self.setGeometry(100, 100, 1200, 800)

        # Create main container and splitter for resizable layout
        main_container = QWidget()
        self.setCentralWidget(main_container)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setStretchFactor(1, 1)

        # Left side panel (configuration/settings)
        self.side_panel = QFrame()
        self.side_panel.setFrameStyle(QFrame.Panel | QFrame.Raised)

        tab_bar = QTabBar()
        tab_names = ["Event Monitoring", "Settings", "Help"]
        for tab_name in tab_names:
            tab_bar.addTab(tab_name)

        # Create content areas for each tab.
        self.tabs = {tab: QScrollArea() for tab in tab_names}
        for tab, scroll_area in self.tabs.items():
            widget = QWidget()
            layout = QVBoxLayout(widget)
            if tab == "Event Monitoring":
                self.setup_event_monitoringUILayout(layout, compact=True)
            elif tab == "Settings":
                layout.addWidget(QLabel("Settings panel is ready for controls."))
                layout.addStretch(1)
            else:
                layout.addWidget(QLabel("Help panel is ready for documentation."))
                layout.addStretch(1)
            scroll_area.setWidget(widget)
            scroll_area.setWidgetResizable(True)

        self.side_stack = QStackedWidget()
        for tab in tab_names:
            self.side_stack.addWidget(self.tabs[tab])
        tab_bar.currentChanged.connect(self.side_stack.setCurrentIndex)

        side_layout = QVBoxLayout(self.side_panel)
        side_layout.addWidget(tab_bar)
        side_layout.addWidget(self.side_stack)

        # Main right pane (monitoring area)
        main_pane = QWidget()
        main_layout = QVBoxLayout(main_pane)
        main_layout.setContentsMargins(10, 10, 10, 10)
        self.setup_event_monitoringUILayout(main_layout)

        splitter.addWidget(self.side_panel)
        splitter.addWidget(main_pane)

        container_layout = QHBoxLayout(main_container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.addWidget(splitter)

        # Style the window and panels for better appearance.
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
                padding: 6px 10px;
                margin-right: 2px;
            }

            QTabBar::tab:selected {
                background-color: #4a82ea;
            }

            QScrollArea {
                background-color: #1a1a1a;
                border: none;
            }

            QPushButton {
                background-color: #4a82ea;
                border-radius: 3px;
                padding: 5px;
            }
            """
        )

        # Set up initial splitter sizes (left panel takes 25% of width).
        splitter.setSizes([int(self.width() * 0.25), int(self.width() * 0.75)])

        # Data structures
        self.event_queue: "queue.Queue[tuple[str, str, str]]" = queue.Queue()
        self.db = EventDB()
        self.event_counter = 0

        # Server thread
        self.status_signal = AgentStatusSignal()
        self.status_signal.status_changed.connect(self._on_status_change)
        self.server_thread = ServerThread(
            host, port, self.event_queue, status_callback=self.status_signal.status_changed.emit
        )
        self.server_thread.start()

        # Timer to poll queue and update UI
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(200)  # ms
        self.poll_timer.timeout.connect(self._poll_queue)
        self.poll_timer.start()

        # Auxiliary listener from legacy UI snippet; kept separate from main server thread.
        self.socket_message_queue: "queue.Queue[str]" = queue.Queue()
        self.socket_server_stop = threading.Event()
        self.socket_accept_thread = None
        self.server_socket = None

        self.socket_poll_timer = QTimer(self)
        self.socket_poll_timer.setInterval(200)
        self.socket_poll_timer.timeout.connect(self._poll_socket_messages)
        self.socket_poll_timer.start()

        self.start_server()

    def setup_event_monitoringUILayout(self, parent_layout, compact: bool = False):
        if compact:
            self.side_agent_status_lbl = QLabel("Agent: ● Waiting for connection")
            self.side_event_count_lbl = QLabel("Events Received: 0")
            parent_layout.addWidget(self.side_agent_status_lbl)
            parent_layout.addWidget(self.side_event_count_lbl)
            parent_layout.addWidget(QLabel("Recent events are visible in the main panel."))
            parent_layout.addStretch(1)
            return

        # Status area in the primary monitoring pane.
        self.agent_status_lbl = QLabel("Agent Status: Waiting for connection")
        self.agent_status_lbl.setFont(QFont("Arial", 14))
        self.agent_status_lbl.setStyleSheet(
            """
            color: #ffffff;
            background-color: #3c3c3c;
            padding: 8px 12px;
            border-radius: 3px;
            """
        )

        self.event_count_lbl = QLabel("Events Received: 0")
        self.event_count_lbl.setFont(QFont("Arial", 14))
        self.event_count_lbl.setStyleSheet(
            """
            color: #ffffff;
            background-color: #3c3c3c;
            padding: 8px 12px;
            border-radius: 3px;
            """
        )

        self.separator = QFrame()
        self.separator.setFrameShape(QFrame.HLine)
        self.separator.setStyleSheet(
            "QFrame { border: 0; border-bottom: 1px solid white; }"
        )

        parent_layout.addWidget(self.agent_status_lbl)
        parent_layout.addWidget(self.event_count_lbl)
        parent_layout.addWidget(self.separator)

        # Event table.
        self.table_model = QStandardItemModel(0, 3, self)
        self.table_model.setHorizontalHeaderLabels(["Timestamp", "Source", "Raw Event"])
        self.table_view = QTableView()
        self.table_view.setModel(self.table_model)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setStyleSheet(
            """
            QTableView {
                background-color: #1e1e1e;
                alternate-background-color: #252525;
                gridline-color: #444444;
                color: #f0f0f0;
                border-radius: 5px;
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #ffffff;
                font-size: 14px;
                padding: 8px;
                border-bottom: 2px solid white;
            }
            """
        )
        self.table_view.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.Interactive
        )
        self.table_view.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Interactive
        )
        self.table_view.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_view.setColumnWidth(0, 350)
        self.table_view.setColumnWidth(1, 200)
        self.table_view.verticalHeader().hide()
        parent_layout.addWidget(self.table_view)

        self.messages_display = QListWidget()
        self.messages_display.setStyleSheet(
            """
            QListWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border-radius: 5px;
                padding: 5px;
            }
            """
        )
        parent_layout.addWidget(self.messages_display)

    def start_server(self):
        """Start an auxiliary TCP listener without replacing existing server logic."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("localhost", 12345))
            self.server_socket.listen(5)
            print("Auxiliary server is listening on port 12345...")
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

        self.socket_accept_thread = threading.Thread(
            target=accept_connections,
            daemon=True,
        )
        self.socket_accept_thread.start()

    def handle_client(self, client_socket):
        """Handle incoming messages from auxiliary clients/agents."""
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
            if hasattr(self, "messages_display"):
                self.messages_display.addItem(msg)

    def _on_status_change(self, status: str):
        # Called from server thread via signal; safe to update UI here.
        self.agent_status_lbl.setText(f"Agent Status: {status}")
        if hasattr(self, "side_agent_status_lbl"):
            self.side_agent_status_lbl.setText(f"Agent: {status}")

    def _poll_queue(self):
        """Transfer all queued events into the DB and table."""
        while not self.event_queue.empty():
            try:
                received_at, source, raw_event = self.event_queue.get_nowait()
            except queue.Empty:
                break
            # Store in DB first – guarantees persistence even if UI fails.
            try:
                self.db.insert_event(received_at, source, raw_event)
            except Exception as exc:  # pragma: no cover - defensive
                print("DB insert error:", exc)
                continue
            # Update table
            items = [
                QStandardItem(received_at),
                QStandardItem(source),
                QStandardItem(raw_event),
            ]
            for itm in items:
                itm.setEditable(False)
            self.table_model.appendRow(items)
            # Update counter
            self.event_counter += 1
            self.event_count_lbl.setText(f"Events Received: {self.event_counter}")
            if hasattr(self, "side_event_count_lbl"):
                self.side_event_count_lbl.setText(
                    f"Events Received: {self.event_counter}"
                )
        # Keep table size reasonable – optional drop oldest rows if >2000.
        MAX_ROWS = 5000
        if self.table_model.rowCount() > MAX_ROWS:
            self.table_model.removeRows(0, self.table_model.rowCount() - MAX_ROWS)

    def closeEvent(self, event):
        # Clean shutdown: stop server thread, close DB.
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
    app = QApplication(sys.argv)
    win = MainWindow(host="127.0.0.1", port=9999)
    win.show()
    sys.exit(app.exec_())
