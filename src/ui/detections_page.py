"""Detections management UI page for Cyberion ThreatHunter."""

from datetime import datetime
from typing import Optional

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import QHBoxLayout, QPushButton, QTableView, QVBoxLayout, QWidget, QLabel

from .theme import COLORS, theme_font


class DetectionsPage(QWidget):
    """Simple table view for persisted detections."""

    def __init__(self, detection_manager, parent=None):
        super().__init__(parent)
        self.detection_manager = detection_manager
        self._build_ui()
        self._apply_styles()
        self._refresh_data()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._refresh_data)
        self.refresh_timer.setSingleShot(False)
        self.refresh_timer.start(5000)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        title = QLabel("Detections")
        title.setFont(theme_font(18, QFont.DemiBold))
        layout.addWidget(title)

        toolbar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setObjectName("primaryButton")
        self.refresh_btn.clicked.connect(self._refresh_data)
        toolbar.addWidget(self.refresh_btn)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)

        self.table = QTableView()
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setShowGrid(False)
        layout.addWidget(self.table, 1)

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            f"""
            QWidget {{ background-color: {COLORS['app_bg']}; color: {COLORS['text_primary']}; }}
            QPushButton {{ min-height: 30px; }}
            """
        )

    def _refresh_data(self) -> None:
        if self.detection_manager is None:
            return
        try:
            detections = self.detection_manager.get_all_detections(limit=100)
            self._populate_table(detections)
        except Exception:
            pass

    def _populate_table(self, detections) -> None:
        model = QStandardItemModel(len(detections), 6)
        model.setHorizontalHeaderLabels([
            "Detection ID",
            "Rule",
            "Severity",
            "Status",
            "Event ID",
            "Detected At",
        ])

        for row, detection in enumerate(detections):
            model.setItem(row, 0, QStandardItem(detection.detection_id or ""))
            model.setItem(row, 1, QStandardItem(detection.rule_name or ""))
            model.setItem(row, 2, QStandardItem((detection.severity or "").upper()))
            model.setItem(row, 3, QStandardItem(detection.status or ""))
            model.setItem(row, 4, QStandardItem(str(detection.trigger_event_id or "")))
            detected_at = detection.detected_at or ""
            try:
                dt = datetime.fromisoformat(detected_at)
                detected_at = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
            model.setItem(row, 5, QStandardItem(detected_at))

        self.table.setModel(model)
        self.table.resizeColumnsToContents()
