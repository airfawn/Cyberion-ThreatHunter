"""Threat Hunting page for analyst-driven investigations."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from PyQt5.QtCore import QEasingCurve, Qt, QPropertyAnimation
from PyQt5.QtGui import QFont, QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableView,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..hunting import ThreatHuntingController, ThreatHypothesis
from .theme import COLORS, theme_font


class EventDetailsDialog(QDialog):
    """Structured event details with optional raw payload view."""

    def __init__(self, event: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.event = event
        self.setWindowTitle("Investigation Event Details")
        self.resize(740, 560)

        root = QVBoxLayout(self)

        meta = QLabel(
            "Structured Evidence"
        )
        meta.setFont(theme_font(13, QFont.DemiBold))
        root.addWidget(meta)

        summary = QTextEdit()
        summary.setReadOnly(True)
        summary.setMinimumHeight(180)

        structured_lines = []
        preferred = [
            "timestamp",
            "event_type",
            "process_name",
            "process",
            "pid",
            "ppid",
            "user",
            "hostname",
            "ip_address",
            "command",
            "filepath",
            "_correlation_reasons",
        ]
        for key in preferred:
            if key in event and event.get(key) not in (None, ""):
                structured_lines.append(f"{key}: {event.get(key)}")

        summary.setPlainText("\n".join(structured_lines) if structured_lines else "No structured fields")
        root.addWidget(summary)

        self.raw_toggle = QPushButton("Show Raw Event")
        self.raw_toggle.setCheckable(True)
        self.raw_toggle.toggled.connect(self._toggle_raw)
        root.addWidget(self.raw_toggle)

        self.raw = QTextEdit()
        self.raw.setReadOnly(True)
        self.raw.setVisible(False)
        self.raw.setMinimumHeight(220)
        self.raw.setFont(theme_font(11))
        self.raw.setPlainText(self._pretty_raw())
        root.addWidget(self.raw)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(close_btn)
        root.addLayout(row)

    def _toggle_raw(self, checked: bool) -> None:
        self.raw_toggle.setText("Hide Raw Event" if checked else "Show Raw Event")
        self.raw.setVisible(checked)

    def _pretty_raw(self) -> str:
        raw = self.event.get("raw_message")
        if isinstance(raw, str):
            try:
                return json.dumps(json.loads(raw), indent=2)
            except Exception:
                return raw
        return json.dumps(self.event, indent=2, default=str)


class HypothesisDialog(QDialog):
    """Create/edit dialog for hunting hypotheses."""

    def __init__(self, hypothesis: Optional[ThreatHypothesis] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Threat Hunting Hypothesis")
        self.resize(760, 640)
        self.hypothesis = hypothesis or ThreatHypothesis.new_default()

        root = QVBoxLayout(self)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft)

        self.name_edit = QLineEdit(self.hypothesis.name)
        self.desc_edit = QTextEdit(self.hypothesis.description)
        self.reason_edit = QTextEdit(self.hypothesis.reason)
        self.sources_edit = QLineEdit(", ".join(self.hypothesis.data_sources))
        self.query_edit = QTextEdit(self.hypothesis.query_kql)
        self.indicators_edit = QLineEdit(", ".join(self.hypothesis.indicators_to_extract))
        self.expected_edit = QTextEdit(self.hypothesis.expected_behavior)
        self.mitre_edit = QLineEdit(self.hypothesis.mitre_technique)

        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["low", "medium", "high", "critical"])
        self.severity_combo.setCurrentText(self.hypothesis.severity or "medium")

        self.confidence_spin = QDoubleSpinBox()
        self.confidence_spin.setRange(0.0, 1.0)
        self.confidence_spin.setSingleStep(0.05)
        self.confidence_spin.setValue(float(self.hypothesis.confidence or 0.5))

        self.status_combo = QComboBox()
        self.status_combo.addItems(["draft", "active", "paused", "archived"])
        self.status_combo.setCurrentText(self.hypothesis.status or "draft")

        form.addRow("Hypothesis Name", self.name_edit)
        form.addRow("Description", self.desc_edit)
        form.addRow("Reason for Hunting", self.reason_edit)
        form.addRow("Relevant Data Sources", self.sources_edit)
        form.addRow("Query / KQL", self.query_edit)
        form.addRow("Indicators to Extract", self.indicators_edit)
        form.addRow("Expected Suspicious Behavior", self.expected_edit)
        form.addRow("MITRE ATT&CK Technique", self.mitre_edit)
        form.addRow("Severity", self.severity_combo)
        form.addRow("Confidence", self.confidence_spin)
        form.addRow("Investigation Status", self.status_combo)
        root.addLayout(form)

        buttons = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("Save Hypothesis")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self._on_save)
        buttons.addStretch(1)
        buttons.addWidget(cancel_btn)
        buttons.addWidget(save_btn)
        root.addLayout(buttons)

    def _on_save(self) -> None:
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Hypothesis name is required.")
            return
        if not self.query_edit.toPlainText().strip():
            QMessageBox.warning(self, "Validation", "A KQL query is required.")
            return
        self.accept()

    def build_hypothesis(self) -> ThreatHypothesis:
        self.hypothesis.name = self.name_edit.text().strip()
        self.hypothesis.description = self.desc_edit.toPlainText().strip()
        self.hypothesis.reason = self.reason_edit.toPlainText().strip()
        self.hypothesis.data_sources = [
            item.strip() for item in self.sources_edit.text().split(",") if item.strip()
        ]
        self.hypothesis.query_kql = self.query_edit.toPlainText().strip()
        self.hypothesis.indicators_to_extract = [
            item.strip() for item in self.indicators_edit.text().split(",") if item.strip()
        ]
        self.hypothesis.expected_behavior = self.expected_edit.toPlainText().strip()
        self.hypothesis.mitre_technique = self.mitre_edit.text().strip()
        self.hypothesis.severity = self.severity_combo.currentText()
        self.hypothesis.confidence = float(self.confidence_spin.value())
        self.hypothesis.status = self.status_combo.currentText()
        return self.hypothesis


class ThreatHuntingPage(QWidget):
    """Main analyst-facing page for threat hunting investigations."""

    def __init__(self, controller: ThreatHuntingController, parent=None):
        super().__init__(parent)
        self.controller = controller

        self.hypotheses: List[ThreatHypothesis] = []
        self.investigations: Dict[str, Dict[str, Any]] = {}
        self.current_investigation_id = ""

        self._animations: List[QPropertyAnimation] = []

        self._build_ui()
        self._apply_styles()
        self._connect_signals()
        self._load_initial_data()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)

        title = QLabel("Threat Hunting")
        title.setFont(theme_font(18, QFont.DemiBold))
        root.addWidget(title)

        self.overview_row = QHBoxLayout()
        self.card_active = self._overview_card("Active Hunts", "0")
        self.card_recent = self._overview_card("Recent Hunts", "0")
        self.card_findings = self._overview_card("Findings", "0")
        self.card_high = self._overview_card("High Confidence", "0")
        self.card_failed = self._overview_card("Failed Hunts", "0")
        root.addLayout(self.overview_row)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_hypothesis_panel())
        splitter.addWidget(self._build_investigation_panel())
        splitter.setSizes([360, 900])
        root.addWidget(splitter, 1)

    def _overview_card(self, label_text: str, value_text: str) -> QFrame:
        card = QFrame()
        card.setObjectName("huntCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        label = QLabel(label_text)
        label.setProperty("secondary", True)
        label.setFont(theme_font(11))
        value = QLabel(value_text)
        value.setFont(theme_font(17, QFont.DemiBold))

        layout.addWidget(label)
        layout.addWidget(value)
        card._value_label = value  # type: ignore[attr-defined]

        self.overview_row.addWidget(card)
        return card

    def _build_hypothesis_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("huntPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        hdr = QLabel("Hypotheses")
        hdr.setFont(theme_font(13, QFont.DemiBold))
        layout.addWidget(hdr)

        self.hypothesis_list = QListWidget()
        self.hypothesis_list.itemSelectionChanged.connect(self._on_hypothesis_selected)
        layout.addWidget(self.hypothesis_list, 1)

        button_row = QHBoxLayout()
        self.btn_create = QPushButton("Create")
        self.btn_edit = QPushButton("Edit")
        self.btn_run = QPushButton("Run Hunt")
        self.btn_run.setObjectName("primaryButton")
        self.btn_cancel = QPushButton("Cancel Hunt")
        self.btn_cancel.setObjectName("dangerButton")

        self.btn_create.clicked.connect(self._on_create_hypothesis)
        self.btn_edit.clicked.connect(self._on_edit_hypothesis)
        self.btn_run.clicked.connect(self._on_run_hypothesis)
        self.btn_cancel.clicked.connect(self._on_cancel_hunt)

        button_row.addWidget(self.btn_create)
        button_row.addWidget(self.btn_edit)
        layout.addLayout(button_row)

        button_row2 = QHBoxLayout()
        button_row2.addWidget(self.btn_run)
        button_row2.addWidget(self.btn_cancel)
        layout.addLayout(button_row2)

        return panel

    def _build_investigation_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("huntPanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        state_row = QHBoxLayout()
        self.state_label = QLabel("Status: idle")
        self.state_label.setFont(theme_font(12, QFont.DemiBold))
        self.state_subtext = QLabel("Select and run a hypothesis.")
        self.state_subtext.setProperty("secondary", True)
        state_row.addWidget(self.state_label)
        state_row.addStretch(1)
        state_row.addWidget(self.state_subtext)
        layout.addLayout(state_row)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setMinimumHeight(6)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(lambda _idx: self._animate_panel(self.tabs.currentWidget()))

        self.suspicious_table = self._build_event_table()
        self.correlated_table = self._build_event_table()
        self.enrichment_table = self._build_enrichment_table()

        self.timeline_list = QListWidget()
        self.timeline_list.itemClicked.connect(self._on_timeline_clicked)

        self.indicators_text = QTextEdit()
        self.indicators_text.setReadOnly(True)

        self.notes_text = QTextEdit()
        self.notes_text.setReadOnly(True)

        self.tabs.addTab(self.suspicious_table, "Suspicious Events")
        self.tabs.addTab(self.correlated_table, "Correlated Events")
        self.tabs.addTab(self.timeline_list, "Timeline")
        self.tabs.addTab(self.indicators_text, "Indicators")
        self.tabs.addTab(self.enrichment_table, "IP Reputation")
        self.tabs.addTab(self.notes_text, "Conclusion")

        layout.addWidget(self.tabs, 1)
        return panel

    def _build_event_table(self) -> QTableView:
        table = QTableView()
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(False)
        table.doubleClicked.connect(lambda index, t=table: self._on_table_open_details(t, index.row()))

        model = QStandardItemModel(0, 8)
        model.setHorizontalHeaderLabels([
            "Timestamp",
            "Type",
            "Process",
            "User",
            "Host",
            "IP",
            "Severity",
            "Correlation",
        ])
        table.setModel(model)
        return table

    def _build_enrichment_table(self) -> QTableView:
        table = QTableView()
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        model = QStandardItemModel(0, 8)
        model.setHorizontalHeaderLabels([
            "IP",
            "Status",
            "Confidence",
            "Country",
            "ASN",
            "Organization",
            "Reports",
            "Source",
        ])
        table.setModel(model)
        return table

    def _connect_signals(self) -> None:
        self.controller.investigation_updated.connect(self._on_investigation_updated)
        self.controller.overview_updated.connect(self._on_overview_updated)
        self.controller.hypotheses_changed.connect(self._on_hypotheses_changed)

    def _load_initial_data(self) -> None:
        self.hypotheses = self.controller.list_hypotheses()
        self._render_hypotheses()
        for inv in self.controller.list_investigations():
            self.investigations[inv.investigation_id] = inv.to_dict()
        self._on_overview_updated(self.controller.get_overview())

    def _render_hypotheses(self) -> None:
        self.hypothesis_list.clear()
        for hypothesis in self.hypotheses:
            item = QListWidgetItem(f"{hypothesis.name} [{hypothesis.status}]")
            item.setData(Qt.UserRole, hypothesis.hypothesis_id)
            item.setToolTip(hypothesis.description or hypothesis.reason)
            self.hypothesis_list.addItem(item)

    def _selected_hypothesis(self) -> Optional[ThreatHypothesis]:
        item = self.hypothesis_list.currentItem()
        if item is None:
            return None
        hypothesis_id = item.data(Qt.UserRole)
        for hypothesis in self.hypotheses:
            if hypothesis.hypothesis_id == hypothesis_id:
                return hypothesis
        return None

    def _on_hypothesis_selected(self) -> None:
        hypothesis = self._selected_hypothesis()
        if hypothesis is None:
            self.state_subtext.setText("Select and run a hypothesis.")
            return
        self.state_subtext.setText(hypothesis.expected_behavior or hypothesis.reason or "Ready")

    def _on_create_hypothesis(self) -> None:
        dialog = HypothesisDialog(parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        saved = self.controller.save_hypothesis(dialog.build_hypothesis())
        self.hypotheses = self.controller.list_hypotheses()
        self._render_hypotheses()
        self._select_hypothesis(saved.hypothesis_id)

    def _on_edit_hypothesis(self) -> None:
        hypothesis = self._selected_hypothesis()
        if hypothesis is None:
            QMessageBox.information(self, "Threat Hunting", "Select a hypothesis to edit.")
            return
        dialog = HypothesisDialog(hypothesis=hypothesis, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        saved = self.controller.save_hypothesis(dialog.build_hypothesis())
        self.hypotheses = self.controller.list_hypotheses()
        self._render_hypotheses()
        self._select_hypothesis(saved.hypothesis_id)

    def _on_run_hypothesis(self) -> None:
        hypothesis = self._selected_hypothesis()
        if hypothesis is None:
            QMessageBox.information(self, "Threat Hunting", "Select a hypothesis before running a hunt.")
            return
        inv = self.controller.run_hypothesis(hypothesis)
        self.current_investigation_id = inv.investigation_id
        self._set_state(inv.status, "Hunt started in background")

    def _on_cancel_hunt(self) -> None:
        if not self.current_investigation_id:
            QMessageBox.information(self, "Threat Hunting", "No active investigation selected.")
            return
        cancelled = self.controller.cancel_hunt(self.current_investigation_id)
        if not cancelled:
            QMessageBox.information(self, "Threat Hunting", "Selected hunt is no longer running.")

    def _on_hypotheses_changed(self, payload: List[Dict[str, Any]]) -> None:
        self.hypotheses = [ThreatHypothesis.from_dict(item) for item in payload]
        self._render_hypotheses()

    def _on_overview_updated(self, overview: Dict[str, Any]) -> None:
        self._set_card_value(self.card_active, overview.get("active_hunts", 0))
        self._set_card_value(self.card_recent, overview.get("recent_hunts", 0))
        self._set_card_value(self.card_findings, overview.get("findings", 0))
        self._set_card_value(self.card_high, overview.get("high_confidence", 0))
        self._set_card_value(self.card_failed, overview.get("failed_hunts", 0))

    def _set_card_value(self, card: QFrame, value: Any) -> None:
        value_lbl = getattr(card, "_value_label", None)
        if value_lbl is not None:
            value_lbl.setText(str(value))

    def _on_investigation_updated(self, payload: Dict[str, Any]) -> None:
        investigation_id = str(payload.get("investigation_id", ""))
        if not investigation_id:
            return
        self.investigations[investigation_id] = payload
        self.current_investigation_id = investigation_id

        self._set_state(payload.get("status", "idle"), payload.get("error") or "")
        self._render_investigation(payload)

    def _set_state(self, status: str, detail: str) -> None:
        self.state_label.setText(f"Status: {status}")
        self.state_subtext.setText(detail or "")
        if status == "running":
            self.progress.setRange(0, 0)
        else:
            self.progress.setRange(0, 1)
            self.progress.setValue(1 if status == "completed" else 0)

    def _render_investigation(self, inv: Dict[str, Any]) -> None:
        suspicious = inv.get("suspicious_events") or []
        related = inv.get("related_events") or []
        timeline = inv.get("timeline") or []
        indicators = inv.get("extracted_indicators") or {}
        enrichment = inv.get("ip_enrichment") or {}

        self._populate_event_table(self.suspicious_table, suspicious)
        self._populate_event_table(self.correlated_table, related)
        self._populate_timeline(timeline)
        self._populate_enrichment(enrichment)

        indicators_lines = []
        for key, values in indicators.items():
            indicators_lines.append(f"{key}: {', '.join(values)}")
        if not indicators_lines:
            indicators_lines.append("No indicators extracted.")
        self.indicators_text.setPlainText("\n".join(indicators_lines))

        conclusion = inv.get("analyst_conclusion") or ""
        mitre = ", ".join(inv.get("mitre_techniques") or [])
        confidence = inv.get("confidence")
        notes = [
            f"Confidence: {confidence}",
            f"MITRE ATT&CK: {mitre or 'n/a'}",
            "",
            "Analyst Conclusion",
            conclusion or "No conclusion available.",
        ]
        self.notes_text.setPlainText("\n".join(notes))

    def _populate_event_table(self, table: QTableView, events: List[Dict[str, Any]]) -> None:
        model = table.model()
        if model is None:
            return
        model.removeRows(0, model.rowCount())

        # Keep rendering bounded for responsiveness.
        capped = events[:500]
        for event in capped:
            ts = str(event.get("timestamp") or event.get("received_at") or "")
            ev_type = str(event.get("event_type") or "")
            proc = str(event.get("process_name") or event.get("process") or "")
            user = str(event.get("user") or "")
            host = str(event.get("hostname") or "")
            ip = str(event.get("ip_address") or event.get("source_ip") or "")
            sev = str(event.get("_severity") or event.get("severity") or "")
            corr_reason = ", ".join(event.get("_correlation_reasons") or [])

            row_items = [
                QStandardItem(ts),
                QStandardItem(ev_type),
                QStandardItem(proc),
                QStandardItem(user),
                QStandardItem(host),
                QStandardItem(ip),
                QStandardItem(sev),
                QStandardItem(corr_reason),
            ]
            for item in row_items:
                item.setEditable(False)
            row_items[0].setData(event, Qt.UserRole)
            model.appendRow(row_items)

        table.resizeColumnsToContents()
        self._animate_panel(table)

    def _populate_timeline(self, timeline: List[Dict[str, Any]]) -> None:
        self.timeline_list.clear()
        for item in timeline[:800]:
            evidence = item.get("evidence_type", "")
            marker = "?" if item.get("uncertain") else "*"
            summary = (
                f"{item.get('timestamp', '')}  {marker}  "
                f"{item.get('event_type', '')}  "
                f"{item.get('process', '')}  "
                f"[{evidence}]"
            )
            row = QListWidgetItem(summary)
            row.setData(Qt.UserRole, item)
            row.setToolTip(item.get("correlation_reason", ""))
            self.timeline_list.addItem(row)
        self._animate_panel(self.timeline_list)

    def _populate_enrichment(self, enrichment: Dict[str, Dict[str, Any]]) -> None:
        model = self.enrichment_table.model()
        if model is None:
            return
        model.removeRows(0, model.rowCount())

        if not enrichment:
            model.appendRow([
                QStandardItem(""),
                QStandardItem("Unavailable"),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem(""),
                QStandardItem("No configured reputation source"),
            ])
            return

        for ip, data in enrichment.items():
            reports = data.get("malicious_reports")
            if isinstance(reports, list):
                reports_text = str(len(reports))
            else:
                reports_text = "" if reports is None else str(reports)
            row = [
                QStandardItem(str(ip)),
                QStandardItem(str(data.get("status") or data.get("reason") or "unknown")),
                QStandardItem(str(data.get("confidence") if data.get("confidence") is not None else "")),
                QStandardItem(str(data.get("country") or "")),
                QStandardItem(str(data.get("asn") or "")),
                QStandardItem(str(data.get("organization") or "")),
                QStandardItem(reports_text),
                QStandardItem(str(data.get("source") or "")),
            ]
            for item in row:
                item.setEditable(False)
            model.appendRow(row)

        self.enrichment_table.resizeColumnsToContents()
        self._animate_panel(self.enrichment_table)

    def _on_table_open_details(self, table: QTableView, row_index: int) -> None:
        model = table.model()
        if model is None or row_index < 0 or row_index >= model.rowCount():
            return
        event = model.item(row_index, 0).data(Qt.UserRole)
        if not isinstance(event, dict):
            return
        EventDetailsDialog(event, self).exec_()

    def _on_timeline_clicked(self, item: QListWidgetItem) -> None:
        payload = item.data(Qt.UserRole)
        if not isinstance(payload, dict):
            return
        raw = payload.get("raw_event")
        if not isinstance(raw, dict):
            return
        EventDetailsDialog(raw, self).exec_()

    def _animate_panel(self, widget: QWidget) -> None:
        if widget is None:
            return
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(180)
        anim.setStartValue(0.6)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)

        def cleanup() -> None:
            widget.setGraphicsEffect(None)

        anim.finished.connect(cleanup)
        self._animations.append(anim)
        anim.finished.connect(lambda: self._animations.remove(anim) if anim in self._animations else None)
        anim.start()

    def _select_hypothesis(self, hypothesis_id: str) -> None:
        for index in range(self.hypothesis_list.count()):
            item = self.hypothesis_list.item(index)
            if item.data(Qt.UserRole) == hypothesis_id:
                self.hypothesis_list.setCurrentItem(item)
                return

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            f"""
            QFrame#huntPanel {{
                background-color: {COLORS['surface_secondary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
            QFrame#huntCard {{
                background-color: {COLORS['surface_secondary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
            }}
            QListWidget::item:hover {{
                background-color: {COLORS['surface_elevated']};
            }}
            QProgressBar {{
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                background-color: {COLORS['surface_primary']};
            }}
            QProgressBar::chunk {{
                background-color: {COLORS['accent']};
                border-radius: 3px;
            }}
            """
        )
