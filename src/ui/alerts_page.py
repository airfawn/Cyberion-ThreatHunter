"""Alert management UI page for Cyberion ThreatHunter.

Provides interface for viewing, creating, editing, and managing alert rules
and triggered alerts.
"""

import logging
from datetime import datetime
from typing import Optional

from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableView,
    QTabWidget, QMessageBox, QMenu, QApplication, QLabel, QFileDialog, QDialog, QTextEdit, QComboBox, QFrame, QLineEdit
)

from ..alerts import AlertRule, AlertSeverity, AlertLifecycleStatus, AlertHistoryRecord
from ..alerts.manager import AlertManager
from ..sigma.importer import SigmaRuleImporter
from .alert_editor import AlertRuleEditor
from .theme import COLORS, theme_font


logger = logging.getLogger(__name__)


class AlertsPage(QWidget):
    """Main page for alert management."""
    
    # Signals
    rule_created = pyqtSignal(AlertRule)
    rule_updated = pyqtSignal(AlertRule)
    rule_deleted = pyqtSignal(str)  # rule_id
    rule_enabled = pyqtSignal(str)  # rule_id
    rule_disabled = pyqtSignal(str)  # rule_id
    
    def __init__(self, alert_manager: AlertManager, parent=None):
        """Initialize alerts page.
        
        Args:
            alert_manager: Alert persistence manager
            parent: Parent widget
        """
        super().__init__(parent)
        self.alert_manager = alert_manager
        self.sigma_importer = SigmaRuleImporter(alert_manager)
        
        self._build_ui()
        self._apply_styles()
        self._refresh_data()
        
        # Auto-refresh timer (every 5 seconds)
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self._refresh_data)
        self.refresh_timer.setSingleShot(False)
        self.refresh_timer.start(5000)
    
    def _build_ui(self):
        """Build the UI layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Overview stats bar
        self._build_overview_bar(layout)
        
        # Top toolbar
        toolbar = self._build_toolbar()
        layout.addLayout(toolbar)
        
        # Tabs for filtering (rules)
        self.tabs = QTabWidget()
        
        # All Rules tab
        self.all_table = self._create_rules_table()
        self.tabs.addTab(self.all_table, "All Rules")
        
        # Active Rules tab
        self.active_table = self._create_rules_table()
        self.tabs.addTab(self.active_table, "Active")
        
        # Disabled Rules tab
        self.disabled_table = self._create_rules_table()
        self.tabs.addTab(self.disabled_table, "Disabled")
        
        self.tabs.currentChanged.connect(self._on_tab_changed)
        
        layout.addWidget(self.tabs)
        
        # Alerts section
        self._build_alerts_section(layout)
        
        self.setLayout(layout)
    
    def _build_overview_bar(self, layout) -> QFrame:
        """Build the overview statistics bar at the top of the page."""
        bar = QFrame()
        bar.setObjectName("overviewBar")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(0, 0, 0, 0)
        bar_layout.setSpacing(20)
        
        # Stats labels
        self.total_lbl = QLabel("Total: 0")
        self.total_lbl.setFont(theme_font(11))
        self.total_lbl.setProperty("secondary", True)
        
        self.critical_lbl = QLabel("Critical: 0")
        self.critical_lbl.setFont(theme_font(11))
        self.critical_lbl.setProperty("secondary", True)
        self.critical_lbl.setStyleSheet("color: #FF5F5F;")
        
        self.high_lbl = QLabel("High: 0")
        self.high_lbl.setFont(theme_font(11))
        self.high_lbl.setProperty("secondary", True)
        self.high_lbl.setStyleSheet("color: #FFB400;")
        
        self.medium_lbl = QLabel("Medium: 0")
        self.medium_lbl.setFont(theme_font(11))
        self.medium_lbl.setProperty("secondary", True)
        
        self.low_lbl = QLabel("Low: 0")
        self.low_lbl.setFont(theme_font(11))
        self.low_lbl.setProperty("secondary", True)
        
        self.new_lbl = QLabel("New: 0")
        self.new_lbl.setFont(theme_font(11))
        self.new_lbl.setProperty("secondary", True)
        
        self.investigating_lbl = QLabel("Investigating: 0")
        self.investigating_lbl.setFont(theme_font(11))
        self.investigating_lbl.setProperty("secondary", True)
        self.investigating_lbl.setStyleSheet("color: #FFAA00;")
        
        self.resolved_lbl = QLabel("Resolved: 0")
        self.resolved_lbl.setFont(theme_font(11))
        self.resolved_lbl.setProperty("secondary", True)
        
        self.false_positive_lbl = QLabel("False Positive: 0")
        self.false_positive_lbl.setFont(theme_font(11))
        self.false_positive_lbl.setProperty("secondary", True)
        
        # Layout order: total, severity breakdown, status breakdown
        bar_layout.addWidget(self.total_lbl)
        bar_layout.addWidget(self.critical_lbl)
        bar_layout.addWidget(self.high_lbl)
        bar_layout.addWidget(self.medium_lbl)
        bar_layout.addWidget(self.low_lbl)
        bar_layout.addStretch(1)
        bar_layout.addWidget(self.new_lbl)
        bar_layout.addWidget(self.investigating_lbl)
        bar_layout.addWidget(self.resolved_lbl)
        bar_layout.addWidget(self.false_positive_lbl)
        
        layout.addWidget(bar)
        
        return bar
    
    

    def _build_toolbar(self):
        """Build top toolbar."""
        layout = QHBoxLayout()
        
        self.create_btn = QPushButton("+ Create New Rule")
        self.create_btn.setObjectName("primaryButton")
        self.create_btn.clicked.connect(self._on_create_rule)
        
        layout.addWidget(self.create_btn)

        self.import_sigma_btn = QPushButton("Import Sigma")
        self.import_sigma_btn.clicked.connect(self._on_import_sigma)
        layout.addWidget(self.import_sigma_btn)

        layout.addStretch()
        
        return layout
    def _build_alerts_section(self, layout) -> QWidget:
        """Build the triggered alerts section with table, filtering, and search."""
        section = QFrame()
        section.setObjectName("alertsSection")
        section_layout = QVBoxLayout(section)
        section_layout.setContentsMargins(0, 0, 0, 0)
        section_layout.setSpacing(10)
        
        # Filter row
        filter_layout = QHBoxLayout()
        filter_layout.setContentsMargins(6, 6, 6, 6)
        filter_layout.setSpacing(8)
        
        # Severity filter
        filter_layout.addWidget(QLabel("Severity:"))
        self.alert_severity_filter = QComboBox()
        self.alert_severity_filter.addItems(["All", "critical", "high", "medium", "low"])
        self.alert_severity_filter.setCurrentIndex(0)
        self.alert_severity_filter.currentTextChanged.connect(self._on_alert_severity_changed)
        filter_layout.addWidget(self.alert_severity_filter)
        
        # Status filter
        filter_layout.addWidget(QLabel("Status:"))
        self.alert_status_filter = QComboBox()
        self.alert_status_filter.addItems(["All", "new", "acknowledged", "investigating", "resolved", "false_positive"])
        self.alert_status_filter.setCurrentIndex(0)
        self.alert_status_filter.currentTextChanged.connect(self._on_alert_status_changed)
        filter_layout.addWidget(self.alert_status_filter)
        
        # Time range filter
        filter_layout.addWidget(QLabel("Time range:"))
        self.alert_time_filter = QComboBox()
        self.alert_time_filter.addItems(["All Time", "24h", "7d", "30d"])
        self.alert_time_filter.setCurrentIndex(0)
        self.alert_time_filter.currentTextChanged.connect(self._on_alert_time_changed)
        filter_layout.addWidget(self.alert_time_filter)
        
        # Search box
        filter_layout.addWidget(QLabel("Search:"))
        self.alert_search_input = QLineEdit()
        self.alert_search_input.setPlaceholderText("Alert ID, name, IP, rule, MITRE...")
        self.alert_search_input.textChanged.connect(self._on_alert_search_changed)
        filter_layout.addWidget(self.alert_search_input)
        
        filter_layout.addStretch(1)
        section_layout.addLayout(filter_layout)
        
        # Alerts table
        self.alert_table = self._create_alerts_table()
        section_layout.addWidget(self.alert_table, 1)
        
        # Status bar for info messages
        self.alert_info_lbl = QLabel("")
        self.alert_info_lbl.setFont(theme_font(10))
        self.alert_info_lbl.setProperty("secondary", True)
        section_layout.addWidget(self.alert_info_lbl)
        
        layout.addWidget(section)
        
        return section
        """Build top toolbar."""
        layout = QHBoxLayout()
        
        self.create_btn = QPushButton("+ Create New Rule")
        self.create_btn.setObjectName("primaryButton")
        self.create_btn.clicked.connect(self._on_create_rule)
        
        layout.addWidget(self.create_btn)

        self.import_sigma_btn = QPushButton("Import Sigma")
        self.import_sigma_btn.clicked.connect(self._on_import_sigma)
        layout.addWidget(self.import_sigma_btn)

        layout.addStretch()
        
        return layout
    


    def _create_alerts_table(self):
        """Create alerts table view."""
        table = QTableView()
        table.setSelectionBehavior(table.SelectionBehavior.SelectRows)
        table.setSelectionMode(table.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        model = QStandardItemModel(0, 7)
        model.setHorizontalHeaderLabels(["Rule", "Severity", "Status", "Triggers", "Last Triggered", "Actions", "Success Rate"])
        table.setModel(model)
        return table
    def _create_rules_table(self):
        """Create a rules table view."""
        table = QTableView()
        table.setSelectionBehavior(table.SelectionBehavior.SelectRows)
        table.setSelectionMode(table.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        
        model = QStandardItemModel(0, 7)
        model.setHorizontalHeaderLabels([
            "Name",
            "Status",
            "Severity",
            "Triggers",
            "Actions",
            "Success Rate",
            "Last Triggered",
        ])
        table.setModel(model)
        
        # Set column widths
        table.setColumnWidth(0, 200)  # Name
        table.setColumnWidth(1, 80)   # Status
        table.setColumnWidth(2, 80)   # Severity
        table.setColumnWidth(3, 80)   # Triggers
        table.setColumnWidth(4, 80)   # Actions
        table.setColumnWidth(5, 100)  # Success Rate
        table.setColumnWidth(6, 150)  # Last Triggered
        
        # Context menu
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(
            lambda pos: self._on_table_context_menu(table, pos)
        )
        
        # Double-click to edit
        table.doubleClicked.connect(self._on_table_double_click)
        
        return table
    
    def _apply_styles(self):
        self.setStyleSheet(
            f"""
            QWidget {{ background-color: {COLORS['app_bg']}; color: {COLORS['text_primary']}; }}
            QTabWidget::pane {{ border: 1px solid {COLORS['border']}; border-radius: 8px; background-color: {COLORS['app_bg']}; }}
            QPushButton {{ min-height: 30px; }}
            """
        )

    def _refresh_data(self):
        """Refresh rule and alert data from database."""
        if not hasattr(self, "all_table") or self.alert_manager is None:
            return
        
        try:
            # Refresh rule data
            all_rules = self.alert_manager.get_all_rules()
            active_rules = [r for r in all_rules if r.enabled]
            disabled_rules = [r for r in all_rules if not r.enabled]
            
            self._populate_table(self.all_table, all_rules)
            self._populate_table(self.active_table, active_rules)
            self._populate_table(self.disabled_table, disabled_rules)
            
            # Refresh alert data
            self._refresh_alert_data()
        except Exception:
            # Avoid crashing during headless or early initialization
            pass
    
    def _refresh_alert_data(self):
        """Refresh the triggered alerts table and overview statistics."""
        try:
            # Get overview statistics
            overview = self.alert_manager.get_alert_overview()
            self._update_overview_stats(overview)
            
            # Get alerts with current filters
            alerts = self.alert_manager.get_alerts(
                severity=self._get_selected_severity(),
                status=self._get_selected_status(),
                limit=500,
                offset=0,
            )
            
            # Count for info
            count = self.alert_manager.count_alerts(
                severity=self._get_selected_severity(),
                status=self._get_selected_status(),
            )
            
            self._populate_alerts_table(alerts)
            self.alert_info_lbl.setText(f"Showing {len(alerts)} of {count} alerts")
        except Exception as e:
            logger.error(f"Failed to refresh alert data: {e}")
            self.alert_info_lbl.setText(f"Error loading alerts: {str(e)}")
            self.alert_table.setModel(QStandardItemModel(0, 12))
    
    def _update_overview_stats(self, overview: dict):
        """Update the overview statistics bar."""
        self.total_lbl.setText(f"Total: {overview.get('total', 0)}")
        self.critical_lbl.setText(f"Critical: {overview.get('critical', 0)}")
        self.high_lbl.setText(f"High: {overview.get('high', 0)}")
        self.medium_lbl.setText(f"Medium: {overview.get('medium', 0)}")
        self.low_lbl.setText(f"Low: {overview.get('low', 0)}")
        self.new_lbl.setText(f"New: {overview.get('new', 0)}")
        self.investigating_lbl.setText(f"Investigating: {overview.get('investigating', 0)}")
        self.resolved_lbl.setText(f"Resolved: {overview.get('resolved', 0)}")
        self.false_positive_lbl.setText(f"False Positive: {overview.get('false_positive', 0)}")
    
    def _get_selected_severity(self) -> Optional[str]:
        """Get the currently selected severity filter."""
        severity = self.alert_severity_filter.currentText()
        if severity == "All":
            return None
        return severity
    
    def _get_selected_status(self) -> Optional[str]:
        """Get the currently selected status filter."""
        status = self.alert_status_filter.currentText()
        if status == "All":
            return None
        return status
    
    def _populate_table(self, table, rules):
        """Populate a table with rules."""
        model = QStandardItemModel(len(rules), 7)
        model.setHorizontalHeaderLabels([
            "Name",
            "Status",
            "Severity",
            "Triggers",
            "Actions",
            "Success Rate",
            "Last Triggered",
        ])
        
        for row, rule in enumerate(rules):
            stats = self.alert_manager.get_statistics(rule.id)
            
            # Name
            name_item = QStandardItem(rule.name)
            name_item.setData(rule.id, Qt.ItemDataRole.UserRole)  # Store rule_id
            model.setItem(row, 0, name_item)
            
            # Status
            status = "Active" if rule.enabled else "Disabled"
            status_item = QStandardItem(status)
            model.setItem(row, 1, status_item)
            
            # Severity
            severity_item = QStandardItem(rule.severity.value)
            model.setItem(row, 2, severity_item)
            
            # Trigger Count
            triggers = str(stats.trigger_count) if stats else "0"
            trigger_item = QStandardItem(triggers)
            model.setItem(row, 3, trigger_item)
            
            # Action Count
            actions = str(stats.action_count) if stats else "0"
            action_item = QStandardItem(actions)
            model.setItem(row, 4, action_item)
            
            # Success Rate
            if stats and stats.success_rate is not None:
                success_rate = f"{stats.success_rate:.1f}%"
            else:
                success_rate = "N/A"
            success_item = QStandardItem(success_rate)
            model.setItem(row, 5, success_item)
            
            # Last Triggered
            if stats and stats.last_triggered_at:
                try:
                    dt = datetime.fromisoformat(stats.last_triggered_at)
                    last_triggered = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    last_triggered = stats.last_triggered_at
            else:
                last_triggered = "Never"
            last_item = QStandardItem(last_triggered)
            model.setItem(row, 6, last_item)
        
        table.setModel(model)
    
    def _populate_alerts_table(self, alerts: List[dict]):
        """Populate the alerts table with triggered alert data."""
        model = QStandardItemModel(len(alerts), 12)
        model.setHorizontalHeaderLabels([
            "Timestamp",
            "Alert ID",
            "Alert Name",
            "Severity",
            "Status",
            "Source IP",
            "Destination IP",
            "Affected User",
            "Host/Device",
            "Detection Rule",
            "MITRE Technique",
            "Correlation Group",
        ])
        
        for row, alert in enumerate(alerts):
            # Timestamp
            ts = alert.get("triggered_at", "")[:19].replace("T", " ") if alert.get("triggered_at") else ""
            ts_item = QStandardItem(ts)
            model.setItem(row, 0, ts_item)
            
            # Alert ID
            alert_id = alert.get("id", "")
            alert_id_item = QStandardItem(alert_id)
            alert_id_item.setData(alert_id, Qt.ItemDataRole.UserRole)
            model.setItem(row, 1, alert_id_item)
            
            # Alert Name (from rule name)
            rule_name = alert.get("rule_name", "") or ""
            name_item = QStandardItem(rule_name)
            model.setItem(row, 2, name_item)
            
            # Severity
            severity = alert.get("severity", "") or ""
            sev_item = QStandardItem(severity)
            model.setItem(row, 3, sev_item)
            
            # Status
            status = alert.get("lifecycle_status", "") or "new"
            status_item = QStandardItem(status.upper())
            model.setItem(row, 4, status_item)
            
            # Source IP
            source_ip = alert.get("source_ip", "") or ""
            src_ip_item = QStandardItem(source_ip)
            model.setItem(row, 5, src_ip_item)
            
            # Destination IP
            dest_ip = alert.get("destination_ip", "") or ""
            dest_ip_item = QStandardItem(dest_ip)
            model.setItem(row, 6, dest_ip_item)
            
            # Affected User
            user = alert.get("user", "") or ""
            user_item = QStandardItem(user)
            model.setItem(row, 7, user_item)
            
            # Host/Device
            host = alert.get("hostname", "") or alert.get("host", "") or ""
            host_item = QStandardItem(host)
            model.setItem(row, 8, host_item)
            
            # Detection Rule (rule name)
            rule_display = alert.get("rule_name", "") or ""
            rule_item = QStandardItem(rule_display)
            model.setItem(row, 9, rule_item)
            
            # MITRE Technique
            mitre = alert.get("mitre_technique", "") or ""
            mitre_item = QStandardItem(mitre if mitre else "N/A")
            model.setItem(row, 10, mitre_item)
            
            # Correlation Group with related count
            group_key = alert.get("group_key", "") or ""
            group_count = 0
            if group_key:
                try:
                    related = self.alert_manager.get_alerts(group_key=group_key, limit=100, offset=0)
                    group_count = len(related)
                except Exception:
                    group_count = 0
            group_display = f"{group_key} ({group_count} related)" if group_key else "None"
            group_item = QStandardItem(group_display)
            model.setItem(row, 11, group_item)
        
        self.alert_table.setModel(model)
        
        # Adjust column widths
        self.alert_table.setColumnWidth(0, 180)
        self.alert_table.setColumnWidth(1, 100)
        self.alert_table.setColumnWidth(2, 220)
        self.alert_table.setColumnWidth(3, 80)
        self.alert_table.setColumnWidth(4, 100)
        self.alert_table.setColumnWidth(5, 120)
        self.alert_table.setColumnWidth(6, 120)
        self.alert_table.setColumnWidth(7, 130)
        self.alert_table.setColumnWidth(8, 150)
        self.alert_table.setColumnWidth(9, 200)
        self.alert_table.setColumnWidth(10, 130)
        self.alert_table.setColumnWidth(11, 130)
    
    def _on_alert_severity_changed(self):
        """Handle severity filter change for alerts."""
        self._refresh_alert_data()
    
    def _on_alert_status_changed(self):
        """Handle status filter change for alerts."""
        self._refresh_alert_data()
    
    def _on_alert_time_changed(self):
        """Handle time range filter change for alerts."""
        # Time range filtering would be implemented via the API;
        # for now, just refresh with current filters
        self._refresh_alert_data()
    
    def _on_alert_search_changed(self):
        """Handle search input change for alerts."""
        self._refresh_alert_data()
    
    def _on_alert_double_click(self, index):
        """Handle double-click on alert to open detail view."""
        model = self.alert_table.model()
        if model is None:
            return
        
        alert_id = model.item(index.row(), 1).data(Qt.ItemDataRole.UserRole)
        if not alert_id:
            return
        
        self._open_alert_detail(alert_id)
    
    def _on_alert_context_menu(self, table, pos):
        """Handle right-click context menu on alerts table."""
        index = table.indexAt(pos)
        if not index.isValid():
            return
        
        model = table.model()
        if model is None:
            return
        
        alert_id = model.item(index.row(), 1).data(Qt.ItemDataRole.UserRole)
        if not alert_id:
            return
        
        alert = self.alert_manager.get_rule(alert_id)  # Get rule for now
        # Actually we need to get the alert history record
        # For now, show menu with available actions
        menu = QMenu()
        
        view_action = menu.addAction("View Details")
        view_action.triggered.connect(lambda: self._open_alert_detail(alert_id))
        
        menu.addSeparator()
        
        # Status change actions
        status_menu = QMenu("Change Status", menu)
        new_action = status_menu.addAction("New")
        acknowledged_action = status_menu.addAction("Acknowledged")
        investigating_action = status_menu.addAction("Investigating")
        resolved_action = status_menu.addAction("Resolved")
        false_positive_action = status_menu.addAction("False Positive")
        escalated_action = status_menu.addAction("Escalated")
        
        # Check current status to check appropriate default
        current_status = model.item(index.row(), 4).text()  # Status column
        
        menu.addSeparator()
        
        # Analyst actions
        assign_action = menu.addAction("Assign to Me")
        note_action = menu.addAction("Add Investigation Note...")
        playbook_action = menu.addAction("Run Associated Playbook")
        
        menu.addSeparator()
        
        export_action = menu.addAction("Export Alert")
        
        action = menu.exec(table.mapToGlobal(pos))
        
        if action == view_action:
            self._open_alert_detail(alert_id)
        elif action == new_action:
            self.alert_manager.update_alert_status(alert_id, AlertLifecycleStatus.NEW)
            self._refresh_alert_data()
        elif action == acknowledged_action:
            self.alert_manager.update_alert_status(alert_id, AlertLifecycleStatus.ACKNOWLEDGED)
            self._refresh_alert_data()
        elif action == investigating_action:
            self.alert_manager.update_alert_status(alert_id, AlertLifecycleStatus.INVESTIGATING)
            self._refresh_alert_data()
        elif action == resolved_action:
            self.alert_manager.update_alert_status(alert_id, AlertLifecycleStatus.RESOLVED)
            self._refresh_alert_data()
        elif action == false_positive_action:
            self.alert_manager.update_alert_status(alert_id, AlertLifecycleStatus.FALSE_POSITIVE)
            self._refresh_alert_data()
        elif action == escalated_action:
            self.alert_manager.update_alert_status(alert_id, AlertLifecycleStatus.ESCALATED)
            self._refresh_alert_data()
        elif action == assign_action:
            self.alert_manager.update_alert_status(alert_id, alert.get("lifecycle_status", AlertLifecycleStatus.NEW), assignee="current_analyst")
            # Note: assign primarily sets assignee; we'll just show a message
            QMessageBox.information(self, "Assign", "Alert assigned to current analyst.")
        elif action == note_action:
            self._show_add_note_dialog(alert_id)
        elif action == playbook_action:
            self._run_playbook_for_alert(alert_id)
    
    def _open_alert_detail(self, alert_id: str):
        """Open the detail view for a specific alert."""
        try:
            # Get the alert history record with rule data
            alerts = self.alert_manager.get_alerts(rule_id=alert_id, limit=1, offset=0)
            if not alerts:
                QMessageBox.warning(self, "Alert Not Found", f"Alert {alert_id} not found.")
                return
            
            alert = alerts[0]
            
            # Fetch the associated event for network context
            event_id = alert.get("event_id", "")
            event = None
            if event_id:
                try:
                    ev = self.alert_manager.conn.execute(
                        f"SELECT {self._row_select()} FROM events WHERE id = ?",
                        (event_id,)
                    ).fetchone()
                    # Actually let me use the proper method
                    from src.database import CyberionDB
                    # We have the connection via self.alert_manager.conn
                    event = self._fetch_event(int(event_id)) if event_id else None
                except Exception:
                    event = None
            
            # Build detail dialog
            detail = AlertDetailDialog(self, alert, event, self.alert_manager)
            detail.show_detail.connect(self._on_detail_action)
            detail.exec_()
        except Exception as e:
            logger.error(f"Failed to open alert detail: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to open alert detail: {str(e)}")
    
    def _fetch_event(self, event_id: int) -> Optional[dict]:
        """Fetch an event from the database by ID."""
        from src.database import CyberionDB
        # Use the alert manager's connection
        with self._lock if hasattr(self, '_lock') else threading.RLock():
            cur = self.alert_manager.conn.cursor()
            cur.execute(f"SELECT {', '.join(CyberionDB._ROW_COLUMNS)} FROM events WHERE id = ?", (event_id,))
            row = cur.fetchone()
        if row:
            return dict(zip(CyberionDB._ROW_COLUMNS, row))
        return None
    
    def _show_add_note_dialog(self, alert_id: str):
        """Show dialog to add an investigation note."""
        from .alert_note_dialog import AlertNoteDialog
        dialog = AlertNoteDialog(alert_id, self.alert_manager, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            note = dialog.get_note()
            # The note would be added to the history record
            # For now, just refresh
            self._refresh_alert_data()
    
    def _run_playbook_for_alert(self, alert_id: str):
        """Run the associated playbook for an alert."""
        # Check if the alert rule has a playbook/action config
        alert = self.alert_manager.get_alerts(rule_id=alert_id, limit=1, offset=0)
        if not alert:
            return
        
        # In a full implementation, this would check the rule's action config
        # for associated playbooks and execute them
        QMessageBox.information(self, "Playbook", 
            "Playbook execution would run here for alert: " + alert[0].get("rule_name", alert_id))
    
    class AlertDetailDialog(QDialog):
        """Dialog showing detailed information for a triggered alert."""
        
        def __init__(self, parent, alert: dict, event: Optional[dict], alert_manager: AlertManager):
            super().__init__(parent)
            self.alert_manager = alert_manager
            self.setWindowTitle("Alert Detail")
            self.resize(800, 600)
            
            layout = QVBoxLayout(self)
            
            # Alert information section
            info_group = QFrame()
            info_group.setObjectName("infoGroup")
            info_layout = QVBoxLayout(info_group)
            
            # Build alert info from the alert dict and associated rule
            rule_id = alert.get("rule_id", "")
            rule = None
            if rule_id:
                rule = alert_manager.get_rule(rule_id)
            
            # Alert ID and timestamp
            info_rows = []
            info_rows.append(("Alert ID", alert.get("id", "")))
            info_rows.append(("Triggered At", alert.get("triggered_at", "")[:16] or "N/A"))
            if rule:
                info_rows.append(("Rule Name", rule.name))
            info_rows.append(("Severity", alert.get("severity", "") or "N/A"))
            info_rows.append(("Status", alert.get("lifecycle_status", "new").upper()))
            info_rows.append(("Assignee", alert.get("assignee", "") or "Unassigned"))
            
            info_grid = QGridLayout()
            for i, (key, value) in enumerate(info_rows):
                key_lbl = QLabel(key + ":")
                key_lbl.setFont(theme_font(10, QFont.DemiBold))
                key_lbl.setStyleSheet("color: #9aa0a6;")
                val_lbl = QLabel(str(value) if value else "N/A")
                val_lbl.setWordWrap(True)
                info_grid.addWidget(key_lbl, i, 0)
                info_grid.addWidget(val_lbl, i, 1)
            
            # Set column widths for grid
            info_grid.setColumnStretch(0, 1)
            info_grid.setColumnStretch(1, 2)
            info_layout.addLayout(info_grid)
            
            # Network context section
            net_group = QFrame()
            net_group.setObjectName("netGroup")
            net_layout = QVBoxLayout(net_group)
            
            if event:
                net_fields = [
                    ("Source IP", event.get("ip_address") or event.get("source", "")),
                    ("Destination IP", event.get("destination_ip", "") or ""),
                    ("Source Port", str(event.get("source_port", "")) or "N/A"),
                    ("Destination Port", str(event.get("destination_port", "")) or "N/A"),
                    ("Protocol", str(event.get("protocol", "")) or "N/A"),
                ]
                for i, (label, value) in enumerate(net_fields):
                    row = QHBoxLayout()
                    row.addWidget(QLabel(label + ":"))
                    row.addWidget(QLabel(str(value) if value else "N/A"))
                    net_layout.addLayout(row)
                
                # Process context
                proc_fields = [
                    ("Hostname", event.get("hostname") or ""),
                    ("Username", event.get("user") or ""),
                    ("Process", event.get("process_name") or event.get("process", "")),
                    ("PID", str(event.get("pid", "")) or "N/A"),
                    ("Parent PID", str(event.get("ppid", "")) or "N/A"),
                    ("Command Line", event.get("command") or ""),
                    ("File Path", event.get("filepath") or ""),
                ]
                for i, (label, value) in enumerate(proc_fields):
                    row = QHBoxLayout()
                    row.addWidget(QLabel(label + ":"))
                    row.addWidget(QLabel(str(value) if value else "N/A"))
                    net_layout.addLayout(row)
            else:
                net_layout.addWidget(QLabel("No associated event data available"))
            
            # MITRE context section
            mitre_group = QFrame()
            mitre_group.setObjectName("mitreGroup")
            mitre_layout = QVBoxLayout(mitre_group)
            
            # Determine MITRE technique from rule or event
            mitre_technique = alert.get("mitre_technique", "") or ""
            if not mitre_technique and rule:
                # Try to extract from generated_kql or description
                mitre_technique = rule.generated_kql if rule else ""
            
            mitre_fields = [
                ("Tactic", mitre_technique.split(".")[0] if "." in mitre_technique else ""),
                ("Technique ID", mitre_technique.split()[-1] if mitre_technique else ""),
                ("Technique Name", mitre_technique or "N/A"),
            ]
            for i, (label, value) in enumerate(mitre_fields):
                row = QHBoxLayout()
                row.addWidget(QLabel(label + ":"))
                row.addWidget(QLabel(str(value) if value else "N/A"))
                mitre_layout.addLayout(row)
            
            # Correlation context section
            corr_group = QFrame()
            corr_group.setObjectName("corrGroup")
            corr_layout = QVBoxLayout(corr_group)
            
            group_key = alert.get("group_key", "") or ""
            related_count = 0
            if group_key:
                # Count related alerts with same group_key
                related = self.alert_manager.get_alerts(group_key=group_key, limit=100, offset=0)
                related_count = len(related)
            
            corr_fields = [
                ("Correlation Group ID", group_key or "None"),
                ("Related Alerts", str(related_count)),
            ]
            for i, (label, value) in enumerate(corr_fields):
                row = QHBoxLayout()
                row.addWidget(QLabel(label + ":"))
                row.addWidget(QLabel(str(value) if value else "N/A"))
                corr_layout.addLayout(row)
            
            # Add investigation note button
            note_btn = QPushButton("Add Investigation Note")
            note_btn.clicked.connect(lambda: self._show_add_note_dialog(alert.get("id", "")))
            corr_layout.addWidget(note_btn)
            
            # Close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(self.accept)
            
            # Main layout
            layout.addWidget(info_group, 1)
            layout.addWidget(net_group)
            layout.addWidget(mitre_group)
            layout.addWidget(corr_group)
            layout.addWidget(close_btn)
            
            # Style the frames
            self.setStyleSheet("""
                QFrame#infoGroup { border: 1px solid #27313D; border-radius: 4px; margin: 4px; padding: 8px; }
                QFrame#netGroup { border: 1px solid #27313D; border-radius: 4px; margin: 4px; padding: 8px; }
                QFrame#mitreGroup { border: 1px solid #27313D; border-radius: 4px; margin: 4px; padding: 8px; }
                QFrame#corrGroup { border: 1px solid #27313D; border-radius: 4px; margin: 4px; padding: 8px; }
            """)
        
        def _show_add_note_dialog(self, alert_id: str):
            """Show dialog to add an investigation note."""
            from .alert_note_dialog import AlertNoteDialog
            dialog = AlertNoteDialog(alert_id, self.alert_manager, parent=self)
            if dialog.exec_() == QDialog.Accepted:
                note = dialog.get_note()
                self._refresh_alert_data()
    def _on_tab_changed(self, index):
        """Handle tab change."""
        self._refresh_data()
    
    def _on_table_double_click(self, index):
        """Handle double-click on table row to edit."""
        table = self.tabs.currentWidget()
        model = table.model()
        if model is None:
            return
        
        rule_id = model.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
        rule = self.alert_manager.get_rule(rule_id)
        
        if rule:
            self._edit_rule(rule)
    
    def _on_table_context_menu(self, table, pos):
        """Handle right-click context menu on table."""
        index = table.indexAt(pos)
        if not index.isValid():
            return
        
        model = table.model()
        if model is None:
            return
        
        rule_id = model.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
        rule = self.alert_manager.get_rule(rule_id)
        
        if not rule:
            return
        
        menu = QMenu()
        
        # Edit action
        edit_action = menu.addAction("Edit")
        edit_action.triggered.connect(lambda: self._edit_rule(rule))
        
        menu.addSeparator()
        
        # Enable/Disable action
        if rule.enabled:
            disable_action = menu.addAction("Disable")
            disable_action.triggered.connect(lambda: self._disable_rule(rule))
        else:
            enable_action = menu.addAction("Enable")
            enable_action.triggered.connect(lambda: self._enable_rule(rule))
        
        menu.addSeparator()
        
        # Delete action
        delete_action = menu.addAction("Delete")
        delete_action.triggered.connect(lambda: self._delete_rule(rule))
        
        menu.popup(table.mapToGlobal(pos))
    
    def _edit_rule(self, rule: AlertRule):
        """Edit an existing rule."""
        editor = AlertRuleEditor(self.alert_manager, rule)
        result = editor.exec()
        
        if result == editor.Accepted:
            try:
                updated = editor.get_rule()
                self.alert_manager.update_rule(updated)
                self.rule_updated.emit(updated)
                self._refresh_data()
                logger.info(f"Updated alert rule: {updated.name}")
            except ValueError as e:
                QMessageBox.warning(self, "Validation", str(e))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to update rule: {e}")
    
    def _enable_rule(self, rule: AlertRule):
        """Enable a disabled rule."""
        try:
            self.alert_manager.enable_rule(rule.id)
            self.rule_enabled.emit(rule.id)
            self._refresh_data()
            logger.info(f"Enabled alert rule: {rule.name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to enable rule: {e}")
    
    def _disable_rule(self, rule: AlertRule):
        """Disable an enabled rule."""
        try:
            self.alert_manager.disable_rule(rule.id)
            self.rule_disabled.emit(rule.id)
            self._refresh_data()
            logger.info(f"Disabled alert rule: {rule.name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to disable rule: {e}")
    
    def _delete_rule(self, rule: AlertRule):
        """Delete a rule with confirmation."""
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete the alert rule '{rule.name}'?\n\n"
            "This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                rule_id = rule.id
                self.alert_manager.delete_rule(rule_id)
                self.rule_deleted.emit(rule_id)
                self._refresh_data()
                logger.info(f"Deleted alert rule: {rule.name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete rule: {e}")

    def _on_import_sigma(self):
        """Import Sigma YAML rules and convert into local alert rules."""
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Sigma Rule Files",
            "",
            "YAML Files (*.yml *.yaml)",
        )
        if not paths:
            return

        validation_results = []
        for path in paths:
            try:
                validation_results.extend(self.sigma_importer.validate_file(path))
            except Exception as exc:
                QMessageBox.critical(self, "Sigma Validation Error", f"Failed to validate {path}: {exc}")
                return

        preview_text = self._format_sigma_results(validation_results, header_prefix="Validation")
        preview = QDialog(self)
        preview.setWindowTitle("Sigma Conversion Preview")
        preview.resize(860, 560)
        p_layout = QVBoxLayout(preview)
        box = QTextEdit()
        box.setReadOnly(True)
        box.setPlainText(preview_text)
        p_layout.addWidget(box, 1)

        action_row = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(preview.reject)
        action_row.addWidget(cancel_btn)

        update_existing = False

        def _import_new_only():
            nonlocal update_existing
            update_existing = False
            preview.accept()

        def _import_update_existing():
            nonlocal update_existing
            update_existing = True
            preview.accept()

        import_btn = QPushButton("Import New")
        import_btn.setObjectName("primaryButton")
        import_btn.clicked.connect(_import_new_only)
        action_row.addWidget(import_btn)

        update_btn = QPushButton("Import / Update Existing")
        update_btn.clicked.connect(_import_update_existing)
        action_row.addWidget(update_btn)

        p_layout.addLayout(action_row)

        if preview.exec_() != QDialog.Accepted:
            return

        results = []
        for path in paths:
            try:
                results.extend(self.sigma_importer.import_file(path, update_existing=update_existing))
            except Exception as exc:
                QMessageBox.critical(self, "Sigma Import Error", f"Failed to import {path}: {exc}")
                return

        self._show_sigma_import_summary(results)
        self._refresh_data()

    def _format_sigma_results(self, results, header_prefix: str = "Summary") -> str:
        imported = 0
        failed = 0
        warnings = 0
        lines = []
        for result in results:
            if result.errors:
                failed += 1
            else:
                imported += 1
            if result.warnings:
                warnings += 1

            lines.append(
                f"[{result.status.value}] {result.sigma_title or 'Untitled'} "
                f"(sigma_id={result.sigma_id or 'n/a'}, local_rule_id={result.local_rule_id or 'n/a'})"
            )
            if result.local_rule is not None:
                lines.append(f"  Local rule preview: name={result.local_rule.name}, severity={result.local_rule.severity.value}")
            for msg in result.errors:
                lines.append(f"  ERROR: {msg}")
            for msg in result.warnings:
                lines.append(f"  WARNING: {msg}")

        header = f"{header_prefix} results -> Ready: {imported}  Invalid/Unsupported: {failed}  With warnings: {warnings}"
        return header + "\n\n" + "\n".join(lines)

    def _show_sigma_import_summary(self, results):
        text = self._format_sigma_results(results, header_prefix="Import")

        dialog = QDialog(self)
        dialog.setWindowTitle("Sigma Import Summary")
        dialog.resize(860, 540)
        layout = QVBoxLayout(dialog)
        box = QTextEdit()
        box.setReadOnly(True)
        box.setPlainText(text)
        layout.addWidget(box, 1)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(close_btn)
        layout.addLayout(row)
        dialog.exec_()
    


    def _on_create_rule(self):
        """Handle create new rule button."""
        editor = AlertRuleEditor(self.alert_manager)
        result = editor.exec()
        
        if result == editor.Accepted:
            try:
                rule = editor.get_rule()
                created = self.alert_manager.create_rule(rule)
                self.rule_created.emit(created)
                self._refresh_data()
                logger.info(f"Created alert rule: {created.name}")
            except ValueError as e:
                QMessageBox.warning(self, "Validation", str(e))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create rule: {e}")
    def closeEvent(self, event):
        """Clean up on close."""
        self.refresh_timer.stop()
        super().closeEvent(event)


__all__ = ["AlertsPage"]
