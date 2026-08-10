"""Alert management UI page for Cyberion ThreatHunter.

Provides interface for viewing, creating, editing, and managing alert rules.
"""

import logging
from datetime import datetime
from typing import Optional

from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableView,
    QTabWidget, QMessageBox, QMenu, QApplication, QLabel
)

from ..alerts import AlertRule, AlertSeverity
from ..alerts.manager import AlertManager
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
        
        title = QLabel("Alert Rules")
        title.setFont(theme_font(18, QFont.DemiBold))
        layout.addWidget(title)
        
        # Top toolbar
        toolbar = self._build_toolbar()
        layout.addLayout(toolbar)
        
        # Tabs for filtering
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
        
        self.setLayout(layout)
    
    def _build_toolbar(self):
        """Build top toolbar."""
        layout = QHBoxLayout()
        
        self.create_btn = QPushButton("+ Create New Rule")
        self.create_btn.setObjectName("primaryButton")
        self.create_btn.clicked.connect(self._on_create_rule)
        
        layout.addWidget(self.create_btn)
        layout.addStretch()
        
        return layout
    
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
        """Refresh rule data from database."""
        if not hasattr(self, "all_table") or self.alert_manager is None:
            return
        
        try:
            all_rules = self.alert_manager.get_all_rules()
            active_rules = [r for r in all_rules if r.enabled]
            disabled_rules = [r for r in all_rules if not r.enabled]
            
            self._populate_table(self.all_table, all_rules)
            self._populate_table(self.active_table, active_rules)
            self._populate_table(self.disabled_table, disabled_rules)
        except Exception:
            # Avoid crashing during headless or early initialization
            pass
    
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
    
    def _on_create_rule(self):
        """Handle create new rule button."""
        editor = AlertRuleEditor(self.alert_manager)
        result = editor.exec()
        
        if result == editor.Accepted:
            rule = editor.get_rule()
            try:
                created = self.alert_manager.create_rule(rule)
                self.rule_created.emit(created)
                self._refresh_data()
                logger.info(f"Created alert rule: {created.name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create rule: {e}")
    
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
            updated = editor.get_rule()
            try:
                self.alert_manager.update_rule(updated)
                self.rule_updated.emit(updated)
                self._refresh_data()
                logger.info(f"Updated alert rule: {updated.name}")
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
    
    def closeEvent(self, event):
        """Clean up on close."""
        self.refresh_timer.stop()
        super().closeEvent(event)


__all__ = ["AlertsPage"]
