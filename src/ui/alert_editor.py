"""Alert rule editor dialog for creating and editing alert rules."""

from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit,
    QComboBox, QPushButton, QGroupBox, QFormLayout, QMessageBox,
    QSpinBox, QCheckBox, QTabWidget
)

from ..alerts import (
    AlertRule, AlertSeverity, ActionType, ActionConfig,
    AlertHistoryRecord, ActionStatus
)
from ..query.query_model import QueryDefinition
from ..query.model_to_kql import query_definition_to_kql
from .visual_query_builder import VisualQueryBuilder


class AlertRuleEditor(QDialog):
    """Dialog for creating or editing an alert rule."""
    
    def __init__(
        self,
        alert_manager,
        rule: Optional[AlertRule] = None,
        parent=None
    ):
        """Initialize the editor.
        
        Args:
            alert_manager: Alert manager for testing rules
            rule: Existing rule to edit (None for new rule)
            parent: Parent widget
        """
        super().__init__(parent)
        self.alert_manager = alert_manager
        self.rule = rule
        self.setWindowTitle(
            "Edit Alert Rule" if rule else "Create New Alert Rule"
        )
        self.setMinimumWidth(800)
        self.setMinimumHeight(600)
        
        self._build_ui()
        if rule:
            self._populate_from_rule(rule)
    
    def _build_ui(self):
        """Build the dialog UI."""
        layout = QVBoxLayout()
        
        # Basic info section
        basic_group = QGroupBox("Basic Information")
        basic_layout = QFormLayout()
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g., 'Detect PowerShell Execution'")
        basic_layout.addRow("Rule Name:", self.name_input)
        
        self.desc_input = QTextEdit()
        self.desc_input.setPlaceholderText("Describe the rule's purpose")
        self.desc_input.setMaximumHeight(80)
        basic_layout.addRow("Description:", self.desc_input)
        
        self.severity_combo = QComboBox()
        for severity in AlertSeverity:
            self.severity_combo.addItem(severity.value, severity)
        self.severity_combo.setCurrentIndex(1)  # Default to MEDIUM
        basic_layout.addRow("Severity:", self.severity_combo)
        
        basic_group.setLayout(basic_layout)
        layout.addWidget(basic_group)
        
        # Tabs for query and action
        tabs = QTabWidget()
        
        # Query tab
        query_group = self._build_query_section()
        tabs.addTab(query_group, "Query")
        
        # Action tab
        action_group = self._build_action_section()
        tabs.addTab(action_group, "Action")
        
        layout.addWidget(tabs)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.test_btn = QPushButton("Test Rule")
        self.test_btn.clicked.connect(self._on_test_rule)
        button_layout.addWidget(self.test_btn)
        
        button_layout.addStretch()
        
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.save_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def _build_query_section(self):
        """Build the query section."""
        group = QGroupBox("Alert Query")
        layout = QVBoxLayout()
        
        # Visual query builder
        self.visual_builder = VisualQueryBuilder()
        layout.addWidget(self.visual_builder)
        
        group.setLayout(layout)
        return group
    
    def _build_action_section(self):
        """Build the action section."""
        group = QGroupBox("Action Configuration")
        layout = QFormLayout()
        
        # Action type
        self.action_type_combo = QComboBox()
        for action_type in ActionType:
            self.action_type_combo.addItem(action_type.value, action_type)
        self.action_type_combo.currentIndexChanged.connect(
            self._on_action_type_changed
        )
        layout.addRow("Action Type:", self.action_type_combo)
        
        # Action-specific config
        self.action_config_layout = QFormLayout()
        layout.addRow("Configuration:", self.action_config_layout)
        
        self._on_action_type_changed()
        
        group.setLayout(layout)
        return group
    
    def _on_action_type_changed(self):
        """Handle action type change."""
        # Clear existing config
        while self.action_config_layout.rowCount() > 0:
            self.action_config_layout.removeRow(0)
        
        action_type = self.action_type_combo.currentData()
        
        if action_type == ActionType.LOG_ALERT:
            label = QLabel("Alerts will be logged to the application log")
            self.action_config_layout.addRow(label)
        
        elif action_type == ActionType.CREATE_EVENT:
            label = QLabel("Alert events will be created in the event database")
            self.action_config_layout.addRow(label)
        
        elif action_type == ActionType.DESKTOP_NOTIFICATION:
            self.notif_title = QLineEdit()
            self.notif_title.setText("Cyberion Alert")
            self.action_config_layout.addRow("Title:", self.notif_title)
            
            self.notif_message = QLineEdit()
            self.notif_message.setText("Alert triggered: {rule_name}")
            self.action_config_layout.addRow("Message:", self.notif_message)
    
    def _on_test_rule(self):
        """Test the rule against the database."""
        if not self.name_input.text().strip():
            QMessageBox.warning(self, "Validation", "Please enter a rule name")
            return
        
        try:
            query_def = self.visual_builder.get_query_definition()
            kql = query_definition_to_kql(query_def)
            
            # Execute query to test it
            from ..query import CyberionQueryEngine
            from ..database import CyberionDB
            
            # Get default database
            db = CyberionDB()
            engine = CyberionQueryEngine(db)
            
            result = engine.execute(kql)
            
            QMessageBox.information(
                self,
                "Test Result",
                f"Query executed successfully!\n\n"
                f"Query: {kql}\n\n"
                f"Rows matched: {len(result.rows)}\n"
                f"Execution time: {result.execution_time_ms:.2f}ms"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Test Failed",
                f"Error executing test query: {e}"
            )
    
    def _populate_from_rule(self, rule: AlertRule):
        """Populate form from existing rule."""
        self.name_input.setText(rule.name)
        self.desc_input.setPlainText(rule.description or "")
        
        # Set severity
        for i in range(self.severity_combo.count()):
            if self.severity_combo.itemData(i) == rule.severity:
                self.severity_combo.setCurrentIndex(i)
                break
        
        # Set action type
        for i in range(self.action_type_combo.count()):
            if self.action_type_combo.itemData(i) == rule.action.action_type:
                self.action_type_combo.setCurrentIndex(i)
                break
        
        # Set query
        self.visual_builder.set_query_definition(rule.query_definition)
        
        # Set action config
        if rule.action.action_type == ActionType.DESKTOP_NOTIFICATION:
            config = rule.action.config
            self.notif_title.setText(config.get("title", "Cyberion Alert"))
            self.notif_message.setText(config.get("message", "Alert triggered"))
    
    def get_rule(self) -> AlertRule:
        """Get the configured rule."""
        if not self.name_input.text().strip():
            raise ValueError("Rule name is required")
        
        query_def = self.visual_builder.get_query_definition()
        kql = query_definition_to_kql(query_def)
        
        # Build action config
        action_type = self.action_type_combo.currentData()
        action_config = {}
        
        if action_type == ActionType.DESKTOP_NOTIFICATION:
            action_config = {
                "title": self.notif_title.text(),
                "message": self.notif_message.text(),
            }
        
        rule = AlertRule(
            id=self.rule.id if self.rule else None,
            name=self.name_input.text().strip(),
            description=self.desc_input.toPlainText().strip(),
            severity=self.severity_combo.currentData(),
            query_definition=query_def,
            generated_kql=kql,
            action=ActionConfig(action_type, action_config),
            enabled=self.rule.enabled if self.rule else True,
            created_at=self.rule.created_at if self.rule else None,
            updated_at=self.rule.updated_at if self.rule else None,
        )
        
        return rule


__all__ = ["AlertRuleEditor"]
