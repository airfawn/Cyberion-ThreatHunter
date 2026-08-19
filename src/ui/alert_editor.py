"""Alert rule editor dialog for creating and editing alert rules."""

import getpass
import os
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit,
    QComboBox, QPushButton, QGroupBox, QFormLayout, QMessageBox,
    QSpinBox, QCheckBox, QTabWidget, QRadioButton, QButtonGroup, QListWidget
)

from ..alerts import (
    AlertRule, AlertSeverity, ActionType, ActionConfig,
    AlertHistoryRecord, ActionStatus, DetectionType, ThresholdConfig, TimeUnit
)
from ..query.query_model import QueryDefinition, FIELD_DEFINITIONS
from ..query.model_to_kql import query_definition_to_kql
from .visual_query_builder import VisualQueryBuilder
from .theme import COLORS, theme_font


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
        self._apply_styles()
        if rule:
            self._populate_from_rule(rule)
    
    def _build_ui(self):
        """Build the dialog UI."""
        layout = QVBoxLayout()
        
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

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

        self.creator_input = QLineEdit()
        self.creator_input.setPlaceholderText("Rule creator name")
        self.creator_input.setText(os.environ.get("THREATHUNTER_USER") or os.environ.get("USER") or getpass.getuser())
        basic_layout.addRow("Rule Creator:", self.creator_input)

        self.detection_mode_group = QButtonGroup(self)
        self.single_event_radio = QRadioButton("Single Event")
        self.threshold_radio = QRadioButton("Multiple Events / Threshold")
        self.single_event_radio.setChecked(True)
        self.detection_mode_group.addButton(self.single_event_radio)
        self.detection_mode_group.addButton(self.threshold_radio)
        self.single_event_radio.toggled.connect(self._on_detection_mode_changed)

        mode_row = QHBoxLayout()
        mode_row.addWidget(self.single_event_radio)
        mode_row.addWidget(self.threshold_radio)
        mode_row.addStretch()
        basic_layout.addRow("Detection Type:", mode_row)

        self.threshold_group = QGroupBox("Threshold")
        threshold_layout = QFormLayout()
        self.threshold_count = QSpinBox()
        self.threshold_count.setMinimum(1)
        self.threshold_count.setValue(10)
        threshold_layout.addRow("Count:", self.threshold_count)

        self.threshold_window = QSpinBox()
        self.threshold_window.setMinimum(1)
        self.threshold_window.setValue(60)
        threshold_layout.addRow("Within:", self.threshold_window)

        self.threshold_unit = QComboBox()
        self.threshold_unit.addItem("seconds", TimeUnit.SECONDS.value)
        self.threshold_unit.addItem("minutes", TimeUnit.MINUTES.value)
        self.threshold_unit.addItem("hours", TimeUnit.HOURS.value)
        threshold_layout.addRow("Time Unit:", self.threshold_unit)

        group_container = QGroupBox()
        group_container.setFlat(True)
        group_row = QVBoxLayout(group_container)
        group_controls = QHBoxLayout()
        self.group_by_field_combo = QComboBox()
        for field_name in FIELD_DEFINITIONS.keys():
            self.group_by_field_combo.addItem(field_name)
        group_controls.addWidget(self.group_by_field_combo)
        self.group_by_add_btn = QPushButton("+ Add field")
        self.group_by_add_btn.clicked.connect(self._on_add_group_by_field)
        group_controls.addWidget(self.group_by_add_btn)
        self.group_by_remove_btn = QPushButton("Remove selected")
        self.group_by_remove_btn.clicked.connect(self._on_remove_group_by_field)
        group_controls.addWidget(self.group_by_remove_btn)
        group_row.addLayout(group_controls)
        self.group_by_list = QListWidget()
        self.group_by_list.setMaximumHeight(110)
        group_row.addWidget(self.group_by_list)
        threshold_layout.addRow("Group By:", group_container)

        self.cooldown_window = QSpinBox()
        self.cooldown_window.setMinimum(0)
        self.cooldown_window.setValue(10)
        threshold_layout.addRow("Cooldown:", self.cooldown_window)

        self.cooldown_unit = QComboBox()
        self.cooldown_unit.addItem("seconds", TimeUnit.SECONDS.value)
        self.cooldown_unit.addItem("minutes", TimeUnit.MINUTES.value)
        self.cooldown_unit.addItem("hours", TimeUnit.HOURS.value)
        self.cooldown_unit.setCurrentIndex(1)
        threshold_layout.addRow("Cooldown Unit:", self.cooldown_unit)

        self.threshold_group.setLayout(threshold_layout)
        basic_layout.addRow(self.threshold_group)
        
        self.severity_combo = QComboBox()
        for severity in AlertSeverity:
            self.severity_combo.addItem(severity.value, severity)
        self.severity_combo.setCurrentIndex(1)  # Default to MEDIUM
        basic_layout.addRow("Severity:", self.severity_combo)
        
        basic_group.setLayout(basic_layout)
        layout.addWidget(basic_group)
        self._on_detection_mode_changed()
        
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
        self.save_btn.setObjectName("primaryButton")
        self.save_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.save_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)

    def _apply_styles(self):
        self.setStyleSheet(
            f"""
            QDialog {{ background-color: {COLORS['app_bg']}; color: {COLORS['text_primary']}; }}
            QGroupBox {{ border: 1px solid {COLORS['border']}; border-radius: 8px; background-color: {COLORS['app_bg']}; margin-top: 12px; padding-top: 8px; }}
            QGroupBox::title {{ color: {COLORS['text_secondary']}; padding: 0 6px; }}
            QPushButton {{ min-height: 30px; }}
            """
        )
    
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

    def _on_detection_mode_changed(self):
        self.threshold_group.setVisible(self.threshold_radio.isChecked())

    def _on_add_group_by_field(self):
        field = self.group_by_field_combo.currentText().strip()
        if not field:
            return
        existing = {self.group_by_list.item(i).text() for i in range(self.group_by_list.count())}
        if field not in existing:
            self.group_by_list.addItem(field)

    def _on_remove_group_by_field(self):
        row = self.group_by_list.currentRow()
        if row >= 0:
            self.group_by_list.takeItem(row)

    def _collect_group_by_fields(self):
        return [self.group_by_list.item(i).text() for i in range(self.group_by_list.count())]
    
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
        self.creator_input.setText(rule.creator_name or self.creator_input.text())

        if rule.detection_type == DetectionType.THRESHOLD:
            self.threshold_radio.setChecked(True)
            if rule.threshold:
                self.threshold_count.setValue(max(1, int(rule.threshold.count)))
                self.threshold_window.setValue(max(1, int(rule.threshold.window)))
                self._set_combo_data(self.threshold_unit, rule.threshold.unit.value)
                self._set_combo_data(self.cooldown_unit, rule.threshold.cooldown_unit.value)
                self.cooldown_window.setValue(max(0, int(rule.threshold.cooldown)))
                self.group_by_list.clear()
                for field in rule.threshold.group_by:
                    if field in FIELD_DEFINITIONS:
                        self.group_by_list.addItem(field)
        else:
            self.single_event_radio.setChecked(True)
        
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

    def _set_combo_data(self, combo: QComboBox, value: str) -> None:
        for i in range(combo.count()):
            if combo.itemData(i) == value:
                combo.setCurrentIndex(i)
                return
    
    def get_rule(self) -> AlertRule:
        """Get the configured rule."""
        if not self.name_input.text().strip():
            raise ValueError("Rule name is required")

        creator_name = self.creator_input.text().strip()
        if not creator_name:
            raise ValueError("Rule Creator is required")
        
        query_def = self.visual_builder.get_query_definition()
        if query_def.is_empty():
            raise ValueError("Event condition is required")

        kql = query_definition_to_kql(query_def)

        detection_type = DetectionType.SINGLE_EVENT
        threshold = None
        if self.threshold_radio.isChecked():
            detection_type = DetectionType.THRESHOLD
            count = int(self.threshold_count.value())
            window = int(self.threshold_window.value())
            unit = self.threshold_unit.currentData()
            cooldown = int(self.cooldown_window.value())
            cooldown_unit = self.cooldown_unit.currentData()
            group_by = self._collect_group_by_fields()

            if count < 1:
                raise ValueError("Minimum occurrence count must be at least 1")
            if window <= 0:
                raise ValueError("Time window must be greater than 0")
            if unit not in {TimeUnit.SECONDS.value, TimeUnit.MINUTES.value, TimeUnit.HOURS.value}:
                raise ValueError("Invalid threshold time unit")
            if cooldown < 0:
                raise ValueError("Cooldown must be 0 or greater")
            if cooldown_unit not in {TimeUnit.SECONDS.value, TimeUnit.MINUTES.value, TimeUnit.HOURS.value}:
                raise ValueError("Invalid cooldown time unit")
            invalid_fields = [field for field in group_by if field not in FIELD_DEFINITIONS]
            if invalid_fields:
                raise ValueError(f"Invalid group-by fields: {', '.join(invalid_fields)}")

            threshold = ThresholdConfig(
                count=count,
                window=window,
                unit=TimeUnit(unit),
                group_by=group_by,
                cooldown=cooldown,
                cooldown_unit=TimeUnit(cooldown_unit),
            )
        
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
            detection_type=detection_type,
            threshold=threshold,
            creator_name=creator_name,
            query_definition=query_def,
            generated_kql=kql,
            action=ActionConfig(action_type, action_config),
            enabled=self.rule.enabled if self.rule else True,
            created_at=self.rule.created_at if self.rule else None,
            updated_at=self.rule.updated_at if self.rule else None,
        )
        
        return rule


__all__ = ["AlertRuleEditor"]
