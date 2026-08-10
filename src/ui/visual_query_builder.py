"""PyQt5 Visual Query Builder Widget.

This widget allows users to build queries visually without knowing KQL syntax.
It can be embedded in Search or Alert rule editing interfaces.
"""

from typing import Optional
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QComboBox,
    QLineEdit,
    QPushButton,
    QLabel,
    QSpinBox,
    QFrame,
    QScrollArea,
    QDateTimeEdit,
)
from PyQt5.QtCore import QDateTime

from ..query.query_model import (
    Condition,
    ConditionGroup,
    QueryDefinition,
    ComparisonOperator,
    FieldType,
    LogicalOperator,
    FIELD_DEFINITIONS,
    VALID_OPERATORS_BY_TYPE,
)
from ..query.model_to_kql import query_definition_to_kql


class ConditionRow(QFrame):
    """A single condition row with field/operator/value dropdowns."""
    
    changed = pyqtSignal()
    removed = pyqtSignal()
    
    def __init__(self, condition: Optional[Condition] = None, parent=None):
        super().__init__(parent)
        self.condition = condition
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(6)
        
        # Field dropdown
        self.field_combo = QComboBox()
        self.field_combo.addItem("-- Select Field --", None)
        for field_name, (display_name, _) in sorted(FIELD_DEFINITIONS.items()):
            self.field_combo.addItem(display_name, field_name)
        self.field_combo.currentIndexChanged.connect(self._on_field_changed)
        layout.addWidget(QLabel("Field:"), 0)
        layout.addWidget(self.field_combo, 1)
        
        # Operator dropdown (populated based on field)
        self.operator_combo = QComboBox()
        self.operator_combo.currentIndexChanged.connect(self._on_value_changed)
        layout.addWidget(QLabel("Operator:"), 0)
        layout.addWidget(self.operator_combo, 1)
        
        # Value input (type depends on field)
        self.value_input = None
        self.value_layout = QHBoxLayout()
        layout.addWidget(QLabel("Value:"), 0)
        layout.addLayout(self.value_layout, 2)
        
        # Remove button
        self.remove_btn = QPushButton("✕")
        self.remove_btn.setMaximumWidth(30)
        self.remove_btn.clicked.connect(self.removed.emit)
        layout.addWidget(self.remove_btn, 0)
        
        # Load existing condition if provided
        if self.condition:
            self.field_combo.setCurrentIndex(
                max(0, self._find_combo_index(self.field_combo, self.condition.field))
            )
    
    def _find_combo_index(self, combo: QComboBox, value) -> int:
        """Find the index in a combo box by user data."""
        for i in range(combo.count()):
            if combo.itemData(i) == value:
                return i
        return 0
    
    def _on_field_changed(self):
        """Handle field selection change."""
        field = self.field_combo.currentData()
        
        # Update operator combo based on field type
        self.operator_combo.clear()
        if field:
            field_info = FIELD_DEFINITIONS.get(field)
            if field_info:
                field_type = field_info[1]
                for op in VALID_OPERATORS_BY_TYPE[field_type]:
                    self.operator_combo.addItem(
                        self._operator_display_name(op),
                        op
                    )
        
        # Update value input widget based on field type
        self._update_value_input(field)
        self._on_value_changed()
    
    def _operator_display_name(self, op: ComparisonOperator) -> str:
        """Convert operator enum to display name."""
        names = {
            ComparisonOperator.EQUALS: "equals",
            ComparisonOperator.NOT_EQUALS: "not equals",
            ComparisonOperator.GREATER_THAN: "greater than",
            ComparisonOperator.LESS_THAN: "less than",
            ComparisonOperator.GREATER_THAN_EQUAL: "greater than or equal",
            ComparisonOperator.LESS_THAN_EQUAL: "less than or equal",
            ComparisonOperator.CONTAINS: "contains",
            ComparisonOperator.NOT_CONTAINS: "not contains",
            ComparisonOperator.STARTS_WITH: "starts with",
            ComparisonOperator.ENDS_WITH: "ends with",
            ComparisonOperator.IS_EMPTY: "is empty",
            ComparisonOperator.IS_NOT_EMPTY: "is not empty",
        }
        return names.get(op, op.value)
    
    def _update_value_input(self, field: Optional[str]):
        """Update the value input widget based on field type."""
        # Clear existing value input
        while self.value_layout.count():
            item = self.value_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        self.value_input = None
        
        if not field:
            return
        
        field_info = FIELD_DEFINITIONS.get(field)
        if not field_info:
            return
        
        field_type = field_info[1]
        
        # Check if current operator needs a value
        op = self.operator_combo.currentData()
        if op in (ComparisonOperator.IS_EMPTY, ComparisonOperator.IS_NOT_EMPTY):
            # No value needed
            return
        
        # Create appropriate input widget based on field type
        if field_type == FieldType.NUMERIC:
            self.value_input = QSpinBox()
            self.value_input.setMinimum(-999999)
            self.value_input.setMaximum(999999)
            self.value_input.valueChanged.connect(self._on_value_changed)
        elif field_type == FieldType.TIMESTAMP:
            self.value_input = QDateTimeEdit()
            self.value_input.setDateTime(QDateTime.currentDateTime())
            self.value_input.dateTimeChanged.connect(self._on_value_changed)
        elif field_type == FieldType.BOOLEAN:
            self.value_input = QComboBox()
            self.value_input.addItem("true", True)
            self.value_input.addItem("false", False)
            self.value_input.currentIndexChanged.connect(self._on_value_changed)
        else:  # STRING
            self.value_input = QLineEdit()
            self.value_input.setPlaceholderText("Enter value...")
            self.value_input.textChanged.connect(self._on_value_changed)
        
        self.value_layout.addWidget(self.value_input, 1)
        
        # Load existing value if condition exists
        if self.condition and self.condition.value is not None:
            self._set_value_input(self.condition.value)
    
    def _set_value_input(self, value):
        """Set the value in the input widget."""
        if not self.value_input:
            return
        
        if isinstance(self.value_input, QSpinBox):
            self.value_input.setValue(int(value) if value is not None else 0)
        elif isinstance(self.value_input, QComboBox):
            # For boolean combo
            idx = 0
            for i in range(self.value_input.count()):
                if self.value_input.itemData(i) == value:
                    idx = i
                    break
            self.value_input.setCurrentIndex(idx)
        elif isinstance(self.value_input, QLineEdit):
            self.value_input.setText(str(value) if value is not None else "")
        elif isinstance(self.value_input, QDateTimeEdit):
            if isinstance(value, str):
                self.value_input.setDateTime(QDateTime.fromString(value, Qt.ISODate))
            elif isinstance(value, QDateTime):
                self.value_input.setDateTime(value)
    
    def _on_value_changed(self):
        """Handle value change."""
        self.changed.emit()
    
    def get_condition(self) -> Optional[Condition]:
        """Get the current condition from the UI."""
        field = self.field_combo.currentData()
        operator = self.operator_combo.currentData()
        
        if not field or not operator:
            return None
        
        # Get value
        value = None
        if self.value_input:
            if isinstance(self.value_input, QSpinBox):
                value = self.value_input.value()
            elif isinstance(self.value_input, QComboBox):
                value = self.value_input.currentData()
            elif isinstance(self.value_input, QLineEdit):
                value = self.value_input.text()
            elif isinstance(self.value_input, QDateTimeEdit):
                value = self.value_input.dateTime().toString(Qt.ISODate)
        
        try:
            return Condition(field=field, operator=operator, value=value)
        except ValueError:
            # Invalid condition
            return None
    
    def set_condition(self, condition: Condition):
        """Set the condition from model."""
        self.condition = condition
        self.field_combo.setCurrentIndex(
            self._find_combo_index(self.field_combo, condition.field)
        )
        self.operator_combo.setCurrentIndex(
            self._find_combo_index(self.operator_combo, condition.operator)
        )
        if condition.value is not None:
            self._set_value_input(condition.value)


class VisualQueryBuilder(QWidget):
    """Visual query builder widget with condition groups."""
    
    query_changed = pyqtSignal()
    
    def __init__(self, query_def: Optional[QueryDefinition] = None, parent=None):
        super().__init__(parent)
        self.query_def = query_def or QueryDefinition.empty()
        self.condition_rows = []
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Conditions title
        title = QLabel("Conditions")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(title)
        
        # Scrollable area for conditions
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setMinimumHeight(150)
        
        self.conditions_widget = QWidget()
        self.conditions_layout = QVBoxLayout(self.conditions_widget)
        self.conditions_layout.setContentsMargins(0, 0, 0, 0)
        self.conditions_layout.setSpacing(4)
        
        # Populate with existing conditions
        if not self.query_def.is_empty():
            for condition in self.query_def.root_group.conditions:
                self._add_condition_row(condition)
        else:
            self._add_condition_row()
        
        self.conditions_layout.addStretch(1)
        scroll.setWidget(self.conditions_widget)
        layout.addWidget(scroll, 1)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(6)
        
        add_condition_btn = QPushButton("+ Add Condition")
        add_condition_btn.clicked.connect(self._add_condition_row)
        button_layout.addWidget(add_condition_btn)
        
        button_layout.addStretch(1)
        layout.addLayout(button_layout)
        
        # Logical operator selector (for top-level group)
        op_layout = QHBoxLayout()
        op_layout.addWidget(QLabel("Combine conditions with:"))
        self.logical_op_combo = QComboBox()
        self.logical_op_combo.addItem("AND", LogicalOperator.AND)
        self.logical_op_combo.addItem("OR", LogicalOperator.OR)
        self.logical_op_combo.currentIndexChanged.connect(self._on_query_changed)
        op_layout.addWidget(self.logical_op_combo)
        op_layout.addStretch(1)
        layout.addLayout(op_layout)
        
        # Generated KQL display
        kql_title = QLabel("Generated KQL")
        kql_title.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(kql_title)
        
        self.kql_display = QLineEdit()
        self.kql_display.setReadOnly(True)
        self.kql_display.setStyleSheet(
            "background-color: #1a1a1a; color: #00ff00; font-family: monospace;"
        )
        layout.addWidget(self.kql_display)
        
        self._update_kql_display()
    
    def _add_condition_row(self, condition: Optional[Condition] = None):
        """Add a condition row."""
        row = ConditionRow(condition=condition)
        row.changed.connect(self._on_query_changed)
        row.removed.connect(lambda: self._remove_condition_row(row))
        
        self.conditions_layout.insertWidget(len(self.condition_rows), row)
        self.condition_rows.append(row)
    
    def _remove_condition_row(self, row: ConditionRow):
        """Remove a condition row."""
        if row in self.condition_rows:
            self.condition_rows.remove(row)
            row.deleteLater()
            self._on_query_changed()
    
    def _on_query_changed(self):
        """Handle query change."""
        self._update_query_model()
        self._update_kql_display()
        self.query_changed.emit()
    
    def _update_query_model(self):
        """Update the internal query model from UI."""
        self.query_def.root_group.conditions.clear()
        self.query_def.root_group.logical_operator = self.logical_op_combo.currentData()
        
        for row in self.condition_rows:
            condition = row.get_condition()
            if condition:
                self.query_def.root_group.add_condition(condition)
    
    def _update_kql_display(self):
        """Update the KQL display."""
        try:
            kql = query_definition_to_kql(self.query_def)
            self.kql_display.setText(kql)
        except Exception as e:
            self.kql_display.setText(f"Error: {str(e)}")
    
    def get_query_definition(self) -> QueryDefinition:
        """Get the current query definition."""
        self._update_query_model()
        return self.query_def
    
    def set_query_definition(self, query_def: QueryDefinition):
        """Set the query definition."""
        self.query_def = query_def
        
        # Rebuild UI
        for row in self.condition_rows:
            row.deleteLater()
        self.condition_rows.clear()
        
        for condition in query_def.root_group.conditions:
            self._add_condition_row(condition)
        
        self.logical_op_combo.setCurrentIndex(
            0 if query_def.root_group.logical_operator == LogicalOperator.AND else 1
        )
        
        self._update_kql_display()
    
    def get_kql(self) -> str:
        """Get the generated KQL string."""
        self._update_query_model()
        return query_definition_to_kql(self.query_def)


__all__ = [
    "VisualQueryBuilder",
    "ConditionRow",
]
