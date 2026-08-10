"""Search page with visual query builder and search results."""

from typing import Optional
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QTableView,
    QComboBox,
    QListWidget,
    QTabWidget,
)
from PyQt5.QtGui import QStandardItem, QStandardItemModel

from .visual_query_builder import VisualQueryBuilder
from ..query.query_model import QueryDefinition
from ..query.model_to_kql import query_definition_to_kql
from ..query import CyberionQueryEngine


class SearchPage(QWidget):
    """Search page with visual query builder and KQL mode."""
    
    def __init__(self, query_engine: Optional[CyberionQueryEngine] = None, parent=None):
        super().__init__(parent)
        self.query_engine = query_engine
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Title
        title = QLabel("Search Events")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)
        
        # Tab widget for Visual/KQL modes
        self.mode_tabs = QTabWidget()
        
        # Visual mode tab
        visual_widget = self._build_visual_mode()
        self.mode_tabs.addTab(visual_widget, "Visual")
        
        # KQL mode tab
        kql_widget = self._build_kql_mode()
        self.mode_tabs.addTab(kql_widget, "KQL")
        
        layout.addWidget(self.mode_tabs, 0)
        
        # Results section
        results_label = QLabel("Results")
        results_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(results_label)
        
        # Results table
        self.result_model = QStandardItemModel(0, 0, self)
        self.result_table = QTableView()
        self.result_table.setModel(self.result_model)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.verticalHeader().hide()
        self.result_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.result_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        layout.addWidget(self.result_table, 1)
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888888; font-size: 10px;")
        layout.addWidget(self.status_label)
    
    def _build_visual_mode(self) -> QWidget:
        """Build the visual query builder interface."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Visual query builder
        self.visual_builder = VisualQueryBuilder()
        self.visual_builder.query_changed.connect(self._on_visual_query_changed)
        layout.addWidget(self.visual_builder, 1)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)
        
        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self._on_visual_search)
        button_layout.addWidget(search_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._on_clear_search)
        button_layout.addWidget(clear_btn)
        
        button_layout.addStretch(1)
        layout.addLayout(button_layout)
        
        return widget
    
    def _build_kql_mode(self) -> QWidget:
        """Build the KQL manual input interface."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        # Help text
        help_text = QLabel("Enter Cyberion Query Language (KQL) directly")
        help_text.setStyleSheet("color: #888888; font-size: 9px;")
        layout.addWidget(help_text)
        
        # KQL input
        self.kql_input = QLineEdit()
        self.kql_input.setPlaceholderText(
            'Example: events | where severity >= 3 | take 100'
        )
        self.kql_input.returnPressed.connect(self._on_kql_search)
        self.kql_input.setStyleSheet(
            "background-color: #1a1a1a; color: #00ff00; font-family: monospace; padding: 8px;"
        )
        layout.addWidget(self.kql_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)
        
        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self._on_kql_search)
        button_layout.addWidget(search_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._on_clear_search)
        button_layout.addWidget(clear_btn)
        
        button_layout.addStretch(1)
        layout.addLayout(button_layout)
        
        layout.addStretch(1)
        return widget
    
    def _on_visual_query_changed(self):
        """Handle visual query change."""
        pass  # Could update KQL display in real-time
    
    def _on_visual_search(self):
        """Execute search from visual builder."""
        if not self.query_engine:
            self.status_label.setText("Error: Query engine not available")
            return
        
        try:
            query_def = self.visual_builder.get_query_definition()
            kql = query_definition_to_kql(query_def)
            self._execute_query(kql)
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
    
    def _on_kql_search(self):
        """Execute search from KQL input."""
        if not self.query_engine:
            self.status_label.setText("Error: Query engine not available")
            return
        
        kql = self.kql_input.text().strip()
        if not kql:
            self.status_label.setText("No query entered")
            return
        
        self._execute_query(kql)
    
    def _execute_query(self, kql: str):
        """Execute a query and display results."""
        try:
            import time
            start = time.time()
            result = self.query_engine.execute(kql)
            elapsed = time.time() - start
            
            # Populate results table
            self.result_model.setRowCount(len(result.rows))
            self.result_model.setColumnCount(len(result.columns))
            self.result_model.setHorizontalHeaderLabels(result.columns)
            
            for row_idx, row_data in enumerate(result.rows):
                for col_idx, value in enumerate(row_data):
                    item = QStandardItem(str(value) if value is not None else "")
                    self.result_model.setItem(row_idx, col_idx, item)
            
            self.status_label.setText(
                f"Found {len(result.rows)} row(s) in {elapsed*1000:.1f}ms"
            )
        except Exception as e:
            self.status_label.setText(f"Query error: {str(e)}")
            self.result_model.setRowCount(0)
            self.result_model.setColumnCount(0)
    
    def _on_clear_search(self):
        """Clear search results."""
        self.result_model.setRowCount(0)
        self.result_model.setColumnCount(0)
        self.status_label.setText("Ready")


__all__ = [
    "SearchPage",
]
