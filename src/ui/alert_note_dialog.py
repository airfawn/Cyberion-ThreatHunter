"""Dialog for adding investigation notes to an alert."""

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QBrush
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QTextEdit, QPushButton,
    QLabel, QFrame
)


class AlertNoteDialog(QDialog):
    """Dialog for adding/editing an investigation note on an alert."""

    def __init__(self, alert_id: str, alert_manager, parent=None):
        super().__init__(parent)
        self.alert_id = alert_id
        self.alert_manager = alert_manager
        self.setWindowTitle("Add Investigation Note")
        self.resize(480, 320)
        
        # Load existing note if any
        existing_note = ""
        try:
            history = alert_manager.get_rule_history(alert_id, limit=1, offset=0)
            if history:
                existing_note = history[0].note or ""
        except Exception:
            existing_note = ""
        
        layout = QVBoxLayout(self)
        
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft)
        
        self.note_edit = QTextEdit()
        self.note_edit.setPlainText(existing_note)
        self.note_edit.setMinimumHeight(150)
        self.note_edit.setFont(QFont("Menlo", 11))
        
        form.addRow("Investigation Note:", self.note_edit)
        
        layout.addLayout(form)
        
        button_row = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("Save")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self.accept)
        
        button_row.addStretch(1)
        button_row.addWidget(cancel_btn)
        button_row.addWidget(save_btn)
        layout.addLayout(button_row)
        
        self.setStyleSheet("""
            QFrame { margin: 4px; padding: 4px; }
            QPushButton { min-height: 30px; }
        """)
    
    def get_note(self) -> str:
        """Return the note text."""
        return self.note_edit.toPlainText().strip()