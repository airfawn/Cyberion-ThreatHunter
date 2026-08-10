"""Centralized visual theme for the Cyberion UI."""

from PyQt5.QtGui import QFont


COLORS = {
    "app_bg": "#0B0F14",
    "surface_primary": "#11161D",
    "surface_secondary": "#151B23",
    "surface_elevated": "#19212B",
    "border": "#27313D",
    "text_primary": "#F1F5F9",
    "text_secondary": "#94A3B8",
    "text_muted": "#64748B",
    "accent": "#3B82F6",
    "accent_hover": "#60A5FA",
    "success": "#22C55E",
    "warning": "#F59E0B",
    "danger": "#EF4444",
    "info": "#38BDF8",
    "severity_low": "#38BDF8",
    "severity_medium": "#F59E0B",
    "severity_high": "#F97316",
    "severity_critical": "#EF4444",
    "status_active": "#22C55E",
    "status_disabled": "#64748B",
}

FONT_FAMILY = "Inter, SF Pro Text, Segoe UI, Arial, sans-serif"


def apply_global_theme(app) -> None:
    """Apply a centralized dark cyber/SOC theme to the QApplication."""
    app.setStyle("Fusion")
    app.setFont(theme_font(12))
    app.setStyleSheet(build_stylesheet())


def theme_font(size: int, weight: int = QFont.Normal) -> QFont:
    font = QFont(FONT_FAMILY, size, weight)
    font.setHintingPreference(QFont.PreferDefaultHinting)
    return font


def build_stylesheet() -> str:
    return f"""
    QWidget {{
        background-color: {COLORS['app_bg']};
        color: {COLORS['text_primary']};
        font-family: {FONT_FAMILY};
        font-size: 13px;
        outline: none;
    }}

    QMainWindow, QDialog, QFrame, QStackedWidget, QScrollArea, QTabWidget::pane {{
        background-color: {COLORS['app_bg']};
        color: {COLORS['text_primary']};
    }}

    QFrame#sidebar {{
        background-color: #0D1218;
        border: 1px solid {COLORS['border']};
        border-radius: 8px;
    }}

    QFrame#contentPane {{
        background-color: {COLORS['app_bg']};
    }}

    QLabel {{
        background: transparent;
        color: {COLORS['text_primary']};
    }}

    QLabel[secondary="true"] {{
        color: {COLORS['text_secondary']};
    }}

    QGroupBox {{
        border: 1px solid {COLORS['border']};
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 10px;
        background-color: {COLORS['app_bg']};
    }}

    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 6px;
        color: {COLORS['text_secondary']};
    }}

    QPushButton {{
        background-color: {COLORS['surface_secondary']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 8px 12px;
        min-height: 30px;
    }}

    QPushButton:hover {{
        background-color: {COLORS['surface_elevated']};
        border-color: {COLORS['accent']};
    }}

    QPushButton:pressed {{
        background-color: {COLORS['surface_primary']};
    }}

    QPushButton.primary, QPushButton#primaryButton {{
        background-color: {COLORS['accent']};
        border-color: {COLORS['accent']};
        color: #FFFFFF;
    }}

    QPushButton.primary:hover, QPushButton#primaryButton:hover {{
        background-color: {COLORS['accent_hover']};
        border-color: {COLORS['accent_hover']};
    }}

    QPushButton.danger, QPushButton#dangerButton {{
        background-color: {COLORS['danger']};
        border-color: {COLORS['danger']};
        color: #FFFFFF;
    }}

    QLineEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateTimeEdit {{
        background-color: {COLORS['surface_primary']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 7px 8px;
        selection-background-color: {COLORS['accent']};
    }}

    QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus, QDateTimeEdit:focus {{
        border: 1px solid {COLORS['accent']};
    }}

    QComboBox::drop-down {{
        background-color: {COLORS['surface_secondary']};
        border: none;
    }}

    QTabBar {{
        background: transparent;
    }}

    QTabBar::tab {{
        background-color: transparent;
        color: {COLORS['text_secondary']};
        padding: 8px 14px;
        margin-right: 4px;
        border-radius: 6px;
    }}

    QTabBar::tab:hover {{
        background-color: {COLORS['surface_secondary']};
        color: {COLORS['text_primary']};
    }}

    QTabBar::tab:selected {{
        background-color: {COLORS['surface_primary']};
        color: {COLORS['accent']};
        border: 1px solid {COLORS['border']};
    }}

    QTabWidget::pane {{
        border: 1px solid {COLORS['border']};
        border-radius: 8px;
        background-color: {COLORS['app_bg']};
    }}

    QTableView {{
        background-color: {COLORS['app_bg']};
        alternate-background-color: #0F1721;
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 8px;
        gridline-color: #1B2430;
        selection-background-color: #1E3A5F;
        selection-color: {COLORS['text_primary']};
    }}

    QTableView::item {{
        padding: 8px 10px;
        border: none;
    }}

    QHeaderView::section {{
        background-color: {COLORS['surface_primary']};
        color: {COLORS['text_primary']};
        padding: 8px 10px;
        border: none;
        border-bottom: 1px solid {COLORS['border']};
        font-weight: 600;
    }}

    QCheckBox {{
        spacing: 8px;
        color: {COLORS['text_primary']};
    }}

    QCheckBox::indicator {{
        width: 14px;
        height: 14px;
        border: 1px solid {COLORS['border']};
        background-color: {COLORS['surface_primary']};
        border-radius: 3px;
    }}

    QCheckBox::indicator:checked {{
        background-color: {COLORS['accent']};
        border-color: {COLORS['accent']};
    }}

    QListWidget {{
        background-color: {COLORS['app_bg']};
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 4px;
    }}

    QListWidget::item {{
        padding: 6px 8px;
        border-radius: 4px;
    }}

    QListWidget::item:selected {{
        background-color: #1E3A5F;
        color: {COLORS['text_primary']};
    }}

    QScrollBar:vertical {{
        background: {COLORS['app_bg']};
        width: 10px;
    }}

    QScrollBar::handle:vertical {{
        background: {COLORS['border']};
        border-radius: 5px;
        min-height: 24px;
    }}

    QScrollBar:horizontal {{
        background: {COLORS['app_bg']};
        height: 10px;
    }}

    QScrollBar::handle:horizontal {{
        background: {COLORS['border']};
        border-radius: 5px;
        min-width: 24px;
    }}

    QStatusBar {{
        background-color: {COLORS['app_bg']};
        color: {COLORS['text_secondary']};
    }}

    QMessageBox {{
        background-color: {COLORS['app_bg']};
    }}
    """
