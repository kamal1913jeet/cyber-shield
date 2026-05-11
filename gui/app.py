# gui/app.py — CyberShield Main Window

import os

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QFrame,
    QScrollArea
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from config import TOOL_NAME, VERSION


# ── dark theme — applied inline so it always works regardless of QSS path ─────
DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #080c10;
    color: #c9d1d9;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
}
QWidget#Sidebar {
    background-color: #0d1117;
    border-right: 1px solid rgba(0,255,136,0.12);
}
QLabel#SidebarTitle {
    color: #00ff88;
    font-size: 17px;
    font-weight: bold;
    letter-spacing: 2px;
    padding: 20px 16px 4px 16px;
}
QLabel#SidebarVersion {
    color: rgba(255,255,255,0.25);
    font-size: 10px;
    padding: 0px 16px 16px 16px;
}
QPushButton#NavButton {
    background-color: transparent;
    border: none;
    border-left: 3px solid transparent;
    color: rgba(255,255,255,0.45);
    text-align: left;
    padding: 12px 16px;
    font-size: 13px;
}
QPushButton#NavButton:hover {
    background-color: rgba(0,255,136,0.05);
    color: #c9d1d9;
    border-left: 3px solid rgba(0,255,136,0.3);
}
QPushButton#NavButton[active="true"] {
    background-color: rgba(0,255,136,0.08);
    color: #00ff88;
    border-left: 3px solid #00ff88;
    font-weight: bold;
}
QWidget#ContentArea {
    background-color: #080c10;
}
QWidget#Card {
    background-color: #0d1117;
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 6px;
}
QLabel#PageTitle {
    color: #ffffff;
    font-size: 22px;
    font-weight: bold;
}
QLabel#PageSubtitle {
    color: rgba(255,255,255,0.35);
    font-size: 12px;
}
QLabel#CardTitle {
    color: #ffffff;
    font-size: 14px;
    font-weight: bold;
}
QLabel#CardValue {
    color: #00ff88;
    font-size: 26px;
    font-weight: bold;
}
QLabel#CardLabel {
    color: rgba(255,255,255,0.35);
    font-size: 11px;
}
QLabel#FieldLabel {
    color: rgba(255,255,255,0.4);
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
}
QPushButton#PrimaryButton {
    background-color: rgba(0,255,136,0.1);
    border: 1.5px solid #00ff88;
    border-radius: 4px;
    color: #00ff88;
    font-size: 13px;
    font-weight: bold;
    padding: 10px 20px;
}
QPushButton#PrimaryButton:hover {
    background-color: rgba(0,255,136,0.18);
}
QPushButton#PrimaryButton:pressed {
    background-color: rgba(0,255,136,0.06);
}
QPushButton#PrimaryButton:disabled {
    border-color: rgba(0,255,136,0.2);
    color: rgba(0,255,136,0.3);
}
QPushButton#SecondaryButton {
    background-color: transparent;
    border: 1px solid rgba(255,255,255,0.15);
    border-radius: 4px;
    color: rgba(255,255,255,0.6);
    padding: 10px 20px;
}
QPushButton#SecondaryButton:hover {
    border-color: rgba(255,255,255,0.3);
    color: #c9d1d9;
}
QPushButton#DangerButton {
    background-color: rgba(255,59,92,0.08);
    border: 1.5px solid rgba(255,59,92,0.5);
    border-radius: 4px;
    color: #ff3b5c;
    font-size: 13px;
    font-weight: bold;
    padding: 10px 20px;
}
QPushButton#DangerButton:hover {
    background-color: rgba(255,59,92,0.15);
}
QLineEdit, QComboBox {
    background-color: #0d1117;
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 4px;
    color: #c9d1d9;
    padding: 8px 12px;
}
QLineEdit:focus, QComboBox:focus {
    border-color: rgba(0,255,136,0.4);
}
QTextEdit#LogArea {
    background-color: #060a0e;
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 4px;
    color: #7ee787;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 12px;
    padding: 10px;
}
QTableWidget {
    background-color: #0d1117;
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 4px;
    gridline-color: rgba(255,255,255,0.04);
    selection-background-color: rgba(0,255,136,0.08);
    selection-color: #c9d1d9;
    color: #c9d1d9;
}
QTableWidget::item {
    padding: 8px 12px;
    border-bottom: 1px solid rgba(255,255,255,0.04);
}
QHeaderView::section {
    background-color: rgba(255,255,255,0.03);
    border: none;
    border-bottom: 1px solid rgba(255,255,255,0.08);
    color: rgba(255,255,255,0.45);
    font-size: 11px;
    font-weight: bold;
    padding: 8px 12px;
}
QProgressBar {
    background-color: rgba(255,255,255,0.05);
    border: none;
    border-radius: 3px;
    height: 6px;
    color: transparent;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #00ff88;
    border-radius: 3px;
}
QScrollBar:vertical {
    background: transparent;
    width: 6px;
}
QScrollBar::handle:vertical {
    background: rgba(255,255,255,0.12);
    border-radius: 3px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: rgba(0,255,136,0.3);
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QCheckBox {
    color: rgba(255,255,255,0.6);
    spacing: 8px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid rgba(255,255,255,0.2);
    border-radius: 3px;
    background-color: transparent;
}
QCheckBox::indicator:checked {
    background-color: rgba(0,255,136,0.15);
    border-color: #00ff88;
}
QComboBox QAbstractItemView {
    background-color: #0d1117;
    border: 1px solid rgba(0,255,136,0.2);
    selection-background-color: rgba(0,255,136,0.1);
    selection-color: #00ff88;
    color: #c9d1d9;
}
"""


class NavButton(QPushButton):

    def __init__(self, icon, label):
        super().__init__(f"  {icon}  {label}")
        self.setObjectName("NavButton")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(44)
        self.setProperty("active", "false")

    def set_active(self, active):
        self.setProperty("active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)


class CyberShieldApp(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{TOOL_NAME} v{VERSION}")
        self.setMinimumSize(1000, 660)
        self.resize(1100, 720)
        self.setStyleSheet(DARK_STYLE)

        # init all dicts first
        self._pages          = {}
        self._nav_btns       = {}
        self._page_factories = {}
        self._current        = None

        # build layout
        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self._stack = QStackedWidget()
        self._stack.setObjectName("ContentArea")

        sidebar = self._build_sidebar()
        root_layout.addWidget(sidebar)
        root_layout.addWidget(self._stack, 1)

        self._register_pages()
        self._navigate("dashboard")

    def _build_sidebar(self):
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(200)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        title = QLabel("CYBER\nSHIELD")
        title.setObjectName("SidebarTitle")
        title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))

        version = QLabel(f"v{VERSION}")
        version.setObjectName("SidebarVersion")

        layout.addWidget(title)
        layout.addWidget(version)

        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background-color: rgba(0,255,136,0.12); max-height:1px;")
        layout.addWidget(div)
        layout.addSpacing(8)

        nav_items = [
            ("dashboard", "⬡", "Dashboard"),
            ("scan",      "◎", "Network Scan"),
            ("cleanup",   "◈", "File Cleanup"),
            ("hardening", "◆", "Hardening"),
            ("report",    "◉", "Reports"),
        ]

        for key, icon, label in nav_items:
            btn = NavButton(icon, label)
            btn.clicked.connect(lambda checked, k=key: self._navigate(k))
            layout.addWidget(btn)
            self._nav_btns[key] = btn

        layout.addStretch()

        bottom = QLabel("Defensive Use Only")
        bottom.setObjectName("SidebarVersion")
        bottom.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bottom.setContentsMargins(0, 0, 0, 16)
        layout.addWidget(bottom)

        return sidebar

    def _register_pages(self):
        self._page_factories = {
            "dashboard": self._make_dashboard,
            "scan":      self._make_scan,
            "cleanup":   self._make_cleanup,
            "hardening": self._make_hardening,
            "report":    self._make_report,
        }

    def _make_dashboard(self):
        from gui.pages.dashboard_page import DashboardPage
        page = DashboardPage()
        # connect dashboard quick action buttons to navigation
        page.navigate.connect(self._navigate)
        return page

    def _make_scan(self):
        from gui.pages.scan_page import ScanPage
        return ScanPage()

    def _make_cleanup(self):
        from gui.pages.cleanup_page import CleanupPage
        return CleanupPage()

    def _make_hardening(self):
        from gui.pages.hardening_page import HardeningPage
        return HardeningPage()

    def _make_report(self):
        from gui.pages.report_page import ReportPage
        return ReportPage()

    def _wrap_in_scroll(self, page):
        from PyQt6.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidget(page)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background-color: #080c10; border: none; }")
        return scroll

    def _navigate(self, key):
        if key not in self._pages:
            page       = self._page_factories[key]()
            scrollable = self._wrap_in_scroll(page)
            self._pages[key] = scrollable
            self._stack.addWidget(scrollable)

        self._stack.setCurrentWidget(self._pages[key])

        for k, btn in self._nav_btns.items():
            btn.set_active(k == key)

        self._current = key
