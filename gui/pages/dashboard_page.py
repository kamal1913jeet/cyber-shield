# gui/pages/dashboard_page.py — Dashboard

import platform
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QPushButton
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont


class StatCard(QWidget):
    def __init__(self, title: str, value: str, label: str, color: str = "#00ff88"):
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        t = QLabel(title)
        t.setObjectName("CardTitle")

        self._value_lbl = QLabel(value)
        self._value_lbl.setObjectName("CardValue")
        self._value_lbl.setStyleSheet(f"color: {color}; font-size: 26px; font-weight: bold;")

        l = QLabel(label)
        l.setObjectName("CardLabel")

        layout.addWidget(t)
        layout.addWidget(self._value_lbl)
        layout.addWidget(l)

    def set_value(self, value: str):
        self._value_lbl.setText(value)


class DashboardPage(QWidget):

    # signal so dashboard buttons can tell the main window to switch pages
    navigate = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(20)

        # ── header ────────────────────────────────────────────────────────────
        title = QLabel("Dashboard")
        title.setObjectName("PageTitle")
        title.setStyleSheet("color: #ffffff; font-size: 22px; font-weight: bold;")

        sub = QLabel(f"System: {platform.node()}  ·  OS: {platform.system()} {platform.release()}")
        sub.setObjectName("PageSubtitle")
        sub.setStyleSheet("color: rgba(255,255,255,0.35); font-size: 12px;")

        layout.addWidget(title)
        layout.addWidget(sub)

        # ── stat cards row ────────────────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(14)

        self._card_devices = StatCard("Devices Found",   "—", "last scan",    "#00ff88")
        self._card_ports   = StatCard("Open Ports",      "—", "last scan",    "#ffc107")
        self._card_score   = StatCard("Hardening Score", "—", "out of 100",   "#00b4ff")
        self._card_cleaned = StatCard("Files Cleaned",   "—", "last cleanup", "#00ff88")

        for card in (self._card_devices, self._card_ports,
                     self._card_score, self._card_cleaned):
            cards_row.addWidget(card)

        layout.addLayout(cards_row)

        # ── divider ───────────────────────────────────────────────────────────
        div = QFrame()
        div.setObjectName("Separator")
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background-color: rgba(255,255,255,0.06); max-height: 1px;")
        layout.addWidget(div)

        # ── quick actions ─────────────────────────────────────────────────────
        qa_label = QLabel("Quick Actions")
        qa_label.setObjectName("CardTitle")
        qa_label.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold;")
        layout.addWidget(qa_label)

        actions_row = QHBoxLayout()
        actions_row.setSpacing(12)

        # each button navigates to its page
        action_map = [
            ("◎  Run Network Scan",    "scan"),
            ("◈  Run File Cleanup",    "cleanup"),
            ("◆  Run Hardening Audit", "hardening"),
            ("◉  Generate Report",     "report"),
        ]

        for label, page_key in action_map:
            btn = QPushButton(label)
            btn.setObjectName("PrimaryButton")
            btn.setMinimumHeight(40)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(0,255,136,0.1);
                    border: 1.5px solid #00ff88;
                    border-radius: 4px;
                    color: #00ff88;
                    font-size: 13px;
                    font-weight: bold;
                    padding: 8px 16px;
                }
                QPushButton:hover {
                    background-color: rgba(0,255,136,0.18);
                }
                QPushButton:pressed {
                    background-color: rgba(0,255,136,0.06);
                }
            """)
            btn.clicked.connect(lambda checked, k=page_key: self.navigate.emit(k))
            actions_row.addWidget(btn)

        layout.addLayout(actions_row)

        # ── system info card ──────────────────────────────────────────────────
        info_card = QWidget()
        info_card.setObjectName("Card")
        info_card.setStyleSheet("""
            QWidget#Card {
                background-color: #0d1117;
                border: 1px solid rgba(255,255,255,0.06);
                border-radius: 6px;
                padding: 16px;
            }
        """)
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(16, 16, 16, 16)

        info_title = QLabel("System Information")
        info_title.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; margin-bottom: 8px;")
        info_layout.addWidget(info_title)

        rows = [
            ("Hostname",  platform.node()),
            ("OS",        f"{platform.system()} {platform.release()}"),
            ("Machine",   platform.machine()),
            ("Processor", platform.processor() or "N/A"),
            ("Python",    platform.python_version()),
        ]

        for key, val in rows:
            row = QHBoxLayout()
            k = QLabel(key)
            k.setStyleSheet("color: rgba(255,255,255,0.4); font-size: 11px; font-weight: bold; letter-spacing: 1px;")
            k.setFixedWidth(100)
            v = QLabel(val)
            v.setStyleSheet("color: #c9d1d9; font-size: 13px;")
            row.addWidget(k)
            row.addWidget(v)
            row.addStretch()
            info_layout.addLayout(row)

        layout.addWidget(info_card)
        layout.addStretch()
