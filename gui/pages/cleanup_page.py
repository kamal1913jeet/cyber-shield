# gui/pages/cleanup_page.py — File Cleanup Page

import platform
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFrame, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal


class CleanupWorker(QObject):
    log    = pyqtSignal(str)
    result = pyqtSignal(object)
    done   = pyqtSignal()

    def __init__(self, use_consent: bool):
        super().__init__()
        self.use_consent = use_consent

    def run(self):
        try:
            from modules.consent_server import get_remote_consent
            from modules.consent import get_consent
            from modules.file_cleaner import run_cleanup_wizard

            local_ip = "127.0.0.1"
            hostname = platform.node()

            if self.use_consent:
                self.log.emit("[*] Sending remote QR consent...")
                ok = get_remote_consent(local_ip, hostname, "File System Cleanup")
            else:
                ok = get_consent(operation="File System Cleanup", target=local_ip)

            if not ok:
                self.log.emit("[!] Consent denied. Aborting.")
                self.done.emit()
                return

            self.log.emit("[*] Consent granted. Running cleanup...")
            report = run_cleanup_wizard()
            self.log.emit(f"[+] Cleanup complete.")
            if report:
                self.result.emit(report)

        except Exception as e:
            self.log.emit(f"[!] Error: {e}")
        finally:
            self.done.emit()


class CleanupPage(QWidget):

    def __init__(self):
        super().__init__()
        self._thread = None
        self._worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(16)

        # ── header ────────────────────────────────────────────────────────────
        title = QLabel("File Cleanup")
        title.setObjectName("PageTitle")
        sub = QLabel("Scan, quarantine and remove malicious or junk files")
        sub.setObjectName("PageSubtitle")
        layout.addWidget(title)
        layout.addWidget(sub)

        div = QFrame(); div.setObjectName("Separator"); div.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(div)

        # ── config card ───────────────────────────────────────────────────────
        card = QWidget(); card.setObjectName("Card")
        card_layout = QVBoxLayout(card)

        card_title = QLabel("Cleanup Configuration"); card_title.setObjectName("CardTitle")
        card_layout.addWidget(card_title)

        self._consent_check = QCheckBox("Use Remote QR Consent before running cleanup")
        card_layout.addWidget(self._consent_check)

        btn_row = QHBoxLayout()
        self._run_btn = QPushButton("◈  Start Cleanup")
        self._run_btn.setObjectName("PrimaryButton")
        self._run_btn.setMinimumHeight(40)
        self._run_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._run_btn.clicked.connect(self._start_cleanup)
        btn_row.addWidget(self._run_btn)
        btn_row.addStretch()
        card_layout.addLayout(btn_row)

        layout.addWidget(card)

        # ── progress ──────────────────────────────────────────────────────────
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        self._progress.setFixedHeight(6)
        layout.addWidget(self._progress)

        # ── stats row ─────────────────────────────────────────────────────────
        stats_row = QHBoxLayout()
        stats_row.setSpacing(14)

        self._stat_deleted     = self._stat_card("Deleted",     "—", "#ff3b5c")
        self._stat_quarantined = self._stat_card("Quarantined", "—", "#ffc107")
        self._stat_freed       = self._stat_card("Space Freed", "—", "#00ff88")

        for w in (self._stat_deleted, self._stat_quarantined, self._stat_freed):
            stats_row.addWidget(w)
        stats_row.addStretch()
        layout.addLayout(stats_row)

        # ── results table ─────────────────────────────────────────────────────
        res_label = QLabel("File Details"); res_label.setObjectName("CardTitle")
        layout.addWidget(res_label)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["File Path", "Action", "Size"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        layout.addWidget(self._table)

        # ── log ───────────────────────────────────────────────────────────────
        log_label = QLabel("Log"); log_label.setObjectName("CardTitle")
        layout.addWidget(log_label)

        self._log = QTextEdit()
        self._log.setObjectName("LogArea")
        self._log.setReadOnly(True)
        self._log.setMaximumHeight(120)
        layout.addWidget(self._log)

    def _stat_card(self, title: str, value: str, color: str) -> QWidget:
        w = QWidget(); w.setObjectName("Card")
        l = QVBoxLayout(w)
        t = QLabel(title); t.setObjectName("FieldLabel")
        v = QLabel(value)
        v.setStyleSheet(f"color: {color}; font-size: 22px; font-weight: bold;")
        v.setObjectName(f"stat_{title.lower()}")
        l.addWidget(t); l.addWidget(v)
        return w

    def _update_stat(self, card: QWidget, value: str):
        for child in card.findChildren(QLabel):
            if child.objectName().startswith("stat_"):
                child.setText(value)
                break

    def _log_msg(self, msg: str):
        self._log.append(msg)

    def _start_cleanup(self):
        self._run_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._table.setRowCount(0)
        self._log.clear()
        self._log_msg("[*] Starting file cleanup...")

        self._thread = QThread()
        self._worker = CleanupWorker(self._consent_check.isChecked())
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self._log_msg)
        self._worker.result.connect(self._show_result)
        self._worker.done.connect(self._cleanup_done)
        self._worker.done.connect(self._thread.quit)

        self._thread.start()

    def _show_result(self, report):
        deleted     = getattr(report, 'deleted',        [])
        quarantined = getattr(report, 'quarantined',    [])
        freed       = getattr(report, 'space_freed_mb', 0)

        self._update_stat(self._stat_deleted,     str(len(deleted)))
        self._update_stat(self._stat_quarantined, str(len(quarantined)))
        self._update_stat(self._stat_freed,       f"{freed:.1f} MB")

        for path in deleted:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(str(path)))
            self._table.setItem(row, 1, QTableWidgetItem("Deleted"))
            self._table.setItem(row, 2, QTableWidgetItem("—"))

        for path in quarantined:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(str(path)))
            self._table.setItem(row, 1, QTableWidgetItem("Quarantined"))
            self._table.setItem(row, 2, QTableWidgetItem("—"))

    def _cleanup_done(self):
        self._run_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._log_msg("[+] Done.")
