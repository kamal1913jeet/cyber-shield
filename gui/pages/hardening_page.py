# gui/pages/hardening_page.py — Security Hardening Page

import platform
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFrame, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal
from PyQt6.QtGui import QColor


# ── worker ────────────────────────────────────────────────────────────────────
class HardeningWorker(QObject):
    log    = pyqtSignal(str)
    result = pyqtSignal(object)
    done   = pyqtSignal()

    def run(self):
        try:
            from modules.hardener import SystemHardener
            self.log.emit("[*] Running security hardening audit...")
            hardener = SystemHardener()
            report   = hardener.run_all_checks()
            self.log.emit(f"[+] Audit complete. Score: {report.score}/100")
            self.result.emit(report)
        except Exception as e:
            self.log.emit(f"[!] Error: {e}")
        finally:
            self.done.emit()


# ── page ──────────────────────────────────────────────────────────────────────
class HardeningPage(QWidget):

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
        title = QLabel("Security Hardening Audit")
        title.setObjectName("PageTitle")
        sub = QLabel("Check OS security configuration and get actionable fix steps")
        sub.setObjectName("PageSubtitle")
        layout.addWidget(title)
        layout.addWidget(sub)

        div = QFrame()
        div.setObjectName("Separator")
        div.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(div)

        # ── action card ───────────────────────────────────────────────────────
        card = QWidget()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)

        card_title = QLabel("Run Audit")
        card_title.setObjectName("CardTitle")
        card_layout.addWidget(card_title)

        info = QLabel(f"System: {platform.node()}  ·  OS: {platform.system()} {platform.release()}")
        info.setObjectName("PageSubtitle")
        card_layout.addWidget(info)

        btn_row = QHBoxLayout()
        self._run_btn = QPushButton("◆  Start Hardening Audit")
        self._run_btn.setObjectName("PrimaryButton")
        self._run_btn.setMinimumHeight(40)
        self._run_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._run_btn.clicked.connect(self._start_audit)
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

        # ── score row ─────────────────────────────────────────────────────────
        score_row = QHBoxLayout()
        score_row.setSpacing(14)

        self._score_card   = self._mini_card("Hardening Score", "—", "#00b4ff")
        self._pass_card    = self._mini_card("Passed",          "—", "#00ff88")
        self._fail_card    = self._mini_card("Failed",          "—", "#ff3b5c")
        self._warn_card    = self._mini_card("Warnings",        "—", "#ffc107")

        for w in (self._score_card, self._pass_card,
                  self._fail_card, self._warn_card):
            score_row.addWidget(w)
        score_row.addStretch()
        layout.addLayout(score_row)

        # ── findings table ────────────────────────────────────────────────────
        findings_label = QLabel("Findings")
        findings_label.setObjectName("CardTitle")
        layout.addWidget(findings_label)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Check", "Status", "Severity", "Fix"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setWordWrap(True)
        layout.addWidget(self._table, 1)

        # ── log ───────────────────────────────────────────────────────────────
        log_label = QLabel("Log")
        log_label.setObjectName("CardTitle")
        layout.addWidget(log_label)

        self._log = QTextEdit()
        self._log.setObjectName("LogArea")
        self._log.setReadOnly(True)
        self._log.setMaximumHeight(110)
        layout.addWidget(self._log)

    # ── helpers ───────────────────────────────────────────────────────────────
    def _mini_card(self, title: str, value: str, color: str) -> QWidget:
        w = QWidget()
        w.setObjectName("Card")
        l = QVBoxLayout(w)
        t = QLabel(title)
        t.setObjectName("FieldLabel")
        v = QLabel(value)
        v.setStyleSheet(f"color: {color}; font-size: 22px; font-weight: bold;")
        v.setObjectName("mini_val")
        l.addWidget(t)
        l.addWidget(v)
        return w

    def _set_mini(self, card: QWidget, value: str):
        for child in card.findChildren(QLabel):
            if child.objectName() == "mini_val":
                child.setText(value)
                break

    def _log_msg(self, msg: str):
        self._log.append(msg)

    # ── scan control ──────────────────────────────────────────────────────────
    def _start_audit(self):
        self._run_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._table.setRowCount(0)
        self._log.clear()
        self._log_msg("[*] Starting hardening audit...")

        self._thread = QThread()
        self._worker = HardeningWorker()
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self._log_msg)
        self._worker.result.connect(self._show_result)
        self._worker.done.connect(self._audit_done)
        self._worker.done.connect(self._thread.quit)

        self._thread.start()

    def _show_result(self, report):
        findings = getattr(report, 'findings', [])
        score    = getattr(report, 'score',    0)

        passed   = sum(1 for f in findings if getattr(f, 'status', '').lower() == 'pass')
        failed   = sum(1 for f in findings if getattr(f, 'status', '').lower() == 'fail')
        warnings = sum(1 for f in findings if getattr(f, 'status', '').lower() == 'warn')

        self._set_mini(self._score_card, f"{score}/100")
        self._set_mini(self._pass_card,  str(passed))
        self._set_mini(self._fail_card,  str(failed))
        self._set_mini(self._warn_card,  str(warnings))

        # severity colors
        severity_colors = {
            "high":   "#ff3b5c",
            "medium": "#ffc107",
            "low":    "#00ff88",
        }

        self._table.setRowCount(0)
        for f in findings:
            row = self._table.rowCount()
            self._table.insertRow(row)

            name     = str(getattr(f, 'name',     getattr(f, 'check', '—')))
            status   = str(getattr(f, 'status',   '—')).upper()
            severity = str(getattr(f, 'severity', '—')).lower()
            fix      = str(getattr(f, 'fix',      getattr(f, 'recommendation', '—')))

            self._table.setItem(row, 0, QTableWidgetItem(name))
            self._table.setItem(row, 1, QTableWidgetItem(status))
            self._table.setItem(row, 2, QTableWidgetItem(severity.upper()))
            self._table.setItem(row, 3, QTableWidgetItem(fix))

            # color the status cell
            color = {"PASS": "#00ff88", "FAIL": "#ff3b5c", "WARN": "#ffc107"}.get(status, "#c9d1d9")
            self._table.item(row, 1).setForeground(QColor(color))
            sev_color = severity_colors.get(severity, "#c9d1d9")
            self._table.item(row, 2).setForeground(QColor(sev_color))

    def _audit_done(self):
        self._run_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._log_msg("[+] Audit complete.")
