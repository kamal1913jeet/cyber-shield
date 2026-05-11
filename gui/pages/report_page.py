# gui/pages/report_page.py — PDF Report Page

import os
import platform
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QFrame, QProgressBar,
    QFileDialog, QCheckBox, QLineEdit
)
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal


# ── worker ────────────────────────────────────────────────────────────────────
class ReportWorker(QObject):
    log    = pyqtSignal(str)
    done   = pyqtSignal(str)   # emits final path

    def __init__(self, output_path: str):
        super().__init__()
        self.output_path = output_path

    def run(self):
        try:
            from modules.reporter import generate_report
            self.log.emit("[*] Generating PDF report...")
            path = generate_report(
                target_ip        = platform.node(),
                scan_result      = None,
                cleanup_report   = None,
                hardening_report = None,
                output_path      = self.output_path or None,
            )
            self.log.emit(f"[+] Report saved → {path}")
            self.done.emit(str(path))
        except Exception as e:
            self.log.emit(f"[!] Error: {e}")
            self.done.emit("")


# ── page ──────────────────────────────────────────────────────────────────────
class ReportPage(QWidget):

    def __init__(self):
        super().__init__()
        self._thread = None
        self._worker = None
        self._last_path = ""
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(16)

        # ── header ────────────────────────────────────────────────────────────
        title = QLabel("PDF Report")
        title.setObjectName("PageTitle")
        sub = QLabel("Generate and export a full security audit report")
        sub.setObjectName("PageSubtitle")
        layout.addWidget(title)
        layout.addWidget(sub)

        div = QFrame()
        div.setObjectName("Separator")
        div.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(div)

        # ── config card ───────────────────────────────────────────────────────
        card = QWidget()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)

        card_title = QLabel("Report Configuration")
        card_title.setObjectName("CardTitle")
        card_layout.addWidget(card_title)

        # output path row
        path_row = QHBoxLayout()
        path_lbl = QLabel("OUTPUT PATH")
        path_lbl.setObjectName("FieldLabel")
        path_lbl.setFixedWidth(110)

        self._path_input = QLineEdit()
        self._path_input.setPlaceholderText("Leave blank for default (reports/ folder)")

        browse_btn = QPushButton("Browse")
        browse_btn.setObjectName("SecondaryButton")
        browse_btn.setFixedWidth(80)
        browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        browse_btn.clicked.connect(self._browse)

        path_row.addWidget(path_lbl)
        path_row.addWidget(self._path_input)
        path_row.addWidget(browse_btn)
        card_layout.addLayout(path_row)

        # buttons
        btn_row = QHBoxLayout()

        self._gen_btn = QPushButton("◉  Generate Report")
        self._gen_btn.setObjectName("PrimaryButton")
        self._gen_btn.setMinimumHeight(40)
        self._gen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._gen_btn.clicked.connect(self._generate)

        self._open_btn = QPushButton("Open PDF")
        self._open_btn.setObjectName("SecondaryButton")
        self._open_btn.setMinimumHeight(40)
        self._open_btn.setEnabled(False)
        self._open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._open_btn.clicked.connect(self._open_pdf)

        btn_row.addWidget(self._gen_btn)
        btn_row.addWidget(self._open_btn)
        btn_row.addStretch()
        card_layout.addLayout(btn_row)

        layout.addWidget(card)

        # ── progress ──────────────────────────────────────────────────────────
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        self._progress.setFixedHeight(6)
        layout.addWidget(self._progress)

        # ── recent reports card ───────────────────────────────────────────────
        recent_card = QWidget()
        recent_card.setObjectName("Card")
        recent_layout = QVBoxLayout(recent_card)

        recent_title = QLabel("Recent Reports")
        recent_title.setObjectName("CardTitle")
        recent_layout.addWidget(recent_title)

        self._recent_list = QTextEdit()
        self._recent_list.setObjectName("LogArea")
        self._recent_list.setReadOnly(True)
        self._recent_list.setMaximumHeight(160)
        recent_layout.addWidget(self._recent_list)

        layout.addWidget(recent_card)
        self._load_recent_reports()

        # ── log ───────────────────────────────────────────────────────────────
        log_label = QLabel("Log")
        log_label.setObjectName("CardTitle")
        layout.addWidget(log_label)

        self._log = QTextEdit()
        self._log.setObjectName("LogArea")
        self._log.setReadOnly(True)
        self._log.setMaximumHeight(110)
        layout.addWidget(self._log)

        layout.addStretch()

    # ── helpers ───────────────────────────────────────────────────────────────
    def _log_msg(self, msg: str):
        self._log.append(msg)

    def _browse(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report As", "", "PDF Files (*.pdf)"
        )
        if path:
            self._path_input.setText(path)

    def _open_pdf(self):
        if self._last_path and os.path.exists(self._last_path):
            os.startfile(self._last_path)   # Windows
        else:
            self._log_msg("[!] Report file not found.")

    def _load_recent_reports(self):
        """Show any existing PDFs in the reports/ folder."""
        reports_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "reports"
        )
        if os.path.isdir(reports_dir):
            pdfs = sorted(
                [f for f in os.listdir(reports_dir) if f.endswith(".pdf")],
                reverse=True
            )[:10]
            if pdfs:
                self._recent_list.setPlainText("\n".join(pdfs))
            else:
                self._recent_list.setPlainText("No reports found.")
        else:
            self._recent_list.setPlainText("No reports folder found yet.")

    # ── generate ──────────────────────────────────────────────────────────────
    def _generate(self):
        self._gen_btn.setEnabled(False)
        self._open_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._log.clear()
        self._log_msg("[*] Starting report generation...")

        output_path = self._path_input.text().strip()

        self._thread = QThread()
        self._worker = ReportWorker(output_path)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self._log_msg)
        self._worker.done.connect(self._report_done)
        self._worker.done.connect(self._thread.quit)

        self._thread.start()

    def _report_done(self, path: str):
        self._gen_btn.setEnabled(True)
        self._progress.setVisible(False)

        if path:
            self._last_path = path
            self._open_btn.setEnabled(True)
            self._load_recent_reports()
            self._log_msg(f"[+] Done → {path}")
        else:
            self._log_msg("[!] Report generation failed.")
