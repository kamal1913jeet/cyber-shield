# gui/pages/scan_page.py — Network Scan Page

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QComboBox, QTextEdit,
    QTableWidget, QTableWidgetItem, QFrame, QProgressBar,
    QHeaderView, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal
from PyQt6.QtGui import QColor


# ── workers — NEVER touch Qt widgets, only emit signals ──────────────────────
class DiscoveryWorker(QObject):
    log    = pyqtSignal(str)
    result = pyqtSignal(list)
    done   = pyqtSignal()

    def run(self):
        try:
            from modules.network_scanner import get_local_subnet, arp_scan
            self.log.emit("[*] Detecting subnet...")
            subnet = get_local_subnet()
            self.log.emit(f"[*] Scanning subnet: {subnet}")
            devices = arp_scan(subnet)
            self.log.emit(f"[+] Found {len(devices)} device(s)")
            result = []
            for d in devices:
                result.append({
                    "ip":       str(getattr(d, "ip",       d)),
                    "hostname": str(getattr(d, "hostname", "Unknown")),
                    "mac":      str(getattr(d, "mac",      "—")),
                })
            self.result.emit(result)
        except Exception as e:
            self.log.emit(f"[!] Discovery error: {e}")
        finally:
            self.done.emit()


class ScanWorker(QObject):
    log    = pyqtSignal(str)
    result = pyqtSignal(object)
    done   = pyqtSignal()

    def __init__(self, target, mode):
        super().__init__()
        self.target = target
        self.mode   = mode

    def run(self):
        try:
            from modules.vuln_scanner import run_quick_scan, run_deep_scan
            from modules.consent import get_consent

            self.log.emit(f"[*] Asking local consent for {self.target}...")
            ok = get_consent(
                operation=f"{self.mode.capitalize()} Scan",
                target=self.target
            )
            if not ok:
                self.log.emit("[!] Consent denied.")
                self.done.emit()
                return

            self.log.emit(f"[*] Running {self.mode} scan on {self.target}...")
            r = run_quick_scan(self.target) if self.mode == "quick" else run_deep_scan(self.target)
            self.log.emit(f"[+] Scan complete. Risk: {r.risk_level}")
            self.result.emit(r)
        except Exception as e:
            self.log.emit(f"[!] Scan error: {e}")
        finally:
            self.done.emit()


# ── page ──────────────────────────────────────────────────────────────────────
class ScanPage(QWidget):

    def __init__(self):
        super().__init__()
        self._disc_thread = None
        self._disc_worker = None
        self._scan_thread = None
        self._scan_worker = None
        self._devices     = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(16)

        # header
        title = QLabel("Network Scan")
        title.setObjectName("PageTitle")
        sub = QLabel("Discover devices on your network, then run port & CVE scan on any target")
        sub.setObjectName("PageSubtitle")
        layout.addWidget(title)
        layout.addWidget(sub)

        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background: rgba(255,255,255,0.06); max-height:1px;")
        layout.addWidget(div)

        # step 1
        step1 = QLabel("Step 1 — Discover Devices")
        step1.setObjectName("CardTitle")
        layout.addWidget(step1)

        self._disc_btn = QPushButton("⬡  Scan Network for Devices")
        self._disc_btn.setObjectName("PrimaryButton")
        self._disc_btn.setMinimumHeight(38)
        self._disc_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._disc_btn.clicked.connect(self._start_discovery)
        layout.addWidget(self._disc_btn)

        self._dev_table = QTableWidget(0, 3)
        self._dev_table.setHorizontalHeaderLabels(["IP Address", "Hostname", "MAC"])
        self._dev_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._dev_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._dev_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._dev_table.verticalHeader().setVisible(False)
        self._dev_table.verticalHeader().setDefaultSectionSize(40)
        self._dev_table.setMinimumHeight(150)
        self._dev_table.setMaximumHeight(240)
        self._dev_table.itemSelectionChanged.connect(self._on_device_selected)
        self._dev_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid rgba(0,255,136,0.2);
                border-radius: 4px;
            }
            QTableWidget::item {
                padding: 8px 12px;
                color: #c9d1d9;
                border-bottom: 1px solid rgba(255,255,255,0.04);
            }
            QTableWidget::item:selected {
                background-color: rgba(0,255,136,0.15);
                color: #00ff88;
            }
            QHeaderView::section {
                background-color: #080c10;
                color: rgba(255,255,255,0.45);
                font-size: 11px;
                font-weight: bold;
                letter-spacing: 1px;
                padding: 8px;
                border: none;
                border-bottom: 1px solid rgba(255,255,255,0.08);
            }
        """)
        layout.addWidget(self._dev_table)

        div2 = QFrame()
        div2.setFrameShape(QFrame.Shape.HLine)
        div2.setStyleSheet("background: rgba(255,255,255,0.06); max-height:1px;")
        layout.addWidget(div2)

        # step 2
        step2 = QLabel("Step 2 — Vulnerability Scan")
        step2.setObjectName("CardTitle")
        layout.addWidget(step2)

        config = QWidget()
        config.setObjectName("Card")
        cfg = QVBoxLayout(config)
        cfg.setContentsMargins(16, 16, 16, 16)

        t_row = QHBoxLayout()
        t_lbl = QLabel("TARGET")
        t_lbl.setObjectName("FieldLabel")
        t_lbl.setFixedWidth(90)
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Select from table above or type IP manually")
        t_row.addWidget(t_lbl)
        t_row.addWidget(self._target_input)
        cfg.addLayout(t_row)

        m_row = QHBoxLayout()
        m_lbl = QLabel("MODE")
        m_lbl.setObjectName("FieldLabel")
        m_lbl.setFixedWidth(90)
        self._mode_combo = QComboBox()
        self._mode_combo.addItems(["Quick Scan", "Deep Scan"])
        self._mode_combo.setFixedWidth(160)
        m_row.addWidget(m_lbl)
        m_row.addWidget(self._mode_combo)
        m_row.addStretch()
        cfg.addLayout(m_row)

        self._consent_check = QCheckBox("Use Remote QR Consent (client authorizes from their phone)")
        cfg.addWidget(self._consent_check)

        btn_row = QHBoxLayout()
        self._scan_btn = QPushButton("◎  Start Vulnerability Scan")
        self._scan_btn.setObjectName("PrimaryButton")
        self._scan_btn.setMinimumHeight(40)
        self._scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._scan_btn.clicked.connect(self._start_scan)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setObjectName("SecondaryButton")
        self._clear_btn.setMinimumHeight(40)
        self._clear_btn.setFixedWidth(80)
        self._clear_btn.clicked.connect(self._clear_results)

        btn_row.addWidget(self._scan_btn)
        btn_row.addWidget(self._clear_btn)
        btn_row.addStretch()
        cfg.addLayout(btn_row)
        layout.addWidget(config)

        # progress
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        self._progress.setFixedHeight(6)
        layout.addWidget(self._progress)

        # results table
        res_lbl = QLabel("Scan Results")
        res_lbl.setObjectName("CardTitle")
        layout.addWidget(res_lbl)

        self._result_table = QTableWidget(0, 4)
        self._result_table.setHorizontalHeaderLabels(["Port", "Service", "State", "CVE / Risk"])
        self._result_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._result_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._result_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._result_table.verticalHeader().setVisible(False)
        self._result_table.verticalHeader().setDefaultSectionSize(40)
        self._result_table.setMinimumHeight(150)
        self._result_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid rgba(0,255,136,0.2);
                border-radius: 4px;
            }
            QTableWidget::item {
                padding: 8px 12px;
                color: #c9d1d9;
                border-bottom: 1px solid rgba(255,255,255,0.04);
            }
            QTableWidget::item:selected {
                background-color: rgba(0,255,136,0.15);
                color: #00ff88;
            }
            QHeaderView::section {
                background-color: #080c10;
                color: rgba(255,255,255,0.45);
                font-size: 11px;
                font-weight: bold;
                letter-spacing: 1px;
                padding: 8px;
                border: none;
                border-bottom: 1px solid rgba(255,255,255,0.08);
            }
        """)
        layout.addWidget(self._result_table, 1)

        # log
        log_lbl = QLabel("Log")
        log_lbl.setObjectName("CardTitle")
        layout.addWidget(log_lbl)

        self._log = QTextEdit()
        self._log.setObjectName("LogArea")
        self._log.setReadOnly(True)
        self._log.setFixedHeight(120)
        layout.addWidget(self._log)

    # ── helpers ───────────────────────────────────────────────────────────────
    def _log_msg(self, msg):
        self._log.append(msg)

    def _on_device_selected(self):
        row = self._dev_table.currentRow()
        if row >= 0:
            ip = self._dev_table.item(row, 0)
            if ip:
                self._target_input.setText(ip.text())

    def _clear_results(self):
        self._result_table.setRowCount(0)
        self._log.clear()

    # ── discovery ─────────────────────────────────────────────────────────────
    def _start_discovery(self):
        self._disc_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._dev_table.setRowCount(0)
        self._log.clear()
        self._log_msg("[*] Discovering devices...")

        self._disc_thread = QThread()
        self._disc_worker = DiscoveryWorker()
        self._disc_worker.moveToThread(self._disc_thread)

        self._disc_thread.started.connect(self._disc_worker.run)
        self._disc_worker.log.connect(self._log_msg)
        self._disc_worker.result.connect(self._show_devices)
        self._disc_worker.done.connect(self._discovery_done)
        self._disc_worker.done.connect(self._disc_thread.quit)
        self._disc_worker.done.connect(self._disc_worker.deleteLater)
        self._disc_thread.finished.connect(self._disc_thread.deleteLater)

        self._disc_thread.start()

    def _show_devices(self, devices):
        self._devices = devices
        self._dev_table.setRowCount(0)
        for d in devices:
            row = self._dev_table.rowCount()
            self._dev_table.insertRow(row)
            self._dev_table.setItem(row, 0, QTableWidgetItem(d.get("ip",       "—")))
            self._dev_table.setItem(row, 1, QTableWidgetItem(d.get("hostname", "—")))
            self._dev_table.setItem(row, 2, QTableWidgetItem(d.get("mac",      "—")))

    def _discovery_done(self):
        self._disc_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._log_msg(f"[+] Done. {len(self._devices)} device(s) found. Click a row to select target.")

    # ── scan ──────────────────────────────────────────────────────────────────
    def _start_scan(self):
        target = self._target_input.text().strip()
        if not target:
            self._log_msg("[!] Enter a target IP or select one from the table.")
            return

        mode        = "quick" if self._mode_combo.currentIndex() == 0 else "deep"
        use_consent = self._consent_check.isChecked()

        # QR consent must run on main thread
        if use_consent:
            from gui.qr_dialog import show_qr_consent
            self._log_msg("[*] Opening QR consent dialog...")
            ok = show_qr_consent(self, target, target, f"{mode.capitalize()} Vulnerability Scan")
            if not ok:
                self._log_msg("[!] Consent denied. Scan aborted.")
                return
            self._log_msg("[+] Consent granted.")

        self._scan_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._result_table.setRowCount(0)
        self._log_msg(f"[*] Starting {mode} scan on {target}...")

        self._scan_thread = QThread()
        self._scan_worker = ScanWorker(target, mode)
        self._scan_worker.moveToThread(self._scan_thread)

        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_worker.log.connect(self._log_msg)
        self._scan_worker.result.connect(self._show_result)
        self._scan_worker.done.connect(self._scan_done)
        self._scan_worker.done.connect(self._scan_thread.quit)
        self._scan_worker.done.connect(self._scan_worker.deleteLater)
        self._scan_thread.finished.connect(self._scan_thread.deleteLater)

        self._scan_thread.start()

    def _show_result(self, result):
        self._result_table.setRowCount(0)
        for p in getattr(result, "open_ports", []):
            row = self._result_table.rowCount()
            self._result_table.insertRow(row)
            port    = str(getattr(p, "port",    p))
            service = str(getattr(p, "service", "—"))
            state   = str(getattr(p, "state",   "open"))
            cve     = str(getattr(p, "cve",     "—"))
            self._result_table.setItem(row, 0, QTableWidgetItem(port))
            self._result_table.setItem(row, 1, QTableWidgetItem(service))
            self._result_table.setItem(row, 2, QTableWidgetItem(state))
            self._result_table.setItem(row, 3, QTableWidgetItem(cve))
            color = {"open": "#ff3b5c", "filtered": "#ffc107", "closed": "#00ff88"}.get(state.lower(), "#c9d1d9")
            self._result_table.item(row, 2).setForeground(QColor(color))

    def _scan_done(self):
        self._scan_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._log_msg("[+] Scan complete.")
