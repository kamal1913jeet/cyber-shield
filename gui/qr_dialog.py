# gui/qr_dialog.py — QR Code Consent Dialog
# Shows the QR code inside the GUI window so the operator
# can see it and share it with the client easily.

import os
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame
)
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal, QTimer
from PyQt6.QtGui import QPixmap, QImage


class ConsentWatcher(QObject):
    """Runs in background thread — watches for client response."""
    authorized = pyqtSignal(bool)

    def __init__(self, server):
        super().__init__()
        self._server = server

    def run(self):
        import time
        from modules.consent_server import CONSENT_TIMEOUT
        start = __import__("time").time()
        while self._server.response is None:
            if time.time() - start >= CONSENT_TIMEOUT:
                self.authorized.emit(False)
                return
            time.sleep(1)
        self.authorized.emit(self._server.response == "yes")


class QRConsentDialog(QDialog):
    """
    Shows the consent QR code inside a GUI dialog.
    Blocks until client responds or timeout.
    Returns True if authorized, False if denied/timeout.
    """

    def __init__(self, parent, qr_path: str, consent_url: str,
                 target_ip: str, hostname: str, operation: str, server):
        super().__init__(parent)
        self.setWindowTitle("CyberShield — Remote Consent")
        self.setMinimumWidth(480)
        self.setModal(True)
        self._result    = False
        self._server    = server
        self._qr_path   = qr_path
        self._watcher_thread = None

        self.setStyleSheet("""
            QDialog {
                background-color: #080c10;
                color: #c9d1d9;
            }
            QLabel { color: #c9d1d9; }
        """)

        self._build_ui(qr_path, consent_url, target_ip, hostname, operation)
        self._start_watcher(server)

        # countdown timer
        self._seconds = 300
        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)

    def _build_ui(self, qr_path, consent_url, target_ip, hostname, operation):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # ── header ────────────────────────────────────────────────────────────
        title = QLabel("🛡  Remote Consent Request")
        title.setStyleSheet("color: #00ff88; font-size: 16px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        sub = QLabel("Send this QR code to your client.\nThey scan it and tap Authorize on their phone.")
        sub.setStyleSheet("color: rgba(255,255,255,0.45); font-size: 12px;")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(sub)

        # ── QR image ──────────────────────────────────────────────────────────
        self._qr_label = QLabel()
        self._qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._qr_label.setMinimumHeight(280)
        self._qr_label.setStyleSheet("""
            background-color: #0d1117;
            border: 1px solid rgba(0,255,136,0.2);
            border-radius: 8px;
            padding: 16px;
        """)
        self._load_qr(qr_path)
        layout.addWidget(self._qr_label)

        # ── info rows ─────────────────────────────────────────────────────────
        info = QFrame()
        info.setStyleSheet("background-color: #0d1117; border: 1px solid rgba(255,255,255,0.06); border-radius: 4px;")
        info_layout = QVBoxLayout(info)
        info_layout.setContentsMargins(14, 12, 14, 12)
        info_layout.setSpacing(6)

        for key, val in [("Target", target_ip), ("Hostname", hostname), ("Operation", operation)]:
            row = QHBoxLayout()
            k = QLabel(key.upper())
            k.setStyleSheet("color: rgba(255,255,255,0.35); font-size: 10px; font-weight: bold; letter-spacing: 1px;")
            k.setFixedWidth(90)
            v = QLabel(val)
            v.setStyleSheet("color: #c9d1d9; font-size: 12px;")
            row.addWidget(k)
            row.addWidget(v)
            row.addStretch()
            info_layout.addLayout(row)

        layout.addWidget(info)

        # ── timer ─────────────────────────────────────────────────────────────
        timer_row = QHBoxLayout()
        t_lbl = QLabel("EXPIRES IN")
        t_lbl.setStyleSheet("color: #ffc107; font-size: 10px; font-weight: bold; letter-spacing: 1px;")
        self._timer_lbl = QLabel("5:00")
        self._timer_lbl.setStyleSheet("color: #ffc107; font-size: 18px; font-weight: bold; font-family: Consolas;")
        timer_row.addWidget(t_lbl)
        timer_row.addStretch()
        timer_row.addWidget(self._timer_lbl)
        layout.addLayout(timer_row)

        # ── status label ──────────────────────────────────────────────────────
        self._status_lbl = QLabel("⏳  Waiting for client response...")
        self._status_lbl.setStyleSheet("color: rgba(255,255,255,0.45); font-size: 12px;")
        self._status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status_lbl)

        # ── url copy row ──────────────────────────────────────────────────────
        url_lbl = QLabel(f"URL: {consent_url}")
        url_lbl.setStyleSheet("color: rgba(255,255,255,0.25); font-size: 10px; font-family: Consolas;")
        url_lbl.setWordWrap(True)
        url_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(url_lbl)

        # ── cancel button ─────────────────────────────────────────────────────
        self._cancel_btn = QPushButton("Cancel Request")
        self._cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255,59,92,0.08);
                border: 1px solid rgba(255,59,92,0.4);
                border-radius: 4px;
                color: #ff3b5c;
                padding: 10px;
                font-size: 13px;
            }
            QPushButton:hover { background-color: rgba(255,59,92,0.15); }
        """)
        self._cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._cancel_btn.clicked.connect(self._cancel)
        layout.addWidget(self._cancel_btn)

    def _load_qr(self, qr_path: str):
        """Load QR PNG into the label."""
        if os.path.exists(qr_path):
            pixmap = QPixmap(qr_path)
            scaled = pixmap.scaled(
                260, 260,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            self._qr_label.setPixmap(scaled)
        else:
            self._qr_label.setText("QR image not found.\nShare the URL below manually.")
            self._qr_label.setStyleSheet(
                "color: rgba(255,255,255,0.4); font-size: 12px;"
                "background-color: #0d1117; border: 1px solid rgba(255,255,255,0.06);"
                "border-radius: 8px; padding: 16px;"
            )

    def _tick(self):
        self._seconds -= 1
        m = self._seconds // 60
        s = self._seconds % 60
        self._timer_lbl.setText(f"{m}:{s:02d}")
        if self._seconds <= 60:
            self._timer_lbl.setStyleSheet("color: #ff3b5c; font-size: 18px; font-weight: bold; font-family: Consolas;")
        if self._seconds <= 0:
            self._timer.stop()
            self._on_response(False)

    def _start_watcher(self, server):
        self._watcher_thread = QThread()
        self._watcher        = ConsentWatcher(server)
        self._watcher.moveToThread(self._watcher_thread)
        self._watcher_thread.started.connect(self._watcher.run)
        self._watcher.authorized.connect(self._on_response)
        self._watcher_thread.start()

    def _on_response(self, authorized: bool):
        self._timer.stop()
        self._result = authorized

        if self._watcher_thread and self._watcher_thread.isRunning():
            self._watcher_thread.quit()

        if authorized:
            self._status_lbl.setText("✅  Client authorized the scan!")
            self._status_lbl.setStyleSheet("color: #00ff88; font-size: 13px; font-weight: bold;")
        else:
            self._status_lbl.setText("🚫  Request denied or timed out.")
            self._status_lbl.setStyleSheet("color: #ff3b5c; font-size: 13px; font-weight: bold;")

        self._cancel_btn.setText("Close")
        # auto close after 2 seconds
        QTimer.singleShot(2000, self.accept)

    def _cancel(self):
        self._result = False
        if self._watcher_thread and self._watcher_thread.isRunning():
            self._watcher_thread.quit()
        self._timer.stop()
        self.reject()

    def get_result(self) -> bool:
        return self._result


# ── helper function called from scan/cleanup/hardening pages ──────────────────
def show_qr_consent(parent, target_ip: str, hostname: str, operation: str) -> bool:
    """
    Full flow:
      1. Starts Flask + ngrok
      2. Generates QR
      3. Shows QR dialog in GUI
      4. Returns True if client authorized
    """
    import threading
    import time
    import socket
    from modules.consent_server import (
        ConsentServer, _start_ngrok, _generate_qr, PORT, CONSENT_TIMEOUT
    )

    server = ConsentServer()

    # start Flask
    flask_thread = threading.Thread(target=server._run_flask, daemon=True)
    flask_thread.start()
    time.sleep(1.5)

    # start ngrok
    public_base = _start_ngrok(PORT)
    if not public_base:
        return False

    # build consent URL
    consent_url = (
        f"{public_base}/consent/{server.token}"
        f"?ip={target_ip}"
        f"&host={hostname}"
        f"&req={socket.gethostname()}"
        f"&op={operation.replace(' ', '+')}"
    )

    # generate QR PNG
    qr_path = "qr_consent.png"
    _generate_qr(consent_url, save_path=qr_path)

    # show dialog
    dialog = QRConsentDialog(
        parent      = parent,
        qr_path     = qr_path,
        consent_url = consent_url,
        target_ip   = target_ip,
        hostname    = hostname,
        operation   = operation,
        server      = server,
    )
    dialog.exec()
    return dialog.get_result()
