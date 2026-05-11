# modules/reporter.py — PDF Report Generator

import datetime
import os
from typing import Optional

from fpdf import FPDF
from rich.console import Console

from config import REPORT_DIR, TOOL_NAME, VERSION

console = Console()


# ──────────────────────────────────────────────────────────────────────────────
FUTURE_SUGGESTIONS = [
    ("Keep Software Updated",
     "Always apply OS and application patches within 72 hours of release. "
     "Unpatched software is the #1 entry point for attackers."),
    ("Enable Multi-Factor Authentication",
     "Enable MFA on all accounts especially email, banking, and SSH access. "
     "A compromised password alone will not be enough to breach your account."),
    ("Use a Password Manager",
     "Never reuse passwords. Use Bitwarden or KeePassXC to generate and store "
     "unique credentials for every service you use."),
    ("Network Segmentation",
     "Separate IoT devices onto a guest VLAN. Printers, smart TVs, and cameras "
     "should never share a network segment with sensitive machines."),
    ("Regular Backups - 3-2-1 Rule",
     "Keep 3 copies of data, on 2 different media types, with 1 stored offsite. "
     "Test restoration monthly - backups that cannot be restored are worthless."),
    ("Monitor Authentication Logs",
     "Review auth logs or Event Viewer weekly. Unexpected login attempts are "
     "early warning signs of a compromise attempt on your system."),
    ("Disable Unused Services",
     "Every open port is an attack surface. Stop and disable services you do not "
     "actively use such as telnet, FTP, NetBIOS, SMBv1, and others."),
    ("Encrypt Sensitive Data at Rest",
     "Use LUKS on Linux, FileVault on macOS, or BitLocker on Windows for full "
     "disk encryption. Encrypt individual files with GPG when sharing."),
    ("Security Awareness Training",
     "90 percent of breaches start with phishing. Always verify email sender "
     "addresses, hover links before clicking, never open unexpected attachments."),
    ("Run Periodic Security Scans",
     "Re-run CyberShield monthly. Also consider running Malwarebytes or ClamAV "
     "for layered defence against malware and other threats."),
]


def _safe_text(text: str) -> str:
    """Remove or replace any character outside latin-1 range."""
    replacements = {
        '\u2014': '-', '\u2013': '-', '\u2022': '*',
        '\u2019': "'", '\u2018': "'", '\u201c': '"',
        '\u201d': '"', '\u2026': '...', '\u2192': '->',
        '\u2713': 'OK', '\u2717': 'X', '\u26a0': '!',
        '\u2714': 'OK', '\u2718': 'X',
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    # Final fallback — drop anything still outside latin-1
    return text.encode('latin-1', errors='replace').decode('latin-1')


def _truncate(text: str, max_chars: int = 90) -> str:
    """Truncate long strings so they fit in PDF cells."""
    text = _safe_text(text)
    return text if len(text) <= max_chars else text[:max_chars - 3] + "..."


# ──────────────────────────────────────────────────────────────────────────────
class SecurityReport(FPDF):

    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_fill_color(30, 30, 50)
        self.set_text_color(255, 255, 255)
        title = _safe_text(f" {TOOL_NAME} v{VERSION} - Security Report")
        self.cell(0, 12, title, ln=True, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128)
        self.cell(0, 10,
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} | "
            f"Page {self.page_no()}/{{nb}}",
            align="C")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(220, 230, 245)
        self.set_text_color(20, 20, 80)
        self.cell(0, 9, _safe_text(f"  {title}"), ln=True, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def safe_multi_cell(self, text: str, size: int = 10):
        """multi_cell wrapper that guarantees text fits."""
        self.set_font("Helvetica", size=size)
        clean = _safe_text(str(text))
        # Break into lines of max 95 chars manually to avoid FPDF width errors
        words = clean.split()
        line  = ""
        for word in words:
            if len(line) + len(word) + 1 > 95:
                self.cell(0, 6, line, ln=True)
                line = word
            else:
                line = f"{line} {word}".strip()
        if line:
            self.cell(0, 6, line, ln=True)
        self.ln(1)

    def row(self, label: str, value: str):
        self.set_font("Helvetica", "B", 10)
        self.cell(55, 7, _safe_text(label), border="B")
        self.set_font("Helvetica", size=10)
        self.cell(0, 7, _truncate(value, 80), border="B", ln=True)


# ──────────────────────────────────────────────────────────────────────────────
def generate_report(
    target_ip: str,
    scan_result=None,
    cleanup_report=None,
    hardening_report=None,
    output_path=None,       # ← add this
) -> str:

    pdf = SecurityReport()
    pdf.alias_nb_pages()
    pdf.add_page()

    # ── Overview ──────────────────────────────────────────────────────────────
    pdf.section_title("Scan Overview")
    pdf.row("Target IP",    target_ip)
    pdf.row("Scan Date",    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    pdf.row("Tool Version", f"{TOOL_NAME} v{VERSION}")
    pdf.ln(4)

    # ── Vulnerability Scan ────────────────────────────────────────────────────
    if scan_result:
        pdf.section_title("Vulnerability Scan Results")
        pdf.row("Detected OS",  scan_result.os_guess)
        pdf.row("Risk Level",   scan_result.risk_level)
        pdf.row("Open Ports",   str(len(scan_result.open_ports)))
        pdf.ln(3)

        if scan_result.open_ports:
            # Table header
            pdf.set_font("Helvetica", "B", 9)
            col_w = [18, 22, 40, 110]
            for w, h in zip(col_w, ["Port", "Service", "Status", "CVEs / Issues"]):
                pdf.cell(w, 8, h, border=1)
            pdf.ln()
            pdf.set_font("Helvetica", size=8)

            for p in scan_result.open_ports:
                cve_str = _truncate(p.cves[0] if p.cves else "None", 60)
                for w, val in zip(col_w, [
                    str(p.port), p.service, p.state, cve_str
                ]):
                    pdf.cell(w, 7, _safe_text(val), border=1)
                pdf.ln()
            pdf.ln(4)

    # ── File Cleanup ──────────────────────────────────────────────────────────
    if cleanup_report:
        pdf.section_title("File Cleanup Summary")
        pdf.row("Files Scanned",     str(cleanup_report.scanned_count))
        pdf.row("Files Deleted",     str(len(cleanup_report.deleted)))
        pdf.row("Files Quarantined", str(len(cleanup_report.quarantined)))
        pdf.row("Files Skipped",     str(len(cleanup_report.skipped)))
        pdf.row("Space Freed (MB)",  f"{cleanup_report.space_freed_mb:.2f} MB")
        pdf.ln(3)

        if cleanup_report.deleted:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, "Deleted Files:", ln=True)
            pdf.set_font("Helvetica", size=8)
            for f in cleanup_report.deleted[:20]:
                pdf.cell(0, 6, _truncate(f"  * {f}", 95), ln=True)
            if len(cleanup_report.deleted) > 20:
                pdf.cell(0, 6, f"  ... and {len(cleanup_report.deleted)-20} more", ln=True)
        pdf.ln(3)

    # ── Hardening ─────────────────────────────────────────────────────────────
    if hardening_report:
        pdf.section_title(f"Security Hardening - Score: {hardening_report.score}/100")
        icons = {"PASS": "[OK]", "WARN": "[!!]", "FAIL": "[XX]"}

        for f in hardening_report.findings:
            icon = icons.get(f.status, "[ ]")
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, _safe_text(f"{icon} {f.check}"), ln=True)

            pdf.set_font("Helvetica", size=9)
            pdf.safe_multi_cell(f"Detail: {f.detail}")

            if f.fix:
                pdf.set_font("Helvetica", "I", 9)
                pdf.safe_multi_cell(f"Fix: {f.fix}")

            if f.steps:
                pdf.set_font("Helvetica", size=8)
                for i, step in enumerate(f.steps[:6], 1):
                    pdf.safe_multi_cell(f"  {i}. {step}", size=8)

            pdf.ln(2)

    # ── Future Suggestions ────────────────────────────────────────────────────
    pdf.add_page()
    pdf.section_title("Future Security Recommendations")

    for i, (title, description) in enumerate(FUTURE_SUGGESTIONS, 1):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, _safe_text(f"{i}. {title}"), ln=True)
        pdf.set_font("Helvetica", size=9)
        pdf.safe_multi_cell(description)
        pdf.ln(2)

    # ── Save ──────────────────────────────────────────────────────────────────
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = output_path or os.path.join(REPORT_DIR, f"cybershield_report_{timestamp}.pdf")
    pdf.output(filename)
    return filename
