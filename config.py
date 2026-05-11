# config.py — CyberShield Global Configuration
# Author: Kamal | Project: CyberShield v1.0

import os
import platform

# ─── Tool Identity ─────────────────────────────────────────────────────────────
TOOL_NAME    = "CyberShield"
VERSION      = "1.0.0"
AUTHOR       = "Kamal"

# ─── Directories ───────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR   = os.path.join(BASE_DIR, "reports")
DATA_DIR     = os.path.join(BASE_DIR, "data")
QUARANTINE   = os.path.join(BASE_DIR, "quarantine")

for d in [REPORT_DIR, DATA_DIR, QUARANTINE]:
    os.makedirs(d, exist_ok=True)

# ─── Network Defaults ──────────────────────────────────────────────────────────
DEFAULT_TIMEOUT  = 2          # ARP timeout (seconds)
NMAP_ARGS_QUICK  = "-T4 -F"  # Fast scan
NMAP_ARGS_DEEP   = "-T4 -A -sV --script vuln"  # Deep + vuln scripts

# ─── File Cleanup Categories ───────────────────────────────────────────────────
JUNK_EXTENSIONS = [
    ".tmp", ".temp", ".log", ".bak", ".old", ".cache",
    ".dmp", ".swp", "~"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".vbs", ".ps1", ".sh", ".msi",
    ".dll", ".scr", ".pif", ".com", ".cmd"
]

LARGE_FILE_THRESHOLD_MB = 100   # Flag files > 100MB for review

# ─── Malware Signature File ────────────────────────────────────────────────────
MALWARE_SIG_FILE = os.path.join(DATA_DIR, "malware_signatures.json")

# ─── OS Detection ──────────────────────────────────────────────────────────────
CURRENT_OS = platform.system()   # 'Linux', 'Windows', 'Darwin'
