# cyber-shield
CyberShield is a Python-based defensive cybersecurity toolkit for Windows that covers network discovery, port scanning with CVE lookup, OS hardening audit, file quarantine, and PDF report generation — all gated behind a legal consent system with web, QR code, and SMS support. Built with pure Python, no nmap or external security binaries required.
# 🛡️ CyberShield

> A Python-based defensive cybersecurity toolkit for Windows — built to audit, monitor, and harden systems without relying on external security binaries like nmap.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

---

## 📌 What is CyberShield?

CyberShield is a modular, Python-only defensive security tool that helps security professionals and system administrators perform full network audits, identify vulnerabilities, harden OS configurations, and clean up suspicious files — all from a single unified interface running on Windows.

No nmap. No third-party security binaries. Just pure Python.

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🔐 **Legal Consent Gate** | Terminal + web-based consent form before any scan begins |
| 📡 **Network Discovery** | Ping sweep to identify all live hosts on the network |
| 🔎 **Port Scanner + CVE Lookup** | Socket-based port scanning with vulnerability cross-referencing |
| 🛠️ **OS Hardening Audit** | Checks system config and provides actionable fix steps |
| 🗂️ **File Cleanup Engine** | Detects and quarantines suspicious files safely |
| 📄 **PDF Report Generator** | Exports a full audit report in professional PDF format |
| 📲 **QR Code + SMS Delivery** | Consent link delivered via QR code or SMS |

---

## 🔁 How It Works

```
User Launches CyberShield
          │
          ▼
 ┌─────────────────────┐
 │  Legal Consent Gate │ ◄── Terminal / Web UI / QR Code / SMS
 └────────┬────────────┘
          │
          ▼
 ┌─────────────────────┐
 │  Network Ping Sweep │ ──► Discovers all live hosts on the network
 └────────┬────────────┘
          │
          ▼
 ┌──────────────────────────┐
 │ Port Scan + CVE Lookup   │ ──► Flags open ports & known vulnerabilities
 └────────┬─────────────────┘
          │
          ▼
 ┌──────────────────────────┐
 │  OS Hardening Audit      │ ──► Detects misconfigs, gives fix steps
 └────────┬─────────────────┘
          │
          ▼
 ┌──────────────────────────┐
 │  File Cleanup + Quarantine│ ──► Isolates suspicious files safely
 └────────┬─────────────────┘
          │
          ▼
 ┌──────────────────────────┐
 │  PDF Report Generation   │ ──► Full summary exported to PDF
 └──────────────────────────┘
```

---

## 🧩 Module Breakdown

### 🔐 Legal Consent Gate
Before any scan runs, CyberShield requires explicit authorization. The user is presented with a consent form through:
- Terminal prompt
- Local web server (Flask-based)
- QR code for mobile access
- SMS link delivery

This ensures every scan is legally authorized and ethically compliant.

---

### 📡 Network Discovery (Ping Sweep)
Scans a defined IP range using ICMP requests to identify all live and responsive devices on the network. Outputs a clean list of active hosts before deeper scanning begins.

---

### 🔎 Port Scanner + CVE Lookup
Uses raw Python `socket` connections (no nmap) to:
- Scan open ports on each discovered host
- Identify running services
- Cross-reference services against CVE databases to flag known vulnerabilities

---

### 🛠️ OS Hardening Audit
Audits the host machine's security posture by checking:
- Firewall status
- Open network shares
- Unnecessary running services
- Weak user account policies
- Other common misconfigurations

Each finding comes with a clear, actionable fix step.

---

### 🗂️ File Cleanup Engine
Scans the filesystem for suspicious or potentially harmful files. Instead of permanently deleting them, flagged files are moved to an isolated **quarantine folder** — keeping them recoverable in case of false positives.

---

### 📄 PDF Report Generator
After all modules complete, CyberShield compiles everything into a professional PDF report covering:
- Discovered devices and open ports
- Identified CVEs and risk levels
- OS hardening issues and recommended fixes
- List of quarantined files

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Windows OS
- PyCharm (recommended IDE)

### Installation

```bash
git clone https://github.com/yourusername/cybershield.git
cd cybershield
pip install -r requirements.txt
```

### Run CyberShield

```bash
python main.py
```

---

## 📁 Project Structure

```
cybershield/
│
├── consent/            # Legal consent gate (terminal + web)
├── discovery/          # Ping sweep & network mapping
├── scanner/            # Port scanner & CVE lookup
├── hardening/          # OS audit & fix recommendations
├── cleanup/            # File scanner & quarantine engine
├── report/             # PDF report generator
├── utils/              # Shared utilities (QR, SMS, logging)
├── main.py             # Entry point
└── requirements.txt
```

---

## 🛡️ Disclaimer

CyberShield is intended for **authorized security auditing only**. Always ensure you have explicit permission before scanning any network or system. Unauthorized use is illegal and unethical. The built-in consent gate enforces this by design.

---

## 👨‍💻 Author

**Kamal** — Python Developer | Security Tooling  
📍 Mohali, Punjab, India

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
