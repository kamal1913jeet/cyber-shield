# modules/consent.py — Legal Consent & Authorization Module
# This module ensures the user explicitly authorizes every sensitive operation.
# Never perform file operations without passing through this gate first.

import datetime
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()

# ──────────────────────────────────────────────────────────────────────────────
LEGAL_TEXT = """
╔══════════════════════════════════════════════════════════════════════════════╗
║               CYBERSHIELD — AUTHORIZATION & CONSENT AGREEMENT               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  IMPORTANT: READ THIS CAREFULLY BEFORE PROCEEDING                           ║
║                                                                              ║
║  By clicking YES, you confirm and agree to ALL of the following:            ║
║                                                                              ║
║  1. AUTHORIZED USE ONLY                                                     ║
║     You are the legal owner or authorized administrator of the device(s)    ║
║     being scanned. Scanning devices you do not own or have explicit         ║
║     written permission to test is ILLEGAL under:                            ║
║       • Computer Fraud and Abuse Act (CFAA) — USA                          ║
║       • Computer Misuse Act 1990 — UK                                      ║
║       • IT Act 2000, Section 43 & 66 — India                               ║
║       • And equivalent laws in your jurisdiction.                           ║
║                                                                              ║
║  2. FILE OPERATIONS CONSENT                                                 ║
║     You authorize CyberShield to:                                           ║
║       • Read and analyze files on THIS local machine only                  ║
║       • Suggest deletion of junk/temp files                                 ║
║       • Quarantine files suspected of containing malware                    ║
║     No file will be deleted without your explicit per-file confirmation.    ║
║                                                                              ║
║  3. DATA PRIVACY                                                             ║
║     CyberShield does NOT:                                                   ║
║       • Transmit any of your files or scan results to external servers      ║
║       • Store personal data outside this machine                            ║
║       • Share results with any third party                                  ║
║                                                                              ║
║  4. DISCLAIMER OF LIABILITY                                                 ║
║     The authors of CyberShield accept NO liability for:                     ║
║       • Data loss resulting from user-authorized file deletions             ║
║       • Misuse of this tool for unauthorized scanning                       ║
║       • Inaccurate vulnerability reports                                    ║
║                                                                              ║
║  5. ETHICAL USE                                                              ║
║     This tool is intended for DEFENSIVE security purposes only.             ║
║     Any offensive or malicious use is strictly prohibited.                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


def get_consent(operation: str, target: str = "local machine") -> bool:
    """
    Display the legal consent form for a specific operation and return
    True only if the user explicitly accepts.

    Args:
        operation : Short description e.g. "File Cleanup", "Vulnerability Scan"
        target    : IP or machine description being operated on
    """
    console.print(LEGAL_TEXT, style="bold white")

    console.print(Panel(
        f"[bold yellow]Requested Operation:[/bold yellow] {operation}\n"
        f"[bold yellow]Target:[/bold yellow]              {target}\n"
        f"[bold yellow]Timestamp:[/bold yellow]           {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="[red] Authorization Request[/red]",
        border_style="red"
    ))

    console.print(
        "\n[bold red]Do you understand and accept ALL terms above?[/bold red]\n"
        "[dim](This is a legally binding confirmation of your authorization)[/dim]\n"
    )

    accepted = Confirm.ask("[bold]I authorize this operation[/bold]", default=False)

    if accepted:
        console.print("\n[green] Authorization granted. Proceeding...[/green]\n")
        _log_consent(operation, target)
    else:
        console.print("\n[yellow] Operation cancelled. No changes were made.[/yellow]\n")

    return accepted


def _log_consent(operation: str, target: str) -> None:
    """Write a consent audit log entry (good practice for forensics)."""
    import os
    log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports", "consent_audit.log")
    with open(log_path, "a") as f:
        f.write(
            f"[{datetime.datetime.now().isoformat()}] "
            f"AUTHORIZED | Operation: {operation} | Target: {target}\n"
        )
