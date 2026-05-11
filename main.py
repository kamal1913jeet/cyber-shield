#!/usr/bin/env python3
# main.py — CyberShield Entry Point

import sys
import os
import time
import platform

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich import box
from rich.table import Table

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import TOOL_NAME, VERSION, AUTHOR
from modules.network_scanner import (
    get_local_subnet, arp_scan, display_devices, select_target
)
from modules.vuln_scanner import (
    run_quick_scan, run_deep_scan,
    display_scan_result, choose_scan_type
)
from modules.consent import get_consent
from modules.consent_server import get_remote_consent
from modules.file_cleaner import run_cleanup_wizard
from modules.hardener import SystemHardener, display_hardening_report
from modules.reporter import generate_report

console = Console()

BANNER = r"""
   _____      _               _____ _     _      _     _
  / ____|    | |             / ____| |   (_)    | |   | |
 | |    _   _| |__   ___ _ | (___ | |__  _  ___| | __| |
 | |   | | | | '_ \ / _ \ '__\___ \| '_ \| |/ _ \ |/ _` |
 | |___| |_| | |_) |  __/ |  ____) | | | | |  __/ | (_| |
  \_____\__, |_.__/ \___|_| |_____/|_| |_|_|\___|_|\__,_|
         __/ |
        |___/
"""


def print_banner():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(Panel(
        f"[bold green]{TOOL_NAME} v{VERSION}[/bold green] — Defensive Security Toolkit\n"
        f"[dim]by {AUTHOR} | For authorized use only[/dim]",
        box=box.DOUBLE_EDGE,
        border_style="cyan"
    ))
    console.print()


def main_menu() -> str:
    console.print("[bold cyan]=== Main Menu ===[/bold cyan]")
    console.print("  [1] Scan Network  - discover nearby devices")
    console.print("  [2] File Cleanup  - scan & clean this machine")
    console.print("  [3] Harden System - security configuration audit")
    console.print("  [4] Full Scan + Report - run everything and export PDF")
    console.print("  [0] Exit")
    console.print("\nChoice: ", end="")
    return input().strip()


# ─────────────────────────────────────────────────────────────────────────────
def _choose_consent_method(target_ip: str, hostname: str, operation: str) -> bool:
    console.print("\n[bold cyan]--- Consent Method ---[/bold cyan]")
    console.print("  [1] Remote QR  - generate QR code, send PNG to client, they authorize from anywhere")
    console.print("  [2] Terminal   - authorize here on this machine")
    console.print("\nChoice: ", end="")
    choice = input().strip()

    if choice == "1":
        return get_remote_consent(target_ip, hostname, operation)
    else:
        return get_consent(operation=operation, target=target_ip)
def flow_network_scan():
    """Discover devices then vulnerability scan with web consent."""
    console.print("\n[bold cyan]--- Network Discovery ---[/bold cyan]")

    subnet = get_local_subnet()
    console.print(f"[dim]Detected subnet: {subnet}[/dim]")

    devices = arp_scan(subnet)
    if not devices:
        console.print("[red]No devices found.[/red]")
        return None, None

    display_devices(devices)
    target = select_target(devices)
    if not target:
        return None, None

    scan_type = choose_scan_type()
    if scan_type is None:
        return target, None

    operation = f"{'Quick' if scan_type == 'quick' else 'Deep Vulnerability'} Scan"

    # Web or terminal consent
    authorized = _choose_consent_method(target.ip, target.hostname, operation)
    if not authorized:
        return target, None

    if scan_type == "quick":
        result = run_quick_scan(target.ip)
    else:
        result = run_deep_scan(target.ip)

    display_scan_result(result)
    return target, result


def flow_file_cleanup():
    """File cleanup with consent."""
    console.print("\n[bold cyan]--- File Cleanup Wizard ---[/bold cyan]")

    local_ip   = get_local_subnet().replace(".0/24", ".1")
    authorized = _choose_consent_method(
        local_ip,
        platform.node(),
        "File System Cleanup & Malware Scan"
    )
    if not authorized:
        return None

    return run_cleanup_wizard()


def flow_harden():
    """Security hardening checks."""
    console.print("\n[bold cyan]--- Security Hardening Audit ---[/bold cyan]")
    hardener = SystemHardener()
    report   = hardener.run_all_checks()
    display_hardening_report(report)
    return report


def flow_full():
    """Run everything and generate PDF report."""
    console.print("\n[bold green]=== Full Security Audit Mode ===[/bold green]\n")

    scan_result      = None
    cleanup_report   = None
    hardening_report = None
    target_ip        = "Local Machine"

    if Confirm.ask("Run network device scan?", default=True):
        target, scan_result = flow_network_scan()
        if target:
            target_ip = target.ip

    if Confirm.ask("\nRun file cleanup on this machine?", default=True):
        cleanup_report = flow_file_cleanup()

    if Confirm.ask("\nRun security hardening audit?", default=True):
        hardening_report = flow_harden()

    console.print("\n[bold]Generating PDF report...[/bold]")
    report_path = generate_report(
        target_ip=target_ip,
        scan_result=scan_result,
        cleanup_report=cleanup_report,
        hardening_report=hardening_report,
    )

    console.print(Panel(
        f"[bold green]Report saved to:[/bold green]\n{report_path}",
        title="[bold]Audit Complete[/bold]",
        border_style="green"
    ))

    _print_summary(scan_result, cleanup_report, hardening_report)


def _print_summary(scan_result, cleanup_report, hardening_report):
    table = Table(title="[bold]Session Summary[/bold]", box=box.ROUNDED)
    table.add_column("Module",  style="bold cyan", width=26)
    table.add_column("Result",  width=42)

    if scan_result:
        table.add_row(
            "Vulnerability Scan",
            f"Risk: {scan_result.risk_level} | Open ports: {len(scan_result.open_ports)}"
        )
    if cleanup_report:
        table.add_row(
            "File Cleanup",
            f"Deleted: {len(cleanup_report.deleted)} | "
            f"Quarantined: {len(cleanup_report.quarantined)} | "
            f"Freed: {cleanup_report.space_freed_mb:.1f} MB"
        )
    if hardening_report:
        table.add_row(
            "Security Hardening",
            f"Score: {hardening_report.score}/100 | "
            f"Findings: {len(hardening_report.findings)}"
        )

    console.print(table)
    console.print("\n[bold green]Stay safe. Run audits regularly.[/bold green]\n")


# ─────────────────────────────────────────────────────────────────────────────
def main():
    print_banner()
    while True:
        choice = main_menu()
        console.print()

        if   choice == "1": flow_network_scan()
        elif choice == "2": flow_file_cleanup()
        elif choice == "3": flow_harden()
        elif choice == "4": flow_full()
        elif choice == "0":
            console.print("[dim]Goodbye. Keep your systems secure.[/dim]\n")
            sys.exit(0)
        else:
            console.print("[red]Invalid option.[/red]")

        console.print()
        time.sleep(0.5)


if __name__ == "__main__":
    main()
