#!/usr/bin/env python3
# cli/commands.py — CyberShield Secret CLI
# ─────────────────────────────────────────
# LONG FORM (professional):
#   python cybershield.py scan    --target 192.168.1.5 --mode quick
#   python cybershield.py scan    --target 192.168.1.5 --mode deep --cs
#   python cybershield.py clean   --path C:/Users
#   python cybershield.py clean   --cs
#   python cybershield.py harden  --report
#   python cybershield.py full    --target 192.168.1.5 --output report.pdf
#   python cybershield.py consent --target 192.168.1.5 --host my-laptop
#   python cybershield.py discover
#
# SHORT FORM (secret — only you know):
#   python cybershield.py s  -t 192.168.1.5 -m q
#   python cybershield.py s  -t 192.168.1.5 -m d --cs
#   python cybershield.py c  -p C:/Users
#   python cybershield.py c  --cs
#   python cybershield.py hz -r
#   python cybershield.py f  -t 192.168.1.5 -o report.pdf
#   python cybershield.py cs -t 192.168.1.5 -hn my-laptop
#   python cybershield.py d

import sys
import os
import platform
import argparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

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


def _print_cli_banner():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(Panel(
        "[bold green]CyberShield CLI[/bold green] — Defensive Security Toolkit\n"
        "[dim]Authorized use only. All operations require consent.[/dim]",
        border_style="cyan",
        box=box.DOUBLE_EDGE
    ))
    console.print()


def _print_help():
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold cyan",
        border_style="dim"
    )
    table.add_column("Command",   style="bold green",  width=12)
    table.add_column("Short",     style="bold yellow", width=8)
    table.add_column("Arguments", style="cyan",        width=36)
    table.add_column("Description")

    rows = [
        ("discover", "d",   "",                                      "Discover all devices on network"),
        ("scan",     "s",   "-t IP [-m q/d] [--cs]",                "Port scan + CVE lookup"),
        ("clean",    "c",   "[-p PATH] [--cs]",                     "File cleanup & malware scan"),
        ("harden",   "hz",  "[-r]",                                  "OS security hardening audit"),
        ("full",     "f",   "[-t IP] [-o FILE] [--cs]",             "Full suite + PDF report"),
        ("consent",  "cs", "-t IP [-hn HOST] [-op OPERATION]",     "Send remote QR consent only"),
    ]

    for cmd, short, args, desc in rows:
        table.add_row(cmd, short, args, desc)

    console.print("[bold]Available Commands:[/bold]")
    console.print(table)
    console.print()
    console.print("[dim]  -m q = quick scan    -m d = deep scan[/dim]")
    console.print("[dim]  --cs = use remote QR consent[/dim]")
    console.print("[dim]  -r   = save PDF report[/dim]")
    console.print()
    console.print("[dim]Examples:[/dim]")
    console.print("[dim]  python cybershield.py scan -t 192.168.1.5 -m q[/dim]")
    console.print("[dim]  python cybershield.py s -t 192.168.1.5 -m d --cs[/dim]")
    console.print("[dim]  python cybershield.py hz -r[/dim]")
    console.print("[dim]  python cybershield.py f -t 192.168.1.5 -o report.pdf --cs[/dim]")
    console.print()


# ── unified argument parser ───────────────────────────────────────────────────
def _build_parser():
    parser = argparse.ArgumentParser(
        prog="cybershield",
        description="CyberShield — Defensive Security Toolkit",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true")

    sub = parser.add_subparsers(dest="command")

    # discover / -d
    for name in ("discover", "d"):
        sub.add_parser(name)

    # scan / -s
    for name in ("scan", "s"):
        p = sub.add_parser(name)
        p.add_argument("-t", "--target",  required=True)
        p.add_argument("-m", "--mode",    default="quick",
                       choices=["quick", "deep", "q", "d"])
        p.add_argument("--cs", "--consent", dest="consent", action="store_true")

    # clean / -c
    for name in ("clean", "c"):
        p = sub.add_parser(name)
        p.add_argument("-p", "--path",    default=None)
        p.add_argument("--cs", "--consent", dest="consent", action="store_true")

    # harden / -hz
    for name in ("harden", "hz"):
        p = sub.add_parser(name)
        p.add_argument("-r", "--report",  action="store_true")

    # full / -f
    for name in ("full", "f"):
        p = sub.add_parser(name)
        p.add_argument("-t", "--target",  default=None)
        p.add_argument("-o", "--output",  default=None)
        p.add_argument("--cs", "--consent", dest="consent", action="store_true")

    # consent / -cs
    for name in ("consent", "cs"):
        p = sub.add_parser(name)
        p.add_argument("-t",  "--target", required=True)
        p.add_argument("-hn", "--host",   default="Unknown")
        p.add_argument("-op", "--op",     default="Security Audit")

    return parser


# ── handlers ──────────────────────────────────────────────────────────────────
def _handle_discover():
    from modules.network_scanner import get_local_subnet, arp_scan

    console.print("\n[bold cyan]Discovering devices on network...[/bold cyan]\n")
    subnet  = get_local_subnet()
    console.print(f"[dim]Subnet: {subnet}[/dim]")
    devices = arp_scan(subnet)

    if not devices:
        console.print("[yellow]No devices found.[/yellow]")
        return

    table = Table(
        title=f"[bold]Devices Found ({len(devices)})[/bold]",
        box=box.ROUNDED,
        border_style="cyan"
    )
    table.add_column("IP Address", style="bold green")
    table.add_column("Hostname",   style="cyan")
    table.add_column("MAC",        style="dim")

    for d in devices:
        table.add_row(
            str(getattr(d, "ip",       d)),
            str(getattr(d, "hostname", "Unknown")),
            str(getattr(d, "mac",      "—")),
        )

    console.print(table)


def _handle_scan(args):
    from modules.vuln_scanner import run_quick_scan, run_deep_scan, display_scan_result
    from modules.consent_server import get_remote_consent
    from modules.consent import get_consent

    target = args.target
    mode   = "quick" if args.mode in ("quick", "q") else "deep"

    console.print(Panel(
        f"[bold]Target:[/bold] [cyan]{target}[/cyan]\n"
        f"[bold]Mode:[/bold]   [cyan]{mode.upper()}[/cyan]",
        title="[bold cyan]◎ Vulnerability Scan[/bold cyan]",
        border_style="cyan"
    ))

    if args.consent:
        ok = get_remote_consent(target, target, f"{mode.capitalize()} Vulnerability Scan")
    else:
        ok = get_consent(operation=f"{mode.capitalize()} Scan", target=target)

    if not ok:
        console.print("[red]✖ Consent denied. Aborting.[/red]")
        return

    console.print(f"\n[cyan]Running {mode} scan...[/cyan]")
    result = run_quick_scan(target) if mode == "quick" else run_deep_scan(target)
    display_scan_result(result)


def _handle_clean(args):
    from modules.file_cleaner import run_cleanup_wizard
    from modules.consent_server import get_remote_consent
    from modules.consent import get_consent

    local_ip = "127.0.0.1"
    hostname = platform.node()

    console.print(Panel(
        f"[bold]Machine:[/bold] [cyan]{hostname}[/cyan]\n"
        f"[bold]Path:[/bold]    [cyan]{args.path or 'Auto-detect'}[/cyan]",
        title="[bold cyan]◈ File Cleanup[/bold cyan]",
        border_style="cyan"
    ))

    if args.consent:
        ok = get_remote_consent(local_ip, hostname, "File System Cleanup")
    else:
        ok = get_consent(operation="File System Cleanup", target=local_ip)

    if not ok:
        console.print("[red]✖ Consent denied. Aborting.[/red]")
        return

    run_cleanup_wizard()


def _handle_harden(args):
    from modules.hardener import SystemHardener, display_hardening_report
    from modules.reporter import generate_report

    console.print(Panel(
        f"[bold]Machine:[/bold] [cyan]{platform.node()}[/cyan]\n"
        f"[bold]OS:[/bold]      [cyan]{platform.system()} {platform.release()}[/cyan]",
        title="[bold cyan]◆ Security Hardening Audit[/bold cyan]",
        border_style="cyan"
    ))

    hardener = SystemHardener()
    report   = hardener.run_all_checks()
    display_hardening_report(report)

    if args.report:
        path = generate_report(
            target_ip        = platform.node(),
            scan_result      = None,
            cleanup_report   = None,
            hardening_report = report,
        )
        console.print(Panel(
            f"[bold green]✔ Report saved[/bold green]\n→ {path}",
            border_style="green"
        ))


def _handle_full(args):
    from modules.vuln_scanner import run_deep_scan, display_scan_result
    from modules.file_cleaner import run_cleanup_wizard
    from modules.hardener import SystemHardener, display_hardening_report
    from modules.reporter import generate_report
    from modules.consent_server import get_remote_consent
    from modules.consent import get_consent

    target_ip        = args.target or platform.node()
    scan_result      = None
    cleanup_report   = None
    hardening_report = None

    console.print(Panel(
        f"[bold green]Full Security Audit[/bold green]\n"
        f"Target: [cyan]{target_ip}[/cyan]",
        border_style="green"
    ))

    # single consent for entire session
    if args.consent:
        ok = get_remote_consent(target_ip, target_ip, "Full Security Audit")
    else:
        ok = get_consent(operation="Full Security Audit", target=target_ip)

    if not ok:
        console.print("[red]✖ Consent denied. Aborting.[/red]")
        return

    if args.target:
        console.rule("[cyan]Vulnerability Scan[/cyan]")
        scan_result = run_deep_scan(args.target)
        display_scan_result(scan_result)

    console.rule("[cyan]File Cleanup[/cyan]")
    cleanup_report = run_cleanup_wizard()

    console.rule("[cyan]Hardening Audit[/cyan]")
    hardener         = SystemHardener()
    hardening_report = hardener.run_all_checks()
    display_hardening_report(hardening_report)

    console.rule("[cyan]Generating PDF Report[/cyan]")
    path = generate_report(
        target_ip        = target_ip,
        scan_result      = scan_result,
        cleanup_report   = cleanup_report,
        hardening_report = hardening_report,
        output_path      = args.output,
    )

    console.print(Panel(
        f"[bold green]✔ Full audit complete![/bold green]\n"
        f"Report → [underline]{path}[/underline]",
        border_style="green"
    ))


def _handle_consent(args):
    from modules.consent_server import get_remote_consent

    console.print(Panel(
        f"[bold]Target:[/bold]    [cyan]{args.target}[/cyan]\n"
        f"[bold]Hostname:[/bold]  [cyan]{args.host}[/cyan]\n"
        f"[bold]Operation:[/bold] [cyan]{args.op}[/cyan]",
        title="[bold cyan]🛡 Remote QR Consent[/bold cyan]",
        border_style="cyan"
    ))

    ok = get_remote_consent(
        target_ip = args.target,
        hostname  = args.host,
        operation = args.op,
    )

    if ok:
        console.print("[bold green]✔ Client authorized.[/bold green]")
    else:
        console.print("[bold red]✖ Client denied or timed out.[/bold red]")


# ── main dispatcher ───────────────────────────────────────────────────────────
def run_cli():
    _print_cli_banner()

    parser = _build_parser()
    args   = parser.parse_args()

    if getattr(args, "help", False) or not args.command:
        _print_help()
        return

    cmd = args.command

    if   cmd in ("discover", "d"):  _handle_discover()
    elif cmd in ("scan",     "s"):  _handle_scan(args)
    elif cmd in ("clean",    "c"):  _handle_clean(args)
    elif cmd in ("harden",   "hz"):  _handle_harden(args)
    elif cmd in ("full",     "f"):  _handle_full(args)
    elif cmd in ("consent",  "cs"): _handle_consent(args)
    else:
        _print_help()


if __name__ == "__main__":
    run_cli()