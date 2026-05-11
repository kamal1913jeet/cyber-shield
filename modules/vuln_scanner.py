# modules/vuln_scanner.py — Pure Python Vulnerability & Port Scanner
# No nmap required. Uses raw sockets to scan ports and detect services.

import socket
import concurrent.futures
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import box

from config import DATA_DIR

console = Console()


# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class PortInfo:
    port: int
    state: str
    service: str
    version: str = ""
    cves: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    ip: str
    os_guess: str = "Unknown"
    open_ports: List[PortInfo] = field(default_factory=list)
    risk_level: str = "Low"


# ──────────────────────────────────────────────────────────────────────────────
# Common ports and their service names
SERVICE_NAMES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1723: "PPTP VPN",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    27017:"MongoDB",
}

# Quick scan — most common ports
QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139,
    143, 443, 445, 993, 995, 1433, 3306, 3389,
    5900, 8080, 8443
]

# Deep scan — extended port list
DEEP_PORTS = QUICK_PORTS + [
    8888, 6379, 27017, 1723, 2222, 4444, 5000,
    5432, 5555, 6000, 6666, 7070, 8000, 8008,
    8081, 8888, 9090, 9200, 9999, 10000
]

# Known CVEs per port
CVE_DB = {
    21:   ["CVE-2011-2523 (vsftpd backdoor)", "CVE-2015-3306 (ProFTPD mod_copy)"],
    22:   ["CVE-2018-15473 (OpenSSH user enum)", "CVE-2016-6515 (OpenSSH DoS)"],
    23:   ["Telnet sends data in plaintext - credentials exposed on network"],
    80:   ["CVE-2021-41773 (Apache path traversal)", "CVE-2017-9798 (Apache Optionsbleed)"],
    443:  ["CVE-2014-0160 (Heartbleed)", "CVE-2021-3449 (OpenSSL NULL deref)"],
    445:  ["CVE-2017-0144 (EternalBlue/WannaCry)", "CVE-2020-0796 (SMBGhost)"],
    1433: ["CVE-2020-0618 (MSSQL RCE)", "CVE-2019-1068 (MSSQL Remote Code Execution)"],
    3306: ["CVE-2012-2122 (MySQL auth bypass)", "CVE-2016-6662 (MySQL RCE)"],
    3389: ["CVE-2019-0708 (BlueKeep RDP RCE)", "CVE-2020-0609 (RD Gateway RCE)"],
    5900: ["CVE-2015-5239 (VNC integer overflow)", "CVE-2019-15681 (VNC memory leak)"],
    6379: ["Redis exposed without auth - full data access possible"],
    8080: ["CVE-2020-1938 (Ghostcat AJP)", "CVE-2017-12617 (Tomcat JSP upload)"],
    27017:["MongoDB exposed without auth - full database access possible"],
}


# ──────────────────────────────────────────────────────────────────────────────
def _check_port(ip: str, port: int, timeout: float = 1.0) -> Optional[PortInfo]:
    """
    Try to connect to a port. Returns PortInfo if open, None if closed.
    Also grabs the service banner if available.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))

        if result == 0:
            # Port is open — try to grab banner
            banner = ""
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                banner = banner.split("\n")[0][:50]  # first line only
            except Exception:
                pass
            sock.close()

            service = SERVICE_NAMES.get(port, "Unknown")
            cves    = CVE_DB.get(port, [])
            return PortInfo(
                port=port,
                state="open",
                service=service,
                version=banner,
                cves=cves
            )
        sock.close()
        return None

    except Exception:
        return None


def _guess_os(open_ports: List[PortInfo]) -> str:
    """Guess OS based on open ports heuristic."""
    ports = {p.port for p in open_ports}
    if 3389 in ports and 135 in ports:
        return "Windows (RDP + RPC detected)"
    if 445 in ports and 139 in ports:
        return "Windows (SMB + NetBIOS detected)"
    if 22 in ports and 80 in ports:
        return "Linux/Unix (SSH + HTTP detected)"
    if 22 in ports:
        return "Likely Linux/Unix (SSH detected)"
    if 80 in ports or 443 in ports:
        return "Web Server (HTTP/HTTPS detected)"
    return "Unknown"


def _calculate_risk(open_ports: List[PortInfo]) -> str:
    critical = {445, 3389, 23, 6379, 27017}
    high     = {21, 22, 3306, 8080, 1433, 5900}
    ports    = {p.port for p in open_ports}

    if ports & critical:
        return "Critical"
    if ports & high:
        return "High"
    if len(open_ports) > 8:
        return "Medium"
    return "Low"


# ──────────────────────────────────────────────────────────────────────────────
def _run_scan(ip: str, ports: List[int], label: str) -> ScanResult:
    """Multi-threaded port scan using pure Python sockets."""
    open_ports = []

    with Progress(
        SpinnerColumn(),
        TextColumn(f"[cyan]Scanning {label} ports on {ip}... {{task.completed}}/{{task.total}}"),
        BarColumn(),
        transient=True
    ) as progress:
        task = progress.add_task("Scanning", total=len(ports))

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(_check_port, ip, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                progress.advance(task)

    # Sort by port number
    open_ports.sort(key=lambda x: x.port)

    return ScanResult(
        ip=ip,
        os_guess=_guess_os(open_ports),
        open_ports=open_ports,
        risk_level=_calculate_risk(open_ports)
    )


def run_quick_scan(ip: str) -> ScanResult:
    console.print(f"\n[cyan]  Running quick scan on [bold]{ip}[/bold]...[/cyan]")
    return _run_scan(ip, QUICK_PORTS, "quick")


def run_deep_scan(ip: str) -> ScanResult:
    console.print(f"\n[cyan]  Running deep scan on [bold]{ip}[/bold]...[/cyan]")
    console.print("[yellow]  Scanning extended port list. Please wait...[/yellow]\n")
    return _run_scan(ip, DEEP_PORTS, "deep")


# ──────────────────────────────────────────────────────────────────────────────
def display_scan_result(res: ScanResult) -> None:
    risk_colors = {
        "Low": "green", "Medium": "yellow",
        "High": "red",  "Critical": "bold red"
    }
    color = risk_colors.get(res.risk_level, "white")

    console.print(Panel(
        f"[bold]Target:[/bold]  {res.ip}\n"
        f"[bold]OS Guess:[/bold] {res.os_guess}\n"
        f"[bold]Risk:[/bold]    [{color}]{res.risk_level}[/{color}]\n"
        f"[bold]Open Ports:[/bold] {len(res.open_ports)} found",
        title="[bold cyan] Scan Summary[/bold cyan]",
        border_style="cyan"
    ))

    if not res.open_ports:
        console.print("[green]  No open ports found. Host appears well secured.[/green]")
        return

    table = Table(box=box.SIMPLE_HEAVY, header_style="bold magenta", show_lines=True)
    table.add_column("Port",    width=8)
    table.add_column("Service", width=14)
    table.add_column("Banner",  width=30)
    table.add_column("Risk",    width=8)
    table.add_column("Known CVEs / Issues")

    for p in res.open_ports:
        cve_text   = "\n".join(p.cves) if p.cves else "None found"
        port_color = "red" if p.cves else "green"
        risk_label = "HIGH" if p.cves else "Low"
        risk_color = "red" if p.cves else "green"

        table.add_row(
            f"[{port_color}]{p.port}[/{port_color}]",
            p.service,
            p.version or "-",
            f"[{risk_color}]{risk_label}[/{risk_color}]",
            f"[red]{cve_text}[/red]" if p.cves else f"[green]{cve_text}[/green]"
        )

    console.print(table)

    # Show urgent warnings
    urgent = [p for p in res.open_ports if p.cves]
    if urgent:
        console.print(Panel(
            "\n".join([
                f"[red]* Port {p.port} ({p.service})[/red] - {p.cves[0]}"
                for p in urgent
            ]),
            title="[bold red] Urgent Security Issues[/bold red]",
            border_style="red"
        ))


def choose_scan_type() -> Optional[str]:
    console.print("\n[bold]Select scan type:[/bold]")
    console.print("  [1] Quick Scan  - top 20 common ports, ~10 seconds")
    console.print("  [2] Deep Scan   - 40 ports including uncommon ones, ~20 seconds")
    console.print("  [0] Back\n")
    console.print("Choice: ", end="")
    choice = input().strip()
    return {"1": "quick", "2": "deep", "0": None}.get(choice)
