# modules/network_scanner.py — Network Device Discovery (Windows Compatible)
# Pure Python implementation — no scapy, no npcap, no admin rights needed.
# Uses ICMP ping sweep + socket hostname resolution to find live devices.

import socket
import subprocess
import platform
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import box

console = Console()


@dataclass
class Device:
    ip: str
    mac: str = "N/A (need Npcap)"
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    open_ports: List[int] = field(default_factory=list)
    os_guess: str = "Unknown"


def get_local_subnet() -> str:
    """Detect the local machine's subnet automatically."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def _ping_host(ip: str) -> Optional[str]:
    """
    Ping a single IP. Returns the IP if alive, None if not.
    Uses system ping command — works on all platforms without root.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return ip if result.returncode == 0 else None
    except Exception:
        return None


def arp_scan(subnet: str) -> List[Device]:
    """
    Multi-threaded ping sweep across the subnet.
    Uses 100 threads so 254 hosts scan in ~5 seconds instead of 4+ minutes.
    """
    base = subnet.rsplit(".", 1)[0]   # e.g. "192.168.0"
    all_ips = [f"{base}.{i}" for i in range(1, 255)]

    console.print(f"\n[cyan]  Scanning subnet [bold]{subnet}[/bold] ...[/cyan]")
    console.print("[dim]  Using multi-threaded ping sweep (Windows compatible)[/dim]\n")

    alive_ips = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Scanning {task.completed}/{task.total} hosts..."),
        BarColumn(),
        transient=True
    ) as progress:
        task = progress.add_task("Scanning", total=len(all_ips))

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(_ping_host, ip): ip for ip in all_ips}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    alive_ips.append(result)
                progress.advance(task)

    # Build Device objects
    devices = []
    console.print(f"\n[green]  Found {len(alive_ips)} live host(s). Resolving hostnames...[/green]")

    def _resolve(ip):
        return ip, resolve_hostname(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(_resolve, sorted(alive_ips, key=lambda x: int(x.split(".")[-1]))))

    for ip, hostname in results:
        devices.append(Device(ip=ip, hostname=hostname))

    return devices


def display_devices(devices: List[Device]) -> None:
    """Render device list as a rich table."""
    if not devices:
        console.print("[red]  No devices found.[/red]")
        return

    table = Table(
        title=f"[bold green] Discovered Devices ({len(devices)} found)[/bold green]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold cyan"
    )
    table.add_column("#",           style="dim",   width=4)
    table.add_column("IP Address",                 width=18)
    table.add_column("Hostname",                   width=32)
    table.add_column("Status",      style="green", width=10)

    for idx, dev in enumerate(devices, 1):
        table.add_row(
            str(idx),
            f"[bold yellow]{dev.ip}[/bold yellow]",
            dev.hostname,
            "● Live"
        )

    console.print(table)


def select_target(devices: List[Device]) -> Optional[Device]:
    """Let the user pick a device by number."""
    if not devices:
        return None

    console.print("\n[bold]Enter device number to investigate (or 0 to go back): [/bold]", end="")
    try:
        choice = int(input().strip())
        if choice == 0:
            return None
        return devices[choice - 1]
    except (ValueError, IndexError):
        console.print("[red]Invalid choice.[/red]")
        return None
