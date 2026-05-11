# modules/hardener.py — Security Hardening & System Checks
# Checks local system configuration for known security weaknesses.
# Shows detailed fix steps directly in terminal after each finding.

import os
import platform
import subprocess
import stat
from dataclasses import dataclass, field
from typing import List

import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich import box

console = Console()


@dataclass
class HardeningFinding:
    check: str
    status: str        # "PASS" | "WARN" | "FAIL"
    detail: str
    fix: str = ""
    steps: List[str] = field(default_factory=list)   # detailed fix steps


@dataclass
class HardeningReport:
    findings: List[HardeningFinding] = field(default_factory=list)

    @property
    def score(self) -> int:
        total = len(self.findings)
        if total == 0:
            return 100
        weights = {"PASS": 1.0, "WARN": 0.4, "FAIL": 0.0}
        earned  = sum(weights.get(f.status, 0) for f in self.findings)
        return int((earned / total) * 100)


# ──────────────────────────────────────────────────────────────────────────────
class SystemHardener:

    def __init__(self):
        self.os = platform.system()
        self.report = HardeningReport()

    def _add(self, check: str, status: str, detail: str,
             fix: str = "", steps: List[str] = None):
        self.report.findings.append(HardeningFinding(
            check=check, status=status, detail=detail,
            fix=fix, steps=steps or []
        ))

    # ── Firewall ──────────────────────────────────────────────────────────────
    def check_firewall(self):
        check = "Firewall Active"
        if self.os == "Linux":
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if "active" in result.stdout.lower():
                self._add(check, "PASS", "UFW firewall is active")
            else:
                self._add(check, "FAIL", "UFW firewall is inactive",
                    fix="Enable UFW firewall immediately",
                    steps=[
                        "Open terminal as root",
                        "Run: sudo ufw enable",
                        "Run: sudo ufw default deny incoming",
                        "Run: sudo ufw default allow outgoing",
                        "Run: sudo ufw status verbose  (to verify)",
                    ])

        elif self.os == "Windows":
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True, text=True
            )
            if "ON" in result.stdout:
                self._add(check, "PASS", "Windows Firewall is ON")
            else:
                self._add(check, "FAIL", "Windows Firewall is OFF",
                    fix="Turn on Windows Firewall",
                    steps=[
                        "Press Windows + S and search 'Windows Security'",
                        "Click 'Firewall & network protection'",
                        "Click each profile (Domain / Private / Public)",
                        "Toggle 'Microsoft Defender Firewall' to ON",
                        "Repeat for all 3 profiles",
                        "Or run in Admin PowerShell: Set-NetFirewallProfile -All -Enabled True",
                    ])

        elif self.os == "Darwin":
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True
            )
            if "enabled" in result.stdout.lower():
                self._add(check, "PASS", "macOS Application Firewall is enabled")
            else:
                self._add(check, "FAIL", "macOS Firewall is disabled",
                    fix="Enable macOS Firewall",
                    steps=[
                        "Open System Preferences (or System Settings on newer macOS)",
                        "Go to Security & Privacy → Firewall tab",
                        "Click the lock icon and enter your password",
                        "Click 'Turn On Firewall'",
                        "Click 'Firewall Options' and enable stealth mode",
                    ])

    # ── Open Ports ────────────────────────────────────────────────────────────
    def check_open_ports(self):
        risky_ports = {21: "FTP", 23: "Telnet", 135: "RPC",
                       139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC"}
        connections = psutil.net_connections(kind="inet")
        listening   = {c.laddr.port for c in connections if c.status == "LISTEN"}
        risky_open  = {p: name for p, name in risky_ports.items() if p in listening}

        if risky_open:
            port_list = ", ".join([f"{p} ({n})" for p, n in risky_open.items()])

            steps = ["Open PowerShell as Administrator and run these commands:"]

            if 3389 in risky_open:
                steps += [
                    "── Disable Remote Desktop (RDP port 3389) ──",
                    "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
                    "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'",
                ]
            if 445 in risky_open:
                steps += [
                    "── Disable SMBv1 (port 445 exploit risk) ──",
                    "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                    "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                ]
            if 139 in risky_open:
                steps += [
                    "── Disable NetBIOS (port 139) ──",
                    "Go to: Control Panel → Network → Adapter Settings",
                    "Right-click your adapter → Properties → IPv4 → Advanced",
                    "WINS tab → select 'Disable NetBIOS over TCP/IP'",
                ]
            if 23 in risky_open:
                steps += [
                    "── Disable Telnet (port 23) ──",
                    "Run: dism /online /disable-feature /featurename:TelnetClient",
                ]
            if 21 in risky_open:
                steps += [
                    "── Disable FTP (port 21) ──",
                    "Go to: Control Panel → Programs → Turn Windows features on/off",
                    "Uncheck 'Internet Information Services' → FTP Server",
                ]

            self._add(
                "Risky Local Ports", "FAIL" if any(p in risky_open for p in [445, 3389, 23]) else "WARN",
                f"High-risk ports open: {port_list}",
                fix="Disable unused high-risk services",
                steps=steps
            )
        else:
            self._add("Risky Local Ports", "PASS",
                      "No commonly exploited ports found listening locally")

    # ── Auto Update ───────────────────────────────────────────────────────────
    def check_auto_update(self):
        check = "Auto-Update Status"
        if self.os == "Windows":
            self._add(check, "WARN",
                "Cannot verify Windows Update status automatically",
                fix="Manually verify and enable Windows Update",
                steps=[
                    "Press Windows + I to open Settings",
                    "Click 'Windows Update'",
                    "Click 'Check for updates' — install any pending updates",
                    "Click 'Advanced options'",
                    "Turn ON 'Receive updates for other Microsoft products'",
                    "Set Active hours to match your schedule so updates don't interrupt you",
                    "Recommended: enable 'Automatic (recommended)' update setting",
                ])
        elif self.os == "Linux":
            path = "/etc/apt/apt.conf.d/20auto-upgrades"
            if os.path.exists(path):
                with open(path) as f:
                    content = f.read()
                if "1" in content:
                    self._add(check, "PASS", "Automatic security updates configured")
                else:
                    self._add(check, "WARN", "Auto-upgrades config exists but may be disabled",
                        fix="Enable automatic security updates",
                        steps=[
                            "Run: sudo apt install unattended-upgrades",
                            "Run: sudo dpkg-reconfigure -plow unattended-upgrades",
                            "Select YES when prompted",
                            "Verify: cat /etc/apt/apt.conf.d/20auto-upgrades",
                        ])
            else:
                self._add(check, "FAIL", "Automatic updates not configured",
                    fix="Install and configure unattended-upgrades",
                    steps=[
                        "Run: sudo apt update",
                        "Run: sudo apt install unattended-upgrades",
                        "Run: sudo dpkg-reconfigure -plow unattended-upgrades",
                        "Run: sudo systemctl enable unattended-upgrades",
                    ])
        elif self.os == "Darwin":
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
                 "AutomaticCheckEnabled"],
                capture_output=True, text=True
            )
            if result.stdout.strip() == "1":
                self._add(check, "PASS", "macOS auto-update is enabled")
            else:
                self._add(check, "WARN", "macOS auto-update is disabled",
                    fix="Enable macOS automatic updates",
                    steps=[
                        "Open System Preferences → Software Update",
                        "Check 'Automatically keep my Mac up to date'",
                        "Click 'Advanced' and check all options",
                        "Or run: sudo softwareupdate --schedule on",
                    ])

    # ── World Writable ────────────────────────────────────────────────────────
    def check_world_writable(self):
        if self.os == "Windows":
            self._add("World-Writable Files", "PASS", "Not applicable on Windows (uses ACL model)")
            return

        sensitive_dirs = ["/etc", "/usr/bin", "/usr/sbin"]
        problems = []
        for d in sensitive_dirs:
            if not os.path.exists(d):
                continue
            for root, _, files in os.walk(d):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        s = os.stat(fp)
                        if s.st_mode & stat.S_IWOTH:
                            problems.append(fp)
                    except OSError:
                        pass

        if problems:
            fix_cmds = [f"chmod o-w {p}" for p in problems[:5]]
            self._add("World-Writable Files", "FAIL",
                f"{len(problems)} world-writable files in sensitive dirs",
                fix="Remove world-write permissions from system files",
                steps=["Run these commands as root:"] + fix_cmds +
                      (["... and more"] if len(problems) > 5 else []))
        else:
            self._add("World-Writable Files", "PASS",
                      "No world-writable files in sensitive directories")

    # ── SSH Config ────────────────────────────────────────────────────────────
    def check_ssh_config(self):
        ssh_config = "/etc/ssh/sshd_config"
        if not os.path.exists(ssh_config):
            return

        try:
            with open(ssh_config) as f:
                lines = f.readlines()
        except PermissionError:
            self._add("SSH Configuration", "WARN",
                      "Could not read sshd_config (permission denied)")
            return

        checks = [
            ("PermitRootLogin", "no",
             "Disable root SSH login",
             ["Edit /etc/ssh/sshd_config",
              "Find or add: PermitRootLogin no",
              "Run: sudo systemctl restart sshd"]),
            ("PasswordAuthentication", "no",
             "Disable password auth, use SSH keys only",
             ["Generate SSH key: ssh-keygen -t ed25519",
              "Copy to server: ssh-copy-id user@host",
              "Edit /etc/ssh/sshd_config → PasswordAuthentication no",
              "Run: sudo systemctl restart sshd"]),
        ]

        for directive, expected, fix_desc, fix_steps in checks:
            for line in lines:
                stripped = line.strip()
                if stripped.startswith(directive):
                    value = stripped.split()[-1].lower()
                    if value == expected.lower():
                        self._add(f"SSH: {directive}", "PASS", f"{directive} = {value}")
                    else:
                        self._add(f"SSH: {directive}", "FAIL",
                            f"{directive} = {value} (should be {expected})",
                            fix=fix_desc, steps=fix_steps)
                    break

    # ── Disk Encryption ───────────────────────────────────────────────────────
    def check_disk_encryption(self):
        check = "Disk Encryption"
        if self.os == "Windows":
            result = subprocess.run(["manage-bde", "-status"],
                                    capture_output=True, text=True, shell=True)
            if "Protection On" in result.stdout:
                self._add(check, "PASS", "BitLocker encryption is active")
            else:
                self._add(check, "WARN", "BitLocker is disabled — drive not encrypted",
                    fix="Enable BitLocker to protect your data if laptop is stolen",
                    steps=[
                        "Press Windows + S → search 'BitLocker'",
                        "Click 'Manage BitLocker'",
                        "Click 'Turn on BitLocker' next to your C: drive",
                        "Choose how to unlock (password or USB key)",
                        "Save your recovery key to Microsoft account or USB",
                        "Choose 'Encrypt entire drive' for full protection",
                        "Click 'Start encrypting' — takes 1-2 hours on first run",
                        "NOTE: Do NOT turn off PC during encryption",
                    ])

        elif self.os == "Linux":
            result = subprocess.run(["lsblk", "-o", "NAME,TYPE,FSTYPE"],
                                    capture_output=True, text=True)
            if "crypt" in result.stdout.lower():
                self._add(check, "PASS", "LUKS encrypted volume detected")
            else:
                self._add(check, "WARN", "No LUKS encryption detected",
                    fix="Encrypt sensitive partitions with LUKS",
                    steps=[
                        "WARNING: Backup all data before encrypting",
                        "Install: sudo apt install cryptsetup",
                        "Encrypt partition: sudo cryptsetup luksFormat /dev/sdX",
                        "Open: sudo cryptsetup open /dev/sdX encrypted_disk",
                        "Format: sudo mkfs.ext4 /dev/mapper/encrypted_disk",
                        "Add to /etc/crypttab for auto-mount at boot",
                    ])

        elif self.os == "Darwin":
            result = subprocess.run(["fdesetup", "status"], capture_output=True, text=True)
            if "on" in result.stdout.lower():
                self._add(check, "PASS", "FileVault disk encryption is ON")
            else:
                self._add(check, "FAIL", "FileVault is OFF — drive not encrypted",
                    fix="Enable FileVault immediately",
                    steps=[
                        "Open System Preferences → Security & Privacy",
                        "Click the 'FileVault' tab",
                        "Click the lock and enter your password",
                        "Click 'Turn On FileVault'",
                        "Save the recovery key somewhere safe (not on this Mac)",
                        "Encryption runs in background — Mac stays usable",
                    ])

    # ── Antivirus Check (Windows) ─────────────────────────────────────────────
    def check_antivirus(self):
        if self.os != "Windows":
            return
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-MpComputerStatus | Select-Object -ExpandProperty AMRunningMode"],
            capture_output=True, text=True
        )
        if result.returncode == 0 and "Normal" in result.stdout:
            self._add("Windows Defender", "PASS", "Windows Defender is active and running")
        else:
            self._add("Windows Defender", "WARN",
                "Windows Defender status unclear",
                fix="Verify Windows Defender is active",
                steps=[
                    "Press Windows + S → search 'Windows Security'",
                    "Click 'Virus & threat protection'",
                    "Make sure 'Real-time protection' is ON",
                    "Click 'Quick scan' to run an immediate scan",
                    "Under 'Virus & threat protection updates' click 'Check for updates'",
                ])

    # ── Password Policy (Windows) ─────────────────────────────────────────────
    def check_password_policy(self):
        if self.os != "Windows":
            return
        result = subprocess.run(
            ["net", "accounts"],
            capture_output=True, text=True
        )
        output = result.stdout

        if "0" in output and "Minimum password length" in output:
            self._add("Password Policy", "WARN",
                "Minimum password length may be set to 0 (no requirement)",
                fix="Enforce strong password policy",
                steps=[
                    "Open PowerShell as Administrator",
                    "Run: net accounts /minpwlen:12",
                    "Run: net accounts /maxpwage:90",
                    "Run: net accounts /minpwage:1",
                    "Run: net accounts /uniquepw:5",
                    "Or use: secpol.msc → Account Policies → Password Policy",
                ])
        else:
            self._add("Password Policy", "PASS", "Password policy appears configured")

    # ── Guest Account ─────────────────────────────────────────────────────────
    def check_guest_account(self):
        if self.os != "Windows":
            return
        result = subprocess.run(
            ["net", "user", "Guest"],
            capture_output=True, text=True
        )
        if "Account active" in result.stdout and "Yes" in result.stdout:
            self._add("Guest Account", "FAIL",
                "Guest account is ENABLED — security risk",
                fix="Disable the Guest account",
                steps=[
                    "Open PowerShell as Administrator",
                    "Run: net user Guest /active:no",
                    "Verify: net user Guest  (should show 'Account active: No')",
                ])
        else:
            self._add("Guest Account", "PASS", "Guest account is disabled")

    # ── Run All ───────────────────────────────────────────────────────────────
    def run_all_checks(self) -> HardeningReport:
        console.print("\n[cyan] Running security hardening checks...[/cyan]\n")
        checks = [
            self.check_firewall,
            self.check_open_ports,
            self.check_auto_update,
            self.check_world_writable,
            self.check_ssh_config,
            self.check_disk_encryption,
            self.check_antivirus,
            self.check_password_policy,
            self.check_guest_account,
        ]
        for fn in checks:
            try:
                fn()
            except Exception as e:
                self.report.findings.append(HardeningFinding(
                    check=fn.__name__, status="WARN",
                    detail=f"Check failed to run: {e}"
                ))
        return self.report


# ──────────────────────────────────────────────────────────────────────────────
def display_hardening_report(report: HardeningReport) -> None:
    status_colors = {"PASS": "green", "WARN": "yellow", "FAIL": "red"}
    status_icons  = {"PASS": "✓", "WARN": "⚠", "FAIL": "✗"}

    # ── Summary table ─────────────────────────────────────────────────────────
    table = Table(
        title=f"[bold] Security Hardening Report — Score: {report.score}/100[/bold]",
        box=box.ROUNDED, show_lines=True, header_style="bold cyan"
    )
    table.add_column("Status", width=8)
    table.add_column("Check",  width=26)
    table.add_column("Detail")

    for f in report.findings:
        color = status_colors.get(f.status, "white")
        icon  = status_icons.get(f.status, "?")
        table.add_row(
            f"[{color}]{icon} {f.status}[/{color}]",
            f.check,
            f.detail,
        )

    console.print(table)

    # ── Score panel ───────────────────────────────────────────────────────────
    score = report.score
    score_color = "green" if score >= 75 else "yellow" if score >= 45 else "red"
    grade = "Excellent" if score >= 90 else "Good" if score >= 75 else \
            "Needs Work" if score >= 45 else "Critical — Act Now"

    console.print(Panel(
        f"[{score_color}][bold]{score}/100[/bold] — {grade}[/{score_color}]",
        title="Overall Hardening Score"
    ))

    # ── Detailed fix steps for each WARN/FAIL ─────────────────────────────────
    problems = [f for f in report.findings if f.status in ("WARN", "FAIL") and f.steps]

    if not problems:
        console.print("\n[green] All checks passed! Your system is well hardened.[/green]")
        return

    console.print()
    console.rule("[bold red] Action Required — Fix These Issues[/bold red]")
    console.print()

    for i, finding in enumerate(problems, 1):
        color = status_colors.get(finding.status, "white")
        icon  = status_icons.get(finding.status, "?")

        console.print(Panel(
            "\n".join([
                f"[bold]Issue:[/bold]    {finding.detail}",
                f"[bold]Goal:[/bold]     {finding.fix}",
                "",
                "[bold cyan]Steps to fix:[/bold cyan]",
            ] + [f"  [dim]{j}.[/dim] {step}" for j, step in enumerate(finding.steps, 1)]),
            title=f"[{color}]{icon} [{i}] {finding.check}[/{color}]",
            border_style=color,
            padding=(0, 1)
        ))
        console.print()

    # ── Priority summary ──────────────────────────────────────────────────────
    fails = [f for f in problems if f.status == "FAIL"]
    warns = [f for f in problems if f.status == "WARN"]

    console.print(Panel(
        f"[red][bold]CRITICAL (fix today):[/bold] {len(fails)} issue(s)[/red]\n" +
        "\n".join([f"  • {f.check}" for f in fails]) +
        (f"\n\n[yellow][bold]WARNINGS (fix soon):[/bold] {len(warns)} issue(s)[/yellow]\n" +
        "\n".join([f"  • {f.check}" for f in warns]) if warns else ""),
        title="[bold] Priority Action List[/bold]",
        border_style="red" if fails else "yellow"
    ))
