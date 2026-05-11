# modules/file_cleaner.py — File Cleanup & Security Engine
# Scans the local machine for junk files, large files, and suspicious content.
# Always asks per-file confirmation before any deletion or quarantine action.

import hashlib
import json
import os
import shutil
import platform
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.progress import track
from rich import box

from config import (
    JUNK_EXTENSIONS,
    SUSPICIOUS_EXTENSIONS,
    LARGE_FILE_THRESHOLD_MB,
    QUARANTINE,
    MALWARE_SIG_FILE,
)

console = Console()


# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class ScannedFile:
    path: str
    size_mb: float
    category: str        # "junk" | "suspicious" | "large" | "malware_hit"
    reason: str
    action_taken: str = "Pending"


@dataclass
class CleanupReport:
    scanned_count: int = 0
    deleted: List[str] = field(default_factory=list)
    quarantined: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    space_freed_mb: float = 0.0


# ──────────────────────────────────────────────────────────────────────────────
def _load_malware_signatures() -> List[str]:
    """Load known bad MD5/SHA256 hashes from local DB."""
    default_sigs = [
        # These are EXAMPLE known-bad hashes for testing
        # In production pull from VirusTotal, MalwareBazaar, etc.
        "44d88612fea8a8f36de82e1278abb02f",  # EICAR test signature (MD5)
        "275a021bbfb6489e54d471899f7db9d1681c9b5",  # EICAR SHA1
    ]
    if os.path.exists(MALWARE_SIG_FILE):
        try:
            with open(MALWARE_SIG_FILE) as f:
                data = json.load(f)
                return data.get("hashes", default_sigs)
        except Exception:
            pass
    # Write defaults
    with open(MALWARE_SIG_FILE, "w") as f:
        json.dump({"hashes": default_sigs, "note": "Add known-bad hashes here"}, f, indent=2)
    return default_sigs


MALWARE_SIGS = set(_load_malware_signatures())


def _file_hash(filepath: str, algo: str = "md5") -> str:
    """Compute file hash. Returns empty string on read error."""
    h = hashlib.new(algo)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return ""


def _get_default_scan_dirs() -> List[str]:
    """Return sensible default scan directories per OS."""
    system = platform.system()
    home   = str(Path.home())

    if system == "Windows":
        return [
            os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp")),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            "C:\\Windows\\Temp",
        ]
    elif system == "Darwin":  # macOS
        return [
            os.path.expanduser("~/Library/Caches"),
            os.path.expanduser("~/Downloads"),
            "/tmp",
            "/var/folders",
        ]
    else:  # Linux
        return [
            "/tmp",
            "/var/tmp",
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/.cache"),
        ]


# ──────────────────────────────────────────────────────────────────────────────
def scan_directory(directory: str) -> List[ScannedFile]:
    """
    Walk a directory and flag files as junk / suspicious / large / malware.
    Returns a list of ScannedFile objects — no changes are made here.
    """
    flagged: List[ScannedFile] = []

    if not os.path.isdir(directory):
        return flagged

    all_files = []
    for root, _, files in os.walk(directory):
        for name in files:
            all_files.append(os.path.join(root, name))

    for filepath in track(all_files, description=f"  Scanning {directory}"):
        try:
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            ext     = Path(filepath).suffix.lower()

            # ── Malware hash check ──────────────────────────────────────────
            fhash = _file_hash(filepath)
            if fhash and fhash in MALWARE_SIGS:
                flagged.append(ScannedFile(
                    path=filepath, size_mb=size_mb,
                    category="malware_hit",
                    reason=f"Hash match in malware DB: {fhash}"
                ))
                continue

            # ── Junk file check ─────────────────────────────────────────────
            if ext in JUNK_EXTENSIONS or filepath.endswith("~"):
                flagged.append(ScannedFile(
                    path=filepath, size_mb=size_mb,
                    category="junk",
                    reason=f"Temporary/junk file extension: {ext}"
                ))
                continue

            # ── Suspicious extension check ──────────────────────────────────
            if ext in SUSPICIOUS_EXTENSIONS:
                flagged.append(ScannedFile(
                    path=filepath, size_mb=size_mb,
                    category="suspicious",
                    reason=f"Executable extension found in scan path: {ext}"
                ))
                continue

            # ── Large file check ────────────────────────────────────────────
            if size_mb > LARGE_FILE_THRESHOLD_MB:
                flagged.append(ScannedFile(
                    path=filepath, size_mb=size_mb,
                    category="large",
                    reason=f"File exceeds {LARGE_FILE_THRESHOLD_MB}MB threshold ({size_mb:.1f}MB)"
                ))

        except (PermissionError, OSError):
            pass  # Skip files we can't read

    return flagged


def display_flagged_files(flagged: List[ScannedFile]) -> None:
    """Show all flagged files in a color-coded table."""
    if not flagged:
        console.print("[green]  No files flagged during scan.[/green]")
        return

    cat_colors = {
        "malware_hit": "bold red",
        "suspicious":  "red",
        "junk":        "yellow",
        "large":       "cyan",
    }

    table = Table(
        title=f"[bold red] Flagged Files ({len(flagged)} found)[/bold red]",
        box=box.ROUNDED, show_lines=True, header_style="bold"
    )
    table.add_column("#",          width=4)
    table.add_column("Category",   width=14)
    table.add_column("Size (MB)",  width=10)
    table.add_column("Path",       width=52)
    table.add_column("Reason")

    for i, f in enumerate(flagged, 1):
        color = cat_colors.get(f.category, "white")
        table.add_row(
            str(i),
            f"[{color}]{f.category.upper()}[/{color}]",
            f"{f.size_mb:.2f}",
            f.path,
            f.reason,
        )

    console.print(table)


# ──────────────────────────────────────────────────────────────────────────────
def _quarantine_file(filepath: str) -> Tuple[bool, str]:
    """Move a file to the quarantine directory."""
    try:
        filename  = os.path.basename(filepath)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest      = os.path.join(QUARANTINE, f"{timestamp}_{filename}")
        shutil.move(filepath, dest)
        return True, dest
    except Exception as e:
        return False, str(e)


def _delete_file(filepath: str) -> Tuple[bool, str]:
    """Permanently delete a file."""
    try:
        os.remove(filepath)
        return True, "Deleted"
    except Exception as e:
        return False, str(e)


def process_flagged_files(flagged: List[ScannedFile]) -> CleanupReport:
    """
    Interactively walk through each flagged file and ask the user
    what to do: delete / quarantine / keep / skip all of category.
    Returns a CleanupReport for the final report generator.
    """
    report = CleanupReport(scanned_count=len(flagged))

    console.print("\n[bold cyan]═══ File Action Phase ═══[/bold cyan]")
    console.print("[dim]For each file, you'll choose: Delete / Quarantine / Keep[/dim]\n")

    auto_delete_junk = Confirm.ask(
        " Auto-delete ALL junk/temp files without asking one by one?",
        default=False
    )

    for sf in flagged:
        # ── Auto-handle junk if user opted in ──────────────────────────────
        if auto_delete_junk and sf.category == "junk":
            ok, _ = _delete_file(sf.path)
            if ok:
                report.deleted.append(sf.path)
                report.space_freed_mb += sf.size_mb
                sf.action_taken = "Deleted (auto)"
            else:
                report.skipped.append(sf.path)
            continue

        # ── Malware always asks explicitly ──────────────────────────────────
        if sf.category == "malware_hit":
            console.print(f"\n[bold red] MALWARE DETECTED:[/bold red] {sf.path}")
            console.print(f"  Reason: {sf.reason}")
            action = Prompt.ask(
                "  Action",
                choices=["quarantine", "delete", "skip"],
                default="quarantine"
            )
        else:
            console.print(f"\n[yellow]File:[/yellow] {sf.path}")
            console.print(f"  Category: {sf.category} | Size: {sf.size_mb:.2f} MB")
            console.print(f"  Reason: {sf.reason}")
            action = Prompt.ask(
                "  Action",
                choices=["delete", "quarantine", "keep", "skip"],
                default="keep"
            )

        if action == "delete":
            ok, msg = _delete_file(sf.path)
            if ok:
                report.deleted.append(sf.path)
                report.space_freed_mb += sf.size_mb
                sf.action_taken = "Deleted"
                console.print("  [green]✓ Deleted[/green]")
            else:
                console.print(f"  [red]✗ Failed: {msg}[/red]")
                report.skipped.append(sf.path)

        elif action == "quarantine":
            ok, dest = _quarantine_file(sf.path)
            if ok:
                report.quarantined.append(dest)
                report.space_freed_mb += sf.size_mb
                sf.action_taken = f"Quarantined → {dest}"
                console.print(f"  [cyan]✓ Quarantined to {dest}[/cyan]")
            else:
                console.print(f"  [red]✗ Failed: {dest}[/red]")
                report.skipped.append(sf.path)

        elif action in ("keep", "skip"):
            report.skipped.append(sf.path)
            sf.action_taken = "Kept by user"
            console.print("  [dim]Skipped[/dim]")

    return report


# ──────────────────────────────────────────────────────────────────────────────
def run_cleanup_wizard() -> CleanupReport:
    """
    Full cleanup flow: choose directories → scan → review → act.
    Returns CleanupReport to be passed to the report generator.
    """
    console.print("\n[bold cyan] File Cleanup Wizard[/bold cyan]")

    default_dirs = _get_default_scan_dirs()
    console.print("\n[bold]Default scan directories:[/bold]")
    for i, d in enumerate(default_dirs, 1):
        console.print(f"  [{i}] {d}")

    console.print("\nPress ENTER to use defaults, or type a custom path:")
    custom = input("  Path (or ENTER): ").strip()

    scan_dirs = [custom] if custom else default_dirs

    all_flagged: List[ScannedFile] = []
    for directory in scan_dirs:
        console.print(f"\n[cyan]Scanning: {directory}[/cyan]")
        flagged = scan_directory(directory)
        all_flagged.extend(flagged)

    display_flagged_files(all_flagged)

    if not all_flagged:
        return CleanupReport(scanned_count=0)

    console.print(f"\n[bold]{len(all_flagged)} files flagged.[/bold] Proceed to action phase?")
    if not Confirm.ask("Continue", default=True):
        return CleanupReport(scanned_count=len(all_flagged))

    return process_flagged_files(all_flagged)
