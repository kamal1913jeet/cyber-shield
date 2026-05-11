#!/usr/bin/env python3
# cybershield.py — Master Entry Point
# ─────────────────────────────────────
# Usage:
#   python cybershield.py              → launches GUI
#   python cybershield.py --gui        → launches GUI
#   python cybershield.py --cli        → launches original CLI menu
#   python cybershield.py scan ...     → secret CLI command
#   python cybershield.py -s ...       → short secret CLI command

import sys
import os

# make sure all modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import TOOL_NAME, VERSION


def main():
    args = sys.argv[1:]

    # ── no args or explicit --gui / -g → launch GUI ───────────────────────────
    if not args or args[0] in ("--gui", "-g"):
        _launch_gui()

    # ── --cli → launch original terminal menu ─────────────────────────────────
    elif args[0] == "--cli":
        _launch_cli()

    # ── --version / -v ────────────────────────────────────────────────────────
    elif args[0] in ("--version", "-v"):
        print(f"{TOOL_NAME} v{VERSION}")

    # ── everything else → secret CLI commands ─────────────────────────────────
    else:
        _launch_commands()


def _launch_gui():
    try:
        from PyQt6.QtWidgets import QApplication
        from gui.app import CyberShieldApp
        app = QApplication(sys.argv)
        app.setApplicationName(TOOL_NAME)
        window = CyberShieldApp()
        window.show()
        sys.exit(app.exec())
    except ImportError as e:
        print(f"[ERROR] PyQt6 not installed: {e}")
        print("Run: pip install PyQt6")
        sys.exit(1)


def _launch_cli():
    import main as cli_main
    cli_main.main()


def _launch_commands():
    from cli.commands import run_cli
    run_cli()


if __name__ == "__main__":
    main()
