#!/usr/bin/env python3
# cybershield/__main__.py
# ────────────────────────
# This is the entry point for:
#   - `cybershield` command (after pip install)
#   - `python -m cybershield` (direct module run)
#
# Usage:
#   cybershield              → GUI
#   cybershield --gui        → GUI
#   cybershield --cli        → interactive CLI menu
#   cybershield scan ...     → direct CLI command
#   cybershield s ...        → short CLI command

import sys
import os

# ensure project root is importable when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    args = sys.argv[1:]

    # no args or explicit GUI flag → launch GUI
    if not args or args[0] in ("--gui", "-g"):
        _launch_gui()

    # --cli → interactive terminal menu
    elif args[0] == "--cli":
        _launch_cli()

    # --version
    elif args[0] in ("--version", "-v"):
        from config import VERSION, TOOL_NAME
        print(f"{TOOL_NAME} v{VERSION}")

    # --help with no subcommand
    elif args[0] in ("--help", "-h") and len(args) == 1:
        _launch_help()

    # everything else → secret CLI commands
    else:
        _launch_commands()


def _launch_gui():
    try:
        from PyQt6.QtWidgets import QApplication
        from gui.app import CyberShieldApp
        from config import TOOL_NAME

        app = QApplication(sys.argv)
        app.setApplicationName(TOOL_NAME)

        window = CyberShieldApp()
        window.show()
        sys.exit(app.exec())

    except ImportError as e:
        print(f"[ERROR] PyQt6 not installed: {e}")
        print("Run: pip install PyQt6")
        print("Or launch CLI instead: cybershield --cli")
        sys.exit(1)


def _launch_cli():
    # import and run the original interactive main menu
    try:
        import main as cli_main
        cli_main.main()
    except ImportError:
        import main as cli_main
        cli_main.main()


def _launch_commands():
    from cli.commands import run_cli
    run_cli()


def _launch_help():
    from cli.commands import _print_cli_banner, run_cli
    _print_cli_banner()
    run_cli()


if __name__ == "__main__":
    main()
