#!/usr/bin/env python3
"""
Batch Email Registration Tool - Main Entry Point

A GUI application for batch registration of email accounts
across multiple domains.

Usage:
    python main.py

The application provides:
- Multiple username generation modes (fixed, random, English names)
- Multiple password generation modes (fixed, numeric, strong)
- Multi-domain support with authorization checking
- Progress tracking and detailed logging
- Output files for successful registrations and login URLs
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    """Application entry point."""
    # Import here to avoid circular imports and speed up --help
    from config import get_app_dir
    from gui import App

    # Change to app directory for relative file access
    try:
        os.chdir(get_app_dir())
    except Exception:
        pass

    # Create and run the application
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
