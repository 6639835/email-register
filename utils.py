"""
Utility functions for the email registration application.

Contains helper functions for file operations, logging, and other common tasks.
"""

from __future__ import annotations

import os
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, TextIO

from config import get_app_dir


@dataclass
class OutputFiles:
    """Manages output file handles for registration results."""

    timestamp: str = field(
        default_factory=lambda: datetime.now().strftime("%Y%m%d%H%M%S")
    )
    _success_file: TextIO | None = field(default=None, repr=False)
    _failure_file: TextIO | None = field(default=None, repr=False)
    _url_file: TextIO | None = field(default=None, repr=False)

    @property
    def success_path(self) -> Path:
        """Path to the success log file."""
        return get_app_dir() / f"success_{self.timestamp}.txt"

    @property
    def failure_path(self) -> Path:
        """Path to the failure log file."""
        return get_app_dir() / f"failure_{self.timestamp}.txt"

    @property
    def url_path(self) -> Path:
        """Path to the login URLs file."""
        return get_app_dir() / f"login_urls_{self.timestamp}.txt"

    def __enter__(self) -> "OutputFiles":
        """Open all output files."""
        self._success_file = open(self.success_path, "w", encoding="utf-8")
        self._failure_file = open(self.failure_path, "w", encoding="utf-8")
        self._url_file = open(self.url_path, "w", encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Close all output files."""
        if self._success_file:
            self._success_file.close()
        if self._failure_file:
            self._failure_file.close()
        if self._url_file:
            self._url_file.close()

    def write_success(self, email: str, password: str) -> None:
        """Write a successful registration to the success file."""
        if self._success_file:
            self._success_file.write(f"Username: {email}, Password: {password}\n")
            self._success_file.flush()

    def write_failure(self, email: str, password: str, error: str) -> None:
        """Write a failed registration to the failure file."""
        if self._failure_file:
            self._failure_file.write(
                f"Username: {email}, Password: {password}, Error: {error}\n"
            )
            self._failure_file.flush()

    def write_url(self, email: str, url: str) -> None:
        """Write a login URL to the URL file."""
        if self._url_file:
            self._url_file.write(f"{email}----{url}\n")
            self._url_file.flush()

    def get_file_names(self) -> List[str]:
        """Get list of output file names."""
        return [
            self.success_path.name,
            self.failure_path.name,
            self.url_path.name,
        ]

    def open_url_file(self) -> None:
        """Open the URL file in the default application."""
        try:
            webbrowser.open(f"file:///{self.url_path.as_posix()}")
        except Exception:
            pass


def open_directory(path: Path) -> None:
    """Open a directory in the system file browser."""
    try:
        webbrowser.open(f"file:///{path.absolute().as_posix()}")
    except Exception:
        pass


def open_file(path: Path) -> None:
    """Open a file in the default application."""
    try:
        # Create file if it doesn't exist
        if not path.exists():
            path.touch()
        webbrowser.open(f"file:///{path.absolute().as_posix()}")
    except Exception:
        pass


def validate_domain(domain: str) -> bool:
    """
    Check if a domain string appears to be valid.

    Args:
        domain: Domain string to validate.

    Returns:
        True if domain contains at least one dot.
    """
    return "." in domain


def parse_domain_list(text: str) -> List[str]:
    """
    Parse a multi-line text into a list of domains.

    Args:
        text: Multi-line text with one domain per line.

    Returns:
        List of non-empty domain strings.
    """
    lines = text.strip().splitlines()
    return [line.strip() for line in lines if line.strip()]


def validate_prefix(prefix: str) -> bool:
    """
    Validate that prefix is exactly one letter.

    Args:
        prefix: Prefix string to validate.

    Returns:
        True if prefix is exactly one alphabetic character.
    """
    return len(prefix) == 1 and prefix.isalpha()


def validate_count(count_str: str) -> tuple[bool, int, str]:
    """
    Validate and parse the generation count.

    Args:
        count_str: String representation of the count.

    Returns:
        Tuple of (is_valid, parsed_count, error_message).
    """
    try:
        count = int(count_str.strip())
        if count <= 0 or count > 100000:
            return False, 0, "Count should be 1-100000"
        return True, count, ""
    except ValueError:
        return False, 0, "Invalid count format"


@dataclass
class RegistrationStats:
    """Statistics for the registration process."""

    total_target: int = 0
    successful: int = 0
    failed: int = 0
    attempts: int = 0

    def record_success(self) -> None:
        """Record a successful registration."""
        self.successful += 1
        self.attempts += 1

    def record_failure(self) -> None:
        """Record a failed registration."""
        self.failed += 1
        self.attempts += 1

    def get_summary(self) -> str:
        """Get a summary string of the statistics."""
        return (
            f"Complete: Target {self.total_target}, "
            f"Successful {self.successful}, "
            f"Failed {self.failed}, "
            f"Total attempts {self.attempts}"
        )
