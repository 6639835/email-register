"""
Username and password generators for email registration.

Provides multiple generation strategies for creating unique email addresses
and secure passwords.
"""

from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional

from config import get_app_dir


# Character sets
DIGITS = string.digits
LOWER_ALL = string.ascii_lowercase
UPPER_ALL = string.ascii_uppercase

# Character sets for random 8-char usernames (excluding confusing chars: l/1/o/0)
RAND8_ALPHA = "abcdefghijkmnpqrstuvwxyz"
RAND8_DIGIT = "23456789"

# Regex for extracting only letters
ONLY_LETTERS_PATTERN = re.compile(r"[^A-Za-z]")


class UsernameMode(Enum):
    """Username generation mode."""

    FIXED = "fixed"
    RAND8 = "rand8"
    ENAME = "ename"


class PasswordMode(Enum):
    """Password generation mode."""

    FIXED = "fixed"
    NUM6 = "num6"
    STRONG9 = "strong9"


def month_to_letter(month: int) -> str:
    """
    Convert month number (1-12) to letter (a-l).

    Args:
        month: Month number from 1 to 12.

    Returns:
        Corresponding letter a-l.

    Raises:
        ValueError: If month is not in range 1-12.
    """
    if 1 <= month <= 12:
        return chr(ord("a") + month - 1)
    raise ValueError("Month must be between 1 and 12")


@dataclass
class NameLists:
    """Container for first and last name lists used in ename generation."""

    first_names: List[str]
    last_names: List[str]

    @classmethod
    def load_from_files(
        cls,
        first_names_file: str = "first_names.txt",
        last_names_file: str = "last_names.txt",
    ) -> "NameLists":
        """
        Load name lists from text files.

        Searches in app directory first, then current working directory.
        Names are cleaned to contain only ASCII letters.
        """
        first_names = cls._read_name_file(first_names_file)
        last_names = cls._read_name_file(last_names_file)
        return cls(first_names=first_names, last_names=last_names)

    @staticmethod
    def _read_name_file(filename: str) -> List[str]:
        """
        Read and clean a name file.

        Args:
            filename: Name of the file to read.

        Returns:
            Sorted list of unique names containing only letters.
        """
        search_paths = [
            get_app_dir() / filename,
            Path.cwd() / filename,
        ]

        data: List[str] = []
        for path in search_paths:
            if path.is_file():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = [line.strip() for line in f if line.strip()]
                    break
                except Exception:
                    continue

        # Clean: keep only letters, remove empty strings, deduplicate, sort
        cleaned = [ONLY_LETTERS_PATTERN.sub("", name) for name in data]
        cleaned = [name for name in cleaned if name]
        return sorted(set(cleaned))

    def is_valid(self) -> bool:
        """Check if both name lists have at least one entry."""
        return bool(self.first_names) and bool(self.last_names)


class UsernameGenerator:
    """Generates usernames using various strategies."""

    def __init__(self, name_lists: Optional[NameLists] = None):
        """
        Initialize the username generator.

        Args:
            name_lists: Optional NameLists for ename mode.
        """
        self.name_lists = name_lists

    def generate(self, mode: UsernameMode, domain: str, prefix: str = "a") -> str:
        """
        Generate a username based on the specified mode.

        Args:
            mode: The generation mode to use.
            domain: Email domain.
            prefix: Prefix for fixed mode (single letter).

        Returns:
            Complete email address.
        """
        if mode == UsernameMode.FIXED:
            return self._generate_fixed(prefix, domain)
        elif mode == UsernameMode.RAND8:
            return self._generate_rand8(domain)
        elif mode == UsernameMode.ENAME:
            return self._generate_ename(domain)
        else:
            raise ValueError(f"Unknown username mode: {mode}")

    def _generate_fixed(self, prefix: str, domain: str) -> str:
        """
        Generate username with fixed format: prefix + month_letter + day + 5-digit random.

        Example: ab0412345@domain.com (prefix 'a', February 4th)
        """
        now = datetime.now()
        month_letter = month_to_letter(now.month)
        day = now.strftime("%d")
        random_part = f"{random.randint(0, 99999):05d}"

        username = f"{prefix}{month_letter}{day}{random_part}"
        return f"{username}@{domain}"

    def _generate_rand8(self, domain: str) -> str:
        """
        Generate 8-character random username.

        First character is always a letter, rest can be letters or digits.
        Excludes confusing characters (l, 1, o, 0).
        """
        head = random.choice(RAND8_ALPHA)
        body = "".join(random.choices(RAND8_ALPHA + RAND8_DIGIT, k=7))
        return f"{head}{body}@{domain}"

    def _generate_ename(self, domain: str) -> str:
        """
        Generate username from English first + last name.

        Raises:
            ValueError: If name lists are not available or empty.
        """
        if not self.name_lists or not self.name_lists.is_valid():
            raise ValueError(
                "English name mode requires first_names.txt and last_names.txt"
            )

        first = random.choice(self.name_lists.first_names).lower()
        last = random.choice(self.name_lists.last_names).lower()

        # Clean names again to be safe
        first = ONLY_LETTERS_PATTERN.sub("", first)
        last = ONLY_LETTERS_PATTERN.sub("", last)

        if not first or not last:
            raise ValueError("Name files contain empty or non-letter lines")

        return f"{first}{last}@{domain}"


class PasswordGenerator:
    """Generates passwords using various strategies."""

    def __init__(self, fixed_password: str = "a11111"):
        """
        Initialize the password generator.

        Args:
            fixed_password: Password to use in fixed mode.
        """
        self.fixed_password = fixed_password

    def generate(self, mode: PasswordMode) -> str:
        """
        Generate a password based on the specified mode.

        Args:
            mode: The generation mode to use.

        Returns:
            Generated password.
        """
        if mode == PasswordMode.FIXED:
            return self.fixed_password
        elif mode == PasswordMode.NUM6:
            return self._generate_num6()
        elif mode == PasswordMode.STRONG9:
            return self._generate_strong9()
        else:
            raise ValueError(f"Unknown password mode: {mode}")

    @staticmethod
    def _generate_num6() -> str:
        """Generate 6-digit numeric password."""
        return "".join(random.choices(DIGITS, k=6))

    @staticmethod
    def _generate_strong9() -> str:
        """
        Generate 9-character strong password.

        Contains at least one uppercase, one lowercase, and one digit.
        """
        max_attempts = 100

        for _ in range(max_attempts):
            # Ensure at least one of each required character type
            pool = [
                random.choice(UPPER_ALL),
                random.choice(LOWER_ALL),
                random.choice(DIGITS),
            ]

            # Fill remaining characters
            all_chars = UPPER_ALL + LOWER_ALL + DIGITS
            pool.extend(random.choices(all_chars, k=6))

            # Shuffle to randomize position
            random.shuffle(pool)
            password = "".join(pool)

            # Verify requirements are met
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)

            if has_upper and has_lower and has_digit:
                return password

        # Fallback (should never reach here)
        return "Aa1" + "".join(random.choices(all_chars, k=6))
