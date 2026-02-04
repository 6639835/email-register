"""
Configuration management for the Email Registration Tool.

Handles loading, saving, and managing application configuration
from INI files with sensible defaults.
"""

from __future__ import annotations

import base64
import configparser
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


# Application constants
APP_NAME = "RegMailGUI"
DEFAULT_APP_TITLE = "Batch Email Registration Tool"
DEFAULT_APP_TITLE_B64 = "5om56YeP6YKu566x5rOo5YaM5py6IOWkmuWfn+WQjeeJiCBWMy42ayDCtyDmioDmnK/lvq7kv6FhaWRpMTU5Mg=="
DEFAULT_SHORTLINK_SCRIPT = "m.php"


# Default configuration values
DEFAULT_CONFIG = {
    "user_prefix": "a",
    "domain": "",
    "domain_list": "",
    "ip": "",
    "gen_count": "10",
    "fixed_password": "a11111",
    "username_mode": "fixed",
    "password_mode": "num6",
    "strong_symbols": "!@#$%^&*?_-",
    "timeout_sec": "10",
    "retries": "0",
    "proxy": "",
    "api_key": "",
    "open_folder_when_done": "true",
    "first_names_file": "first_names.txt",
    "last_names_file": "last_names.txt",
    "keep_at_in_email": "true",
    "tag_seed": "tk",
    "shortlink_script": DEFAULT_SHORTLINK_SCRIPT,
    "app_title_b64": DEFAULT_APP_TITLE_B64,
    "shortlink_use_api": "false",
}


def is_frozen() -> bool:
    """Check if the application is running as a frozen executable (e.g., PyInstaller)."""
    return getattr(sys, "frozen", False)


def get_app_dir() -> Path:
    """Get the application's directory path."""
    if is_frozen():
        return Path(sys.executable).parent
    return Path(__file__).parent.absolute()


def get_default_config_path() -> Path:
    """Get the default configuration file path in the app directory."""
    return get_app_dir() / "config.ini"


def get_alt_config_path() -> Path:
    """Get the alternative configuration file path in user's app data directory."""
    base = os.environ.get("APPDATA") or Path.home()
    config_dir = Path(base) / "RegMail"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "config.ini"


def find_config_path() -> Path:
    """
    Find an existing configuration file or create one with defaults.

    Searches in order:
    1. App directory
    2. Current working directory
    3. User's app data directory

    Returns:
        Path to the configuration file.
    """
    candidates = [
        get_default_config_path(),
        Path.cwd() / "config.ini",
        get_alt_config_path(),
    ]

    for path in candidates:
        if path.is_file():
            return path

    # No config found, create default
    default_path = get_default_config_path()
    write_default_config(default_path)
    return default_path


def write_default_config(path: Path) -> None:
    """Write default configuration to the specified path."""
    # Use interpolation=None to allow special characters like % in values
    cfg = configparser.ConfigParser(interpolation=None)
    cfg["DEFAULT"] = DEFAULT_CONFIG

    with open(path, "w", encoding="utf-8") as f:
        cfg.write(f)


@dataclass
class AppConfig:
    """Application configuration container with typed access to all settings."""

    # User settings
    user_prefix: str = "a"
    domain: str = ""
    domain_list: str = ""
    ip: str = ""
    gen_count: int = 10
    fixed_password: str = "a11111"
    username_mode: str = "fixed"  # fixed, rand8, ename
    password_mode: str = "num6"  # fixed, num6, strong9

    # Advanced settings
    strong_symbols: str = "!@#$%^&*?_-"
    timeout_sec: int = 10
    retries: int = 0
    proxy: str = ""
    api_key: str = ""
    open_folder_when_done: bool = True

    # Name files for ename mode
    first_names_file: str = "first_names.txt"
    last_names_file: str = "last_names.txt"

    # URL generation
    keep_at_in_email: bool = True
    tag_seed: str = "tk"
    shortlink_script: str = DEFAULT_SHORTLINK_SCRIPT
    app_title_b64: str = DEFAULT_APP_TITLE_B64
    shortlink_use_api: bool = False

    # Internal
    _config_path: Path = field(default_factory=get_default_config_path)

    @classmethod
    def load(cls) -> "AppConfig":
        """Load configuration from file."""
        config_path = find_config_path()
        # Use interpolation=None to allow special characters like % in values
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(config_path, encoding="utf-8")
        defaults = cfg["DEFAULT"]

        return cls(
            user_prefix=defaults.get("user_prefix", "a"),
            domain=defaults.get("domain", ""),
            domain_list=defaults.get("domain_list", ""),
            ip=defaults.get("ip", ""),
            gen_count=int(defaults.get("gen_count", "10")),
            fixed_password=defaults.get("fixed_password", "a11111"),
            username_mode=defaults.get("username_mode", "fixed"),
            password_mode=defaults.get("password_mode", "num6"),
            strong_symbols=defaults.get("strong_symbols", "!@#$%^&*?_-"),
            timeout_sec=int(defaults.get("timeout_sec", "10")),
            retries=int(defaults.get("retries", "0")),
            proxy=defaults.get("proxy", ""),
            api_key=defaults.get("api_key", ""),
            open_folder_when_done=defaults.get("open_folder_when_done", "true").lower()
            == "true",
            first_names_file=defaults.get("first_names_file", "first_names.txt"),
            last_names_file=defaults.get("last_names_file", "last_names.txt"),
            keep_at_in_email=defaults.get("keep_at_in_email", "true").lower() == "true",
            tag_seed=defaults.get("tag_seed", "tk"),
            shortlink_script=defaults.get("shortlink_script", DEFAULT_SHORTLINK_SCRIPT),
            app_title_b64=defaults.get("app_title_b64", DEFAULT_APP_TITLE_B64),
            shortlink_use_api=defaults.get("shortlink_use_api", "false").lower()
            == "true",
            _config_path=config_path,
        )

    def save(self) -> Path:
        """Save current configuration to file."""
        # Use interpolation=None to allow special characters like % in values
        cfg = configparser.ConfigParser(interpolation=None)
        cfg["DEFAULT"] = {
            "user_prefix": self.user_prefix,
            "domain": self.domain,
            "domain_list": self.domain_list,
            "ip": self.ip,
            "gen_count": str(self.gen_count),
            "fixed_password": self.fixed_password,
            "username_mode": self.username_mode,
            "password_mode": self.password_mode,
            "strong_symbols": self.strong_symbols,
            "timeout_sec": str(self.timeout_sec),
            "retries": str(self.retries),
            "proxy": self.proxy,
            "api_key": self.api_key,
            "open_folder_when_done": str(self.open_folder_when_done).lower(),
            "first_names_file": self.first_names_file,
            "last_names_file": self.last_names_file,
            "keep_at_in_email": str(self.keep_at_in_email).lower(),
            "tag_seed": self.tag_seed,
            "shortlink_script": self.shortlink_script,
            "app_title_b64": self.app_title_b64,
            "shortlink_use_api": str(self.shortlink_use_api).lower(),
        }

        with open(self._config_path, "w", encoding="utf-8") as f:
            cfg.write(f)

        return self._config_path

    def get_app_title(self) -> str:
        """Decode and return the application title."""
        if self.app_title_b64:
            try:
                decoded = (
                    base64.b64decode(self.app_title_b64)
                    .decode("utf-8", errors="ignore")
                    .strip()
                )
                if decoded:
                    return decoded
            except Exception:
                pass
        return DEFAULT_APP_TITLE

    def get_proxies(self) -> Optional[Dict[str, str]]:
        """Get proxy configuration for requests."""
        proxy = self.proxy.strip()
        if proxy:
            return {"http": proxy, "https": proxy}
        return None
