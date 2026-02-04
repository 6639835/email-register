"""
API client and network utilities for email registration.

Handles communication with the registration server, domain authorization,
and URL generation.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple

import requests

from config import DEFAULT_SHORTLINK_SCRIPT


# Regex patterns for error detection
DUPLICATE_ENTRY_PATTERN = re.compile(
    r"Duplicate entry\s+'([^']+)'[^\n]*accountaddress", re.IGNORECASE
)
ALREADY_EXISTS_PATTERN = re.compile(r"\balready\s+exists\b", re.IGNORECASE)
ERROR_KEYWORDS_PATTERN = re.compile(
    r"(user\s*or\s*password|password\s*error|failed|error)", re.IGNORECASE
)

# Phrases indicating existing account
EXISTING_ACCOUNT_PHRASES = [
    "already exists",
    "user exists",
    "account exists",
    "email exists",
]


def to_ascii_domain(domain: str) -> str:
    """
    Normalize domain to ASCII (punycode for internationalized domains).

    Args:
        domain: Domain name to normalize.

    Returns:
        Normalized domain in lowercase ASCII.
    """
    d = (domain or "").strip().lower()
    try:
        return d.encode("idna").decode("ascii")
    except Exception:
        return d


def build_base_api(ip_cfg: str, domain: str) -> str:
    """
    Build the base API URL from configuration.

    Args:
        ip_cfg: Custom IP/domain override from config.
        domain: Email domain to derive API URL from.

    Returns:
        Base API URL (without trailing slash).
    """
    ip_cfg = (ip_cfg or "").strip()
    if ip_cfg:
        return f"http://{ip_cfg}/api"
    domain_ascii = to_ascii_domain(domain)
    return f"http://mail.{domain_ascii}/api"


def extract_host_from_base_api(base_api: str) -> str:
    """
    Extract host[:port] from a base API URL.

    Args:
        base_api: Base API URL like 'http://mail.domain.com/api'.

    Returns:
        Host portion like 'mail.domain.com'.
    """
    try:
        parsed = urllib.parse.urlparse(base_api)
        if parsed.netloc:
            return parsed.netloc
    except Exception:
        pass

    # Fallback to regex extraction
    match = re.match(r"^https?://([^/]+)", (base_api or "").strip())
    if match:
        return match.group(1)
    return base_api


def build_login_url(
    base_api: str,
    email: str,
    password: str,
    script_name: str = DEFAULT_SHORTLINK_SCRIPT,
    keep_at: bool = True,
) -> str:
    """
    Build a short login URL for the registered email.

    Args:
        base_api: Base API URL to derive host from.
        email: Email address.
        password: Account password.
        script_name: Login script filename.
        keep_at: Whether to keep @ in the email URL parameter.

    Returns:
        Short login URL.
    """
    email_quoted = urllib.parse.quote(email, safe="@" if keep_at else "")
    password_quoted = urllib.parse.quote(password, safe="")

    host = extract_host_from_base_api(base_api).strip()
    script = (script_name or DEFAULT_SHORTLINK_SCRIPT).lstrip("/")

    return f"http://{host}/{script}?u={email_quoted}&p={password_quoted}"


def is_exists_error(text: str) -> bool:
    """
    Check if the response indicates the account already exists.

    Args:
        text: Response text from the server.

    Returns:
        True if the error indicates duplicate/existing account.
    """
    if not text:
        return False

    # Check for MySQL duplicate entry error
    if DUPLICATE_ENTRY_PATTERN.search(text):
        return True

    # Check for English "already exists"
    if ALREADY_EXISTS_PATTERN.search(text):
        return True

    # Check for Chinese phrases
    for phrase in EXISTING_ACCOUNT_PHRASES:
        if phrase in text:
            return True

    return False


def normalize_response_text(text: str) -> str:
    """
    Normalize response text for success comparison.

    Removes BOM and zero-width characters.

    Args:
        text: Raw response text.

    Returns:
        Cleaned text.
    """
    if not text:
        return ""

    # Remove BOM
    text = text.replace("\ufeff", "")

    # Remove zero-width characters
    text = re.sub(r"[\u200b\u200c\u200d]", "", text)

    return text.strip()


@dataclass
class RegistrationResult:
    """Result of a registration attempt."""

    success: bool
    message: str
    is_duplicate: bool = False


class RegistrationClient:
    """Client for email registration API."""

    SUCCESS_RESPONSE = "成功1成功2"

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        timeout: int = 10,
        retries: int = 0,
        proxies: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize the registration client.

        Args:
            session: Optional requests session (created if not provided).
            timeout: Request timeout in seconds.
            retries: Number of retry attempts.
            proxies: Proxy configuration.
        """
        self.session = session or requests.Session()
        self.timeout = timeout
        self.retries = retries

        if proxies:
            self.session.proxies.update(proxies)

    def register(
        self, base_api: str, email: str, password: str, domain: str
    ) -> RegistrationResult:
        """
        Attempt to register an email account.

        Args:
            base_api: Base API URL.
            email: Email address to register.
            password: Account password.
            domain: Email domain.

        Returns:
            RegistrationResult with success status and message.
        """
        url = f"{base_api}/xjyh_jm.php"
        data = {
            "address": email,
            "password": password,
            "yu_ming": domain,
            "my": "zc123",
        }

        last_error = ""

        for attempt in range(self.retries + 1):
            try:
                response = self.session.post(url, data=data, timeout=self.timeout)

                if response.status_code != 200:
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    continue

                raw_text = response.text or ""
                normalized = normalize_response_text(raw_text)

                # Check for success
                if normalized == self.SUCCESS_RESPONSE:
                    return RegistrationResult(success=True, message=normalized)

                # Check for duplicate/existing account
                if is_exists_error(raw_text):
                    return RegistrationResult(
                        success=False, message=raw_text[:1000], is_duplicate=True
                    )

                # Check for other error indicators
                if ERROR_KEYWORDS_PATTERN.search(raw_text):
                    last_error = raw_text[:1000]
                    continue

                # Unrecognized response
                last_error = (
                    raw_text[:1000] or "HTTP 200 but unrecognized response (empty)"
                )

            except requests.RequestException as e:
                last_error = str(e)

        return RegistrationResult(success=False, message=last_error)
