"""
API client and network utilities for email registration.

Handles communication with the hMailServer registration API using
standard RESTful JSON format.

API Endpoint: POST /api/v1/accounts
Request:  {"email": "user@example.com", "password": "securepassword"}
Response: {"success": true/false, "message": "...", "data": {...}, "error": {...}}
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set, Tuple

import requests

from config import DEFAULT_SHORTLINK_SCRIPT


# Standard API error codes from hMailServer API
ERROR_CODE_ACCOUNT_EXISTS = "ACCOUNT_EXISTS"
ERROR_CODE_DOMAIN_NOT_FOUND = "DOMAIN_NOT_FOUND"
ERROR_CODE_DOMAIN_NOT_ALLOWED = "DOMAIN_NOT_ALLOWED"


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
        return f"http://{ip_cfg}/api/v1"
    domain_ascii = to_ascii_domain(domain)
    return f"http://mail.{domain_ascii}/api/v1"


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


def is_duplicate_error(error_code: str) -> bool:
    """
    Check if the error code indicates the account already exists.

    Args:
        error_code: Error code from API response.

    Returns:
        True if the error indicates duplicate/existing account.
    """
    return error_code == ERROR_CODE_ACCOUNT_EXISTS


def parse_api_response(response_data: Dict[str, Any]) -> Tuple[bool, str, bool]:
    """
    Parse the standard JSON API response.

    Args:
        response_data: Parsed JSON response from the API.

    Returns:
        Tuple of (success, message, is_duplicate).
    """
    success = response_data.get("success", False)

    if success:
        message = response_data.get("message", "Success")
        return True, message, False

    error = response_data.get("error", {})
    error_code = error.get("code", "UNKNOWN_ERROR")
    error_message = error.get("message", "Unknown error occurred")

    is_duplicate = is_duplicate_error(error_code)

    return False, f"[{error_code}] {error_message}", is_duplicate


@dataclass
class RegistrationResult:
    """Result of a registration attempt."""

    success: bool
    message: str
    is_duplicate: bool = False


class RegistrationClient:
    """
    Client for hMailServer registration API.

    Uses standard RESTful JSON API format:
    - Endpoint: POST /api/v1/accounts
    - Request: {"email": "...", "password": "..."}
    - Response: {"success": true/false, "message": "...", "data": {...}, "error": {...}}
    """

    # Standard headers for JSON API
    HEADERS = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        timeout: int = 10,
        retries: int = 0,
        proxies: Optional[Dict[str, str]] = None,
        api_key: Optional[str] = None,
    ):
        """
        Initialize the registration client.

        Args:
            session: Optional requests session (created if not provided).
            timeout: Request timeout in seconds.
            retries: Number of retry attempts.
            proxies: Proxy configuration.
            api_key: Optional API key for authentication.
        """
        self.session = session or requests.Session()
        self.timeout = timeout
        self.retries = retries
        self.api_key = api_key

        if proxies:
            self.session.proxies.update(proxies)

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers including optional API key."""
        headers = self.HEADERS.copy()
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def register(
        self, base_api: str, email: str, password: str, domain: str
    ) -> RegistrationResult:
        """
        Attempt to register an email account.

        Args:
            base_api: Base API URL (e.g., http://server/api/v1).
            email: Email address to register.
            password: Account password.
            domain: Email domain (not used in request, extracted from email).

        Returns:
            RegistrationResult with success status and message.
        """
        url = f"{base_api}/accounts"
        payload = {
            "email": email,
            "password": password,
        }

        last_error = ""

        for attempt in range(self.retries + 1):
            try:
                response = self.session.post(
                    url,
                    json=payload,
                    headers=self._get_headers(),
                    timeout=self.timeout,
                )

                # Try to parse JSON response
                try:
                    response_data = response.json()
                except ValueError:
                    # Non-JSON response
                    if response.status_code >= 400:
                        last_error = (
                            f"HTTP {response.status_code}: {response.text[:200]}"
                        )
                        continue
                    last_error = f"Invalid JSON response: {response.text[:200]}"
                    continue

                # Parse standard API response
                success, message, is_duplicate = parse_api_response(response_data)

                if success:
                    return RegistrationResult(success=True, message=message)

                if is_duplicate:
                    return RegistrationResult(
                        success=False, message=message, is_duplicate=True
                    )

                # Other errors - may retry for server errors
                if response.status_code >= 500:
                    last_error = message
                    continue

                # Client errors (4xx) should not retry
                return RegistrationResult(success=False, message=message)

            except requests.RequestException as e:
                last_error = str(e)

        return RegistrationResult(success=False, message=last_error)
