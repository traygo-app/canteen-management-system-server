"""
Logging utilities for sanitizing sensitive data before logging.
"""

import re
from typing import Any

# Sensitive field names to sanitize
SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "csrf",
    "csrftoken",
    "session",
    "sessionid",
    "cookie",
    "mfa_secret",
    "totp_secret",
    "backup_code",
    "recovery_code",
    "private_key",
    "client_secret",
    "stripe_key",
    "stripe_secret",
    "webhook_secret",
}

# Patterns for sensitive data in strings
SENSITIVE_PATTERNS = [
    (re.compile(r"(Bearer\s+)[\w\-\.]+", re.IGNORECASE), r"\1***"),  # Bearer tokens
    (re.compile(r"(token[=:]\s*)[\w\-\.]+", re.IGNORECASE), r"\1***"),  # token= or token:
    (re.compile(r"(api[_-]?key[=:]\s*)[\w\-]+", re.IGNORECASE), r"\1***"),  # API keys
    (re.compile(r"(password[=:]\s*)[\S]+", re.IGNORECASE), r"\1***"),  # password= or password:
]


def sanitize_value(value: Any) -> Any:
    """
    Sanitize a single value by masking sensitive patterns.

    Args:
        value: The value to sanitize

    Returns:
        Sanitized value
    """
    if isinstance(value, str):
        # Apply regex patterns to mask sensitive data
        sanitized = value
        for pattern, replacement in SENSITIVE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized
    return value


def sanitize_dict(data: dict, mask: str = "***") -> dict:
    """
    Recursively sanitize sensitive fields in a dictionary.

    Args:
        data: Dictionary to sanitize
        mask: String to replace sensitive values with

    Returns:
        Sanitized dictionary
    """
    if not isinstance(data, dict):
        return data

    sanitized = {}
    for key, value in data.items():
        key_lower = key.lower()

        # Check if key is sensitive
        if any(sensitive in key_lower for sensitive in SENSITIVE_FIELDS):
            sanitized[key] = mask
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value, mask)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_dict(item, mask) if isinstance(item, dict) else sanitize_value(item) for item in value
            ]
        else:
            sanitized[key] = sanitize_value(value)

    return sanitized


def sanitize_data(data: Any, mask: str = "***") -> Any:
    """
    Sanitize sensitive data before logging.

    Handles various data types:
    - Dictionaries: recursively sanitizes sensitive keys
    - Lists: sanitizes each item
    - Strings: applies regex patterns to mask sensitive data
    - Other types: returns as-is

    Args:
        data: Data to sanitize (dict, list, str, or other)
        mask: String to replace sensitive values with (default: "***")

    Returns:
        Sanitized data

    Example:
        >>> sanitize_data({"email": "user@example.com", "password": "secret123"})
        {"email": "user@example.com", "password": "***"}
    """
    if isinstance(data, dict):
        return sanitize_dict(data, mask)
    elif isinstance(data, list):
        return [sanitize_data(item, mask) for item in data]
    elif isinstance(data, str):
        return sanitize_value(data)
    else:
        return data


def mask_email(email: str) -> str:
    """
    Partially mask an email address for logging.

    Args:
        email: Email address to mask

    Returns:
        Masked email (e.g., "u***@example.com")

    Example:
        >>> mask_email("user@example.com")
        "u***@example.com"
    """
    if not email or "@" not in email:
        return "***"

    local, domain = email.split("@", 1)
    if len(local) <= 1:
        return f"***@{domain}"

    return f"{local[0]}***@{domain}"


def get_client_ip(request) -> str:
    """
    Get client IP address from request, checking for proxy headers.

    Args:
        request: Django/DRF request object

    Returns:
        Client IP address
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    ip = x_forwarded_for.split(",")[0].strip() if x_forwarded_for else request.META.get("REMOTE_ADDR", "unknown")
    return ip
