"""NLAG Python SDK exceptions."""

from typing import Optional


class NlagError(Exception):
    """Base exception for all NLAG errors."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        if self.code:
            return f"[{self.code}] {self.message}"
        return self.message


class AuthenticationError(NlagError):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, code="AUTH_ERROR")


class ConnectionError(NlagError):
    """Raised when connection to the edge server fails."""

    def __init__(self, message: str = "Connection failed"):
        super().__init__(message, code="CONNECTION_ERROR")


class TunnelError(NlagError):
    """Raised when tunnel operations fail."""

    def __init__(self, message: str, tunnel_id: Optional[str] = None):
        super().__init__(message, code="TUNNEL_ERROR")
        self.tunnel_id = tunnel_id


class ConfigurationError(NlagError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, field: Optional[str] = None):
        super().__init__(message, code="CONFIG_ERROR")
        self.field = field


class RateLimitError(NlagError):
    """Raised when rate limit is exceeded."""

    def __init__(self, retry_after: Optional[int] = None):
        super().__init__("Rate limit exceeded", code="RATE_LIMIT")
        self.retry_after = retry_after


class QuotaExceededError(NlagError):
    """Raised when quota is exceeded."""

    def __init__(self, quota_type: str, limit: int, current: int):
        super().__init__(
            f"Quota exceeded for {quota_type}: {current}/{limit}",
            code="QUOTA_EXCEEDED"
        )
        self.quota_type = quota_type
        self.limit = limit
        self.current = current
