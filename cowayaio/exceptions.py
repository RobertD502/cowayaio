"""Exceptions for Coway IoCare."""

from typing import Any


class CowayError(Exception):
    """Error from Coway api."""

    def __init__(self, *args: Any) -> None:
        """Initialize the exception."""
        Exception.__init__(self, *args)


class AuthError(Exception):
    """Authentication issue from Coway api."""

    def __init__(self, *args: Any) -> None:
        """Initialize the exception."""
        Exception.__init__(self, *args)


class PasswordExpired(Exception):
    """Coway API indicating password has expired."""

    def __init__(self, *args: Any) -> None:
        """Initialize the exception."""
        Exception.__init__(self, *args) 


class ServerMaintenance(Exception):
    """Coway API indicating servers are undergoing maintenance"""

    def __init__(self, *args: Any) -> None:
        """Initialize the exception."""
        Exception.__init__(self, *args)


class RateLimited(Exception):
    """Coway API indicating account has been rate-limited"""

    def __init__(self, *args: Any) -> None:
        """Initialize the exception."""
        Exception.__init__(self, *args)


class NoPlaces(Exception):
    """Coway API indicating account has no places defined"""

    def __init__(self, *args: Any) -> None:
        """Initialize the exception."""
        Exception.__init__(self, *args)


class NoPurifiers(Exception):
    """Coway API indicating account has no purifiers on account"""

    def __init__(self, *args: Any) -> None:
        """Initialize the exception."""
        Exception.__init__(self, *args)
