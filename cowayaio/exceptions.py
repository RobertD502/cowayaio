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
