"""The exceptions used by aioskybellgen."""

from __future__ import annotations


class SkybellException(Exception):
    """Class to throw general skybell exception."""


class SkybellAuthenticationException(SkybellException):
    """Class to throw authentication exception."""


class SkybellAccessControlException(SkybellException):
    """Class to throw access control exception."""


class SkybellUnknownResourceException(SkybellException):
    """Class to throw unknown resource exception."""


class SkybellRequestException(SkybellException):
    """Class to throw general Skybell request exception."""
