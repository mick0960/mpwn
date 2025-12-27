"""
Console utilities for MPwn.

Provides functions for user interaction, error handling,
and formatted output messages.
"""

import sys
from typing import NoReturn


class MpwnError(Exception):
    """Base exception for MPwn errors."""
    pass


def prompt(message: str = "") -> bool:
    """Prompt user for yes/no confirmation.

    Args:
        message: The prompt message to display

    Returns:
        True if user confirms (Y/y or empty), False if user declines (N/n)
    """
    ans = input(f"{message} (Y/y or N/n): ")
    return ans.lower() != "n"


def error(message: str = "") -> NoReturn:
    """Print error message and exit.

    Args:
        message: The error message to display

    Raises:
        SystemExit: Always exits with code 1
    """
    print(f"\033[91m[ERROR]\033[0m {message}", file=sys.stderr)
    sys.exit(1)


def success(message: str = "") -> None:
    """Print success message.

    Args:
        message: The success message to display
    """
    print(f"\033[92m[Success]\033[0m {message}")


def info(message: str = "") -> None:
    """Print info message.

    Args:
        message: The info message to display
    """
    print(f"[*] {message}")


def warning(message: str = "") -> None:
    """Print warning message.

    Args:
        message: The warning message to display
    """
    print(f"\033[93m[!]\033[0m {message}")
