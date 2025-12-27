"""
Selection utilities for MPwn.

Provides generic table-based selection UI for user interaction.
Consolidates duplicate selection logic from the original codebase.
"""

from typing import TypeVar, Sequence, Optional, Callable
from prettytable import PrettyTable

T = TypeVar("T")


def select_from_table(
    items: Sequence[T],
    columns: list[str],
    row_formatter: Callable[[T], list[str]],
    title: str = "Select an option",
    skip_prompt: str = "Select by index (0 to skip): ",
) -> Optional[T]:
    """
    Generic table selection UI.

    This function provides a consistent interface for selecting items
    from a list using a formatted table display.

    Args:
        items: Sequence of items to select from
        columns: Column headers for the table
        row_formatter: Function that converts an item to a list of column values
        title: Title to display above the table
        skip_prompt: Prompt text for user input

    Returns:
        Selected item, or None if user skips (enters 0)

    Example:
        >>> versions = [("2.31", "amd64"), ("2.35", "i386")]
        >>> select_from_table(
        ...     items=versions,
        ...     columns=["Version", "Arch"],
        ...     row_formatter=lambda v: [v[0], v[1]],
        ...     title="Select a version"
        ... )
    """
    if not items:
        return None

    table = PrettyTable()
    table.field_names = ["Index"] + columns

    for idx, item in enumerate(items, 1):
        table.add_row([idx] + row_formatter(item))

    print(f"\n{title}:")
    print(table)

    while True:
        try:
            choice = int(input(f"\n{skip_prompt}"))
            if choice == 0:
                return None
            if 1 <= choice <= len(items):
                return items[choice - 1]
            print("Invalid choice. Please try again.")
        except ValueError:
            print("Please enter a number.")


def select_version_from_local(
    matches: list[str],
    arch: str,
) -> Optional[str]:
    """Select a version from local matches.

    Convenience wrapper for selecting local libc versions.

    Args:
        matches: List of version strings
        arch: Architecture string

    Returns:
        Selected version string, or None if skipped
    """
    return select_from_table(
        items=matches,
        columns=["Version", "Arch"],
        row_formatter=lambda v: [v, arch],
        title="Matching local versions",
    )


def select_version_from_stored(
    matches: list[tuple[str, str]],
) -> Optional[str]:
    """Select a version from stored matches.

    Convenience wrapper for selecting from stored version list.

    Args:
        matches: List of (version, arch) tuples

    Returns:
        Selected version string, or None if skipped
    """
    result = select_from_table(
        items=matches,
        columns=["Version", "Arch"],
        row_formatter=lambda v: [v[0], v[1]],
        title="Matching stored versions",
        skip_prompt="Select a version to download (0 to skip): ",
    )
    return result[0] if result else None
