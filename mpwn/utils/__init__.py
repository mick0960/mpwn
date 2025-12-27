"""Utility functions for MPwn."""

from mpwn.utils.console import prompt, error, success, info, MpwnError
from mpwn.utils.system import detect_arch, parse_ldd_output
from mpwn.utils.selection import select_from_table

# PWN helper utilities (optional, requires pwntools)
try:
    from mpwn.utils.pwn_helpers import (
        conn,
        setup_shortcuts,
        leak64,
        leak32,
        leak,
        lg,
        debug,
        bp,
        set_elf,
        set_libc,
        set_process,
        get_process,
    )

    _PWN_HELPERS_AVAILABLE = True
except ImportError:
    _PWN_HELPERS_AVAILABLE = False

__all__ = [
    "prompt",
    "error",
    "success",
    "info",
    "MpwnError",
    "detect_arch",
    "parse_ldd_output",
    "select_from_table",
]

# Add pwn_helpers to __all__ if available
if _PWN_HELPERS_AVAILABLE:
    __all__.extend(
        [
            "conn",
            "setup_shortcuts",
            "leak64",
            "leak32",
            "leak",
            "lg",
            "debug",
            "bp",
            "set_elf",
            "set_libc",
            "set_process",
            "get_process",
        ]
    )
