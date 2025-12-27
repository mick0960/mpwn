"""
MPwn - CTF Pwn Challenge Environment Manager

A tool for managing glibc versions and patching executables
for binary exploitation challenges.
"""

from mpwn.config import __version__
from mpwn.models import ChallengeFileInfo, LibraryMapping, Architecture

# Export pwn helpers and pwntools if available
try:
    # Import all from pwntools
    from pwn import *

    # Import mpwn's pwn helper functions
    from mpwn.utils.pwn_helpers import (
        setup,
        conn,
        bind_shortcuts,
        PwnShortcuts,
        sla,
        sda,
        sl,
        sd,
        ru,
        rl,
        rc,
        leak64,
        leak32,
        leak,
        lg,
        debug,
        bp,
    )

    _PWN_AVAILABLE = True
except ImportError:
    _PWN_AVAILABLE = False

__all__ = [
    "__version__",
    "ChallengeFileInfo",
    "LibraryMapping",
    "Architecture",
]

# Add pwn tools to __all__ if available
if _PWN_AVAILABLE:
    __all__.extend(
        [
            "setup",
            "conn",
            "bind_shortcuts",
            "PwnShortcuts",
            "sla",
            "sda",
            "sl",
            "sd",
            "ru",
            "rl",
            "rc",
            "leak64",
            "leak32",
            "leak",
            "lg",
            "debug",
            "bp",
            # Export common pwntools items
            "ELF",
            "process",
            "remote",
            "context",
            "args",
            "log",
            "gdb",
            "pause",
            "u64",
            "u32",
            "p64",
            "p32",
        ]
    )
